from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import hashlib
import secrets
import structlog
from ipaddress import ip_address, ip_network
import asyncio

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ValidationError, RateLimitError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class SecurityService:
    """
    Enhanced security service with brute force protection, account lockout, and CAPTCHA integration
    """
    
    def __init__(self):
        # Brute Force Protection Settings
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 30
        self.progressive_delay_enabled = True
        self.progressive_delay_base = 2  # seconds
        self.progressive_delay_multiplier = 2
        
        # Account Lockout Settings
        self.account_lockout_threshold = 10
        self.account_lockout_duration_hours = 24
        self.require_password_reset_on_lockout = True
        
        # IP-based Protection
        self.ip_max_attempts = 20
        self.ip_lockout_duration_hours = 6
        self.ip_whitelist = []
        self.ip_blacklist = []
        
        # CAPTCHA Settings
        self.captcha_threshold = 3  # Show CAPTCHA after N failed attempts
        self.captcha_required_duration_minutes = 60
        
        # Suspicious Activity Detection
        self.suspicious_login_patterns = True
        self.geographic_anomaly_detection = True
        self.concurrent_session_limit = 5
        
        # Password History
        self.password_history_count = 5
        self.password_reuse_days = 90
        
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def check_brute_force_protection(
        self,
        identifier: str,  # email or username
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if login attempt should be allowed based on brute force protection
        """
        try:
            result = {
                "allowed": True,
                "require_captcha": False,
                "delay_seconds": 0,
                "lockout_remaining": None,
                "message": None
            }
            
            # Check IP blacklist
            if await self._is_ip_blacklisted(ip_address):
                result["allowed"] = False
                result["message"] = "Access denied from this IP address"
                return result
            
            # Check IP whitelist (bypass checks)
            if await self._is_ip_whitelisted(ip_address):
                return result
            
            # Check IP-based lockout
            ip_lockout = await self._check_ip_lockout(ip_address)
            if ip_lockout["locked"]:
                result["allowed"] = False
                result["lockout_remaining"] = ip_lockout["remaining_minutes"]
                result["message"] = f"Too many attempts from this IP. Try again in {ip_lockout['remaining_minutes']} minutes"
                return result
            
            # Check account lockout
            account_lockout = await self._check_account_lockout(identifier)
            if account_lockout["locked"]:
                result["allowed"] = False
                result["lockout_remaining"] = account_lockout["remaining_minutes"]
                result["message"] = f"Account is locked. Try again in {account_lockout['remaining_minutes']} minutes"
                
                if self.require_password_reset_on_lockout:
                    result["require_password_reset"] = True
                    result["message"] += " or reset your password"
                
                return result
            
            # Get failed attempt count
            attempts = await self._get_failed_attempts(identifier)
            
            # Check if CAPTCHA is required
            if attempts >= self.captcha_threshold:
                result["require_captcha"] = True
            
            # Calculate progressive delay
            if self.progressive_delay_enabled and attempts > 0:
                delay = self._calculate_progressive_delay(attempts)
                result["delay_seconds"] = delay
            
            # Check if approaching lockout
            if attempts >= self.max_login_attempts - 1:
                result["message"] = f"Warning: {self.max_login_attempts - attempts} attempts remaining before lockout"
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to check brute force protection: {str(e)}")
            # Fail open to avoid blocking legitimate users
            return {"allowed": True, "require_captcha": False, "delay_seconds": 0}
    
    async def record_failed_login(
        self,
        identifier: str,
        ip_address: str,
        user_agent: Optional[str] = None,
        reason: Optional[str] = None
    ):
        """
        Record a failed login attempt
        """
        try:
            # Increment attempt counters
            identifier_attempts = await self._increment_failed_attempts(identifier)
            ip_attempts = await self._increment_ip_attempts(ip_address)
            
            # Check for account lockout
            if identifier_attempts >= self.max_login_attempts:
                await self._lockout_account(identifier)
                logger.warning(
                    f"Account locked due to too many failed attempts",
                    identifier=identifier,
                    attempts=identifier_attempts
                )
            
            # Check for IP lockout
            if ip_attempts >= self.ip_max_attempts:
                await self._lockout_ip(ip_address)
                logger.warning(
                    f"IP locked due to too many failed attempts",
                    ip_address=ip_address,
                    attempts=ip_attempts
                )
            
            # Record detailed attempt log
            await self._log_failed_attempt(
                identifier=identifier,
                ip_address=ip_address,
                user_agent=user_agent,
                reason=reason
            )
            
            # Check for suspicious patterns
            if self.suspicious_login_patterns:
                await self._check_suspicious_patterns(identifier, ip_address)
        
        except Exception as e:
            logger.error(f"Failed to record failed login: {str(e)}")
    
    async def record_successful_login(
        self,
        identifier: str,
        ip_address: str,
        user_agent: Optional[str] = None
    ):
        """
        Record a successful login and reset counters
        """
        try:
            # Clear failed attempt counters
            await self._clear_failed_attempts(identifier)
            await self._clear_ip_attempts(ip_address)
            
            # Record successful login
            await self._log_successful_login(
                identifier=identifier,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Check for geographic anomalies
            if self.geographic_anomaly_detection:
                await self._check_geographic_anomaly(identifier, ip_address)
        
        except Exception as e:
            logger.error(f"Failed to record successful login: {str(e)}")
    
    async def verify_captcha(
        self,
        captcha_response: str,
        ip_address: str
    ) -> bool:
        """
        Verify CAPTCHA response (placeholder for actual implementation)
        """
        try:
            # In production, integrate with reCAPTCHA or hCaptcha
            # For now, simple validation
            if not captcha_response:
                return False
            
            # Store successful CAPTCHA verification
            captcha_key = f"captcha_verified:{ip_address}"
            await cache_service.set(
                captcha_key,
                True,
                expire=self.captcha_required_duration_minutes * 60
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to verify CAPTCHA: {str(e)}")
            return False
    
    async def add_password_to_history(
        self,
        user_id: str,
        password_hash: str
    ):
        """
        Add password to user's password history
        """
        try:
            history_key = f"password_history:{user_id}"
            history = await cache_service.get_list(history_key)
            
            # Add new password hash with timestamp
            entry = {
                "hash": password_hash,
                "created_at": datetime.utcnow().isoformat()
            }
            
            # Add to beginning of list
            history.insert(0, entry)
            
            # Keep only the configured number of passwords
            history = history[:self.password_history_count]
            
            # Store updated history
            await cache_service.delete(history_key)
            for item in history:
                await cache_service.push_to_list(history_key, item)
            
            logger.info(f"Password added to history for user {user_id}")
        
        except Exception as e:
            logger.error(f"Failed to add password to history: {str(e)}")
    
    async def check_password_history(
        self,
        user_id: str,
        password_hash: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if password was recently used
        Returns (is_allowed, reason)
        """
        try:
            history_key = f"password_history:{user_id}"
            history = await cache_service.get_list(history_key)
            
            for entry in history:
                if entry.get("hash") == password_hash:
                    created_at = datetime.fromisoformat(entry["created_at"])
                    days_ago = (datetime.utcnow() - created_at).days
                    
                    if days_ago < self.password_reuse_days:
                        return False, f"Password was used {days_ago} days ago. Must wait {self.password_reuse_days} days to reuse"
            
            return True, None
        
        except Exception as e:
            logger.error(f"Failed to check password history: {str(e)}")
            return True, None  # Fail open
    
    async def force_password_reset(
        self,
        user_id: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Force a user to reset their password on next login
        """
        try:
            # Set password reset flag
            reset_key = f"force_password_reset:{user_id}"
            reset_data = {
                "required": True,
                "reason": reason,
                "initiated_at": datetime.utcnow().isoformat()
            }
            
            await cache_service.set(reset_key, reset_data)
            
            # Update user metadata in Clerk
            clerk_client = await self._get_clerk_client()
            await clerk_client.update_user(
                user_id=user_id,
                private_metadata={
                    "force_password_reset": True,
                    "password_reset_reason": reason
                }
            )
            
            # Invalidate all sessions
            from app.services.token_service import token_service
            await token_service.revoke_all_user_tokens(user_id)
            
            logger.info(f"Password reset forced for user {user_id}", reason=reason)
            
            return {
                "success": True,
                "user_id": user_id,
                "reason": reason,
                "message": "User must reset password on next login"
            }
        
        except Exception as e:
            logger.error(f"Failed to force password reset: {str(e)}")
            raise ValidationError("Failed to force password reset")
    
    async def check_password_reset_required(
        self,
        user_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if user needs to reset password
        Returns (is_required, reason)
        """
        try:
            reset_key = f"force_password_reset:{user_id}"
            reset_data = await cache_service.get(reset_key)
            
            if reset_data and reset_data.get("required"):
                return True, reset_data.get("reason")
            
            # Check Clerk metadata
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if user and user.private_metadata:
                if user.private_metadata.get("force_password_reset"):
                    return True, user.private_metadata.get("password_reset_reason")
            
            return False, None
        
        except Exception as e:
            logger.error(f"Failed to check password reset requirement: {str(e)}")
            return False, None
    
    async def check_concurrent_sessions(
        self,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Check and enforce concurrent session limits
        """
        try:
            # Get active sessions count
            sessions_key = f"user_sessions:{user_id}"
            active_sessions = await cache_service.get_set_members(sessions_key)
            
            if len(active_sessions) >= self.concurrent_session_limit:
                # Get oldest session
                sessions_data = []
                for session_id in active_sessions:
                    session_data = await cache_service.get(f"session:{session_id}")
                    if session_data:
                        sessions_data.append((session_id, session_data))
                
                # Sort by creation time
                sessions_data.sort(key=lambda x: x[1].get("created_at", ""))
                
                # Terminate oldest session
                if sessions_data:
                    oldest_session_id = sessions_data[0][0]
                    await cache_service.delete(f"session:{oldest_session_id}")
                    await cache_service.remove_from_set(sessions_key, oldest_session_id)
                    
                    logger.info(
                        f"Terminated oldest session due to concurrent limit",
                        user_id=user_id,
                        terminated_session=oldest_session_id
                    )
            
            return {
                "active_sessions": len(active_sessions),
                "limit": self.concurrent_session_limit,
                "limit_reached": len(active_sessions) >= self.concurrent_session_limit
            }
        
        except Exception as e:
            logger.error(f"Failed to check concurrent sessions: {str(e)}")
            return {"active_sessions": 0, "limit": self.concurrent_session_limit}
    
    # ============= Helper Methods =============
    
    async def _get_failed_attempts(self, identifier: str) -> int:
        """Get number of failed login attempts"""
        key = f"failed_attempts:{identifier}"
        return await cache_service.get(key) or 0
    
    async def _increment_failed_attempts(self, identifier: str) -> int:
        """Increment failed login attempts"""
        key = f"failed_attempts:{identifier}"
        count = await cache_service.increment(key)
        
        # Set expiry on first attempt
        if count == 1:
            await cache_service.expire(key, 3600)  # 1 hour
        
        return count
    
    async def _clear_failed_attempts(self, identifier: str):
        """Clear failed login attempts"""
        key = f"failed_attempts:{identifier}"
        await cache_service.delete(key)
    
    async def _increment_ip_attempts(self, ip_addr: str) -> int:
        """Increment IP-based attempt counter"""
        key = f"ip_attempts:{ip_addr}"
        count = await cache_service.increment(key)
        
        if count == 1:
            await cache_service.expire(key, 3600)
        
        return count
    
    async def _clear_ip_attempts(self, ip_addr: str):
        """Clear IP-based attempts"""
        key = f"ip_attempts:{ip_addr}"
        await cache_service.delete(key)
    
    async def _lockout_account(self, identifier: str):
        """Lock out an account"""
        lockout_key = f"account_lockout:{identifier}"
        lockout_data = {
            "locked": True,
            "locked_at": datetime.utcnow().isoformat(),
            "duration_minutes": self.lockout_duration_minutes
        }
        
        await cache_service.set(
            lockout_key,
            lockout_data,
            expire=self.lockout_duration_minutes * 60
        )
    
    async def _check_account_lockout(self, identifier: str) -> Dict[str, Any]:
        """Check if account is locked out"""
        lockout_key = f"account_lockout:{identifier}"
        lockout_data = await cache_service.get(lockout_key)
        
        if lockout_data and lockout_data.get("locked"):
            locked_at = datetime.fromisoformat(lockout_data["locked_at"])
            elapsed = (datetime.utcnow() - locked_at).total_seconds() / 60
            remaining = max(0, lockout_data["duration_minutes"] - int(elapsed))
            
            return {
                "locked": True,
                "remaining_minutes": remaining
            }
        
        return {"locked": False}
    
    async def _lockout_ip(self, ip_addr: str):
        """Lock out an IP address"""
        lockout_key = f"ip_lockout:{ip_addr}"
        lockout_data = {
            "locked": True,
            "locked_at": datetime.utcnow().isoformat(),
            "duration_hours": self.ip_lockout_duration_hours
        }
        
        await cache_service.set(
            lockout_key,
            lockout_data,
            expire=self.ip_lockout_duration_hours * 3600
        )
    
    async def _check_ip_lockout(self, ip_addr: str) -> Dict[str, Any]:
        """Check if IP is locked out"""
        lockout_key = f"ip_lockout:{ip_addr}"
        lockout_data = await cache_service.get(lockout_key)
        
        if lockout_data and lockout_data.get("locked"):
            locked_at = datetime.fromisoformat(lockout_data["locked_at"])
            elapsed = (datetime.utcnow() - locked_at).total_seconds() / 60
            remaining = max(0, lockout_data["duration_hours"] * 60 - int(elapsed))
            
            return {
                "locked": True,
                "remaining_minutes": remaining
            }
        
        return {"locked": False}
    
    def _calculate_progressive_delay(self, attempts: int) -> int:
        """Calculate progressive delay in seconds"""
        if attempts <= 0:
            return 0
        
        delay = self.progressive_delay_base * (self.progressive_delay_multiplier ** (attempts - 1))
        return min(delay, 30)  # Cap at 30 seconds
    
    async def _is_ip_whitelisted(self, ip_addr: str) -> bool:
        """Check if IP is whitelisted"""
        # Check static whitelist
        if ip_addr in self.ip_whitelist:
            return True
        
        # Check dynamic whitelist in cache
        whitelist_key = f"ip_whitelist:{ip_addr}"
        return await cache_service.exists(whitelist_key)
    
    async def _is_ip_blacklisted(self, ip_addr: str) -> bool:
        """Check if IP is blacklisted"""
        # Check static blacklist
        if ip_addr in self.ip_blacklist:
            return True
        
        # Check dynamic blacklist in cache
        blacklist_key = f"ip_blacklist:{ip_addr}"
        return await cache_service.exists(blacklist_key)
    
    async def _log_failed_attempt(
        self,
        identifier: str,
        ip_address: str,
        user_agent: Optional[str],
        reason: Optional[str]
    ):
        """Log detailed failed attempt"""
        log_key = f"login_attempts:{identifier}:{datetime.utcnow().strftime('%Y%m%d')}"
        attempt_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": False,
            "reason": reason
        }
        
        await cache_service.push_to_list(log_key, attempt_data)
        await cache_service.expire(log_key, 86400 * 7)  # Keep for 7 days
    
    async def _log_successful_login(
        self,
        identifier: str,
        ip_address: str,
        user_agent: Optional[str]
    ):
        """Log successful login"""
        log_key = f"login_attempts:{identifier}:{datetime.utcnow().strftime('%Y%m%d')}"
        attempt_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": True
        }
        
        await cache_service.push_to_list(log_key, attempt_data)
        await cache_service.expire(log_key, 86400 * 7)
    
    async def _check_suspicious_patterns(self, identifier: str, ip_address: str):
        """Check for suspicious login patterns"""
        # Get recent attempts
        log_key = f"login_attempts:{identifier}:{datetime.utcnow().strftime('%Y%m%d')}"
        recent_attempts = await cache_service.get_list(log_key, 0, 20)
        
        if len(recent_attempts) >= 10:
            # Check for rapid-fire attempts
            timestamps = [datetime.fromisoformat(a["timestamp"]) for a in recent_attempts[-10:]]
            time_diff = (timestamps[-1] - timestamps[0]).total_seconds()
            
            if time_diff < 60:  # 10 attempts in 1 minute
                logger.warning(
                    f"Suspicious rapid-fire login attempts detected",
                    identifier=identifier,
                    ip_address=ip_address,
                    attempts_per_minute=10
                )
                
                # Auto-blacklist IP temporarily
                blacklist_key = f"ip_blacklist:{ip_address}"
                await cache_service.set(blacklist_key, True, expire=3600)
    
    async def _check_geographic_anomaly(self, identifier: str, ip_address: str):
        """Check for geographic anomalies in login location"""
        # This would integrate with IP geolocation service
        # For now, placeholder implementation
        pass
    
    async def get_security_analytics(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Get security analytics"""
        try:
            # This would aggregate security metrics
            return {
                "time_range_hours": time_range_hours,
                "failed_attempts": 0,  # Would calculate from logs
                "locked_accounts": 0,  # Would count locked accounts
                "locked_ips": 0,  # Would count locked IPs
                "suspicious_activities": 0  # Would count flagged activities
            }
        
        except Exception as e:
            logger.error(f"Failed to get security analytics: {str(e)}")
            return {}


# Singleton instance
security_service = SecurityService()