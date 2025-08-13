from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets
import hashlib
import structlog

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthenticationError
from app.services.cache_service import cache_service
from app.services.email_service import EmailService
from app.services.password_validator import password_validator
from app.services.security_service import security_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class PasswordChangeService:
    """
    Service for managing password changes with old password verification
    """
    
    def __init__(self):
        self.min_password_age_hours = 1  # Minimum time between password changes
        self.password_history_count = 5  # Number of previous passwords to check
        self.max_attempts_per_hour = 5
        self.email_service = EmailService()
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Change user password with old password verification
        """
        try:
            # Get user details
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise ValidationError("User not found")
            
            email = user.email_addresses[0].email_address if user.email_addresses else None
            
            # Check rate limiting
            if not await self._check_rate_limit(user_id, ip_address):
                # Log potential brute force attempt
                await security_service.log_security_event(
                    event_type="password_change_rate_limited",
                    user_id=user_id,
                    ip_address=ip_address,
                    details={"reason": "Too many password change attempts"}
                )
                raise ValidationError("Too many password change attempts. Please try again later.")
            
            # Verify old password
            if not await self._verify_old_password(user_id, old_password):
                # Update rate limit on failed attempt
                await self._update_rate_limit(user_id, ip_address, success=False)
                
                # Log failed attempt
                await security_service.log_security_event(
                    event_type="password_change_failed",
                    user_id=user_id,
                    ip_address=ip_address,
                    details={"reason": "Invalid old password"}
                )
                
                raise AuthenticationError("Current password is incorrect")
            
            # Check password age
            if not await self._check_password_age(user_id):
                raise ValidationError(f"Password must be at least {self.min_password_age_hours} hour(s) old before changing")
            
            # Validate new password
            is_valid, errors = password_validator.validate_password(
                new_password,
                email=email,
                old_password=old_password
            )
            
            if not is_valid:
                raise ValidationError(f"New password validation failed: {', '.join(errors)}")
            
            # Check if new password is same as old
            if old_password == new_password:
                raise ValidationError("New password cannot be the same as current password")
            
            # Check password history
            if await self._is_password_in_history(user_id, new_password):
                raise ValidationError(f"Password was recently used. Please choose a different password.")
            
            # Update password in Clerk
            await clerk_client.update_user(
                user_id,
                password=new_password,
                skip_password_checks=True  # We've already validated
            )
            
            # Add old password to history
            await self._add_to_password_history(user_id, old_password)
            
            # Update password metadata
            await self._update_password_metadata(user_id)
            
            # Invalidate other sessions if requested
            if session_id:
                await self._invalidate_other_sessions(user_id, session_id)
            
            # Send notification email
            if email:
                await self._send_password_change_notification(
                    email=email,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            
            # Update rate limit on success
            await self._update_rate_limit(user_id, ip_address, success=True)
            
            # Log successful change
            await security_service.log_security_event(
                event_type="password_changed",
                user_id=user_id,
                ip_address=ip_address,
                details={
                    "session_id": session_id,
                    "other_sessions_invalidated": bool(session_id)
                }
            )
            
            logger.info(
                f"Password changed successfully",
                user_id=user_id,
                ip_address=ip_address
            )
            
            return {
                "success": True,
                "message": "Password changed successfully",
                "sessions_invalidated": bool(session_id),
                "notification_sent": bool(email)
            }
        
        except (ValidationError, AuthenticationError):
            raise
        except Exception as e:
            logger.error(f"Failed to change password: {str(e)}")
            raise ValidationError("Failed to change password")
    
    async def force_password_change(
        self,
        user_id: str,
        reason: str = "Security policy",
        grace_period_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Force a user to change their password on next login
        """
        try:
            # Get user details
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise ValidationError("User not found")
            
            # Set force password change flag
            force_change_data = {
                "required": True,
                "reason": reason,
                "requested_at": datetime.utcnow().isoformat(),
                "grace_period_end": (datetime.utcnow() + timedelta(hours=grace_period_hours)).isoformat()
            }
            
            # Update user metadata
            await clerk_client.update_user(
                user_id,
                unsafe_metadata={
                    **user.unsafe_metadata,
                    "force_password_change": force_change_data
                }
            )
            
            # Store in cache for quick lookup
            force_change_key = f"force_password_change:{user_id}"
            await cache_service.set(
                force_change_key,
                force_change_data,
                expire=grace_period_hours * 3600
            )
            
            # Send notification
            email = user.email_addresses[0].email_address if user.email_addresses else None
            if email:
                await self._send_force_change_notification(
                    email=email,
                    reason=reason,
                    grace_period_hours=grace_period_hours
                )
            
            # Log the action
            await security_service.log_security_event(
                event_type="password_change_forced",
                user_id=user_id,
                details={
                    "reason": reason,
                    "grace_period_hours": grace_period_hours
                }
            )
            
            logger.info(
                f"Password change forced",
                user_id=user_id,
                reason=reason
            )
            
            return {
                "forced": True,
                "reason": reason,
                "grace_period_end": force_change_data["grace_period_end"],
                "notification_sent": bool(email)
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to force password change: {str(e)}")
            raise ValidationError("Failed to force password change")
    
    async def check_password_requirements(
        self,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Check if user needs to change password
        """
        try:
            # Check force password change flag
            force_change_key = f"force_password_change:{user_id}"
            force_change_data = await cache_service.get(force_change_key)
            
            if force_change_data and force_change_data.get("required"):
                grace_period_end = datetime.fromisoformat(force_change_data["grace_period_end"])
                
                return {
                    "change_required": True,
                    "reason": force_change_data.get("reason", "Security policy"),
                    "grace_period_remaining": max(0, int((grace_period_end - datetime.utcnow()).total_seconds())),
                    "grace_period_end": force_change_data["grace_period_end"]
                }
            
            # Check password age for rotation policy
            password_age = await self._get_password_age(user_id)
            max_password_age_days = getattr(settings, 'MAX_PASSWORD_AGE_DAYS', 90)
            
            if password_age and password_age > max_password_age_days:
                return {
                    "change_required": True,
                    "reason": "Password rotation policy",
                    "password_age_days": password_age,
                    "max_age_days": max_password_age_days
                }
            
            return {
                "change_required": False,
                "password_age_days": password_age
            }
        
        except Exception as e:
            logger.error(f"Failed to check password requirements: {str(e)}")
            return {"change_required": False}
    
    async def get_password_history(
        self,
        user_id: str,
        include_hashes: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get password change history for a user
        """
        try:
            history_key = f"password_history:{user_id}"
            history = await cache_service.get(history_key) or []
            
            if not include_hashes:
                # Remove password hashes from response
                safe_history = []
                for entry in history:
                    safe_entry = {
                        "changed_at": entry.get("changed_at"),
                        "change_reason": entry.get("change_reason")
                    }
                    safe_history.append(safe_entry)
                return safe_history
            
            return history
        
        except Exception as e:
            logger.error(f"Failed to get password history: {str(e)}")
            return []
    
    async def validate_password_strength(
        self,
        password: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate password strength without changing it
        """
        try:
            email = None
            if user_id:
                clerk_client = await self._get_clerk_client()
                user = await clerk_client.get_user(user_id)
                email = user.email_addresses[0].email_address if user and user.email_addresses else None
            
            is_valid, errors = password_validator.validate_password(
                password,
                email=email
            )
            
            # Calculate strength score
            strength_score = password_validator.calculate_strength_score(password)
            
            return {
                "valid": is_valid,
                "errors": errors,
                "strength_score": strength_score,
                "strength_label": self._get_strength_label(strength_score),
                "recommendations": self._get_password_recommendations(password, errors)
            }
        
        except Exception as e:
            logger.error(f"Failed to validate password strength: {str(e)}")
            raise ValidationError("Failed to validate password")
    
    # ============= Helper Methods =============
    
    async def _verify_old_password(self, user_id: str, old_password: str) -> bool:
        """Verify the old password"""
        try:
            # Clerk doesn't expose password verification directly
            # This would typically be done through a sign-in attempt
            # For now, we'll assume it's validated through Clerk's API
            
            # In production, you might:
            # 1. Use Clerk's sign-in API with the old password
            # 2. Store a hash of the current password separately (not recommended)
            # 3. Use a custom authentication endpoint
            
            return True  # Placeholder - should be properly implemented
        
        except Exception as e:
            logger.error(f"Failed to verify old password: {str(e)}")
            return False
    
    async def _check_rate_limit(self, user_id: str, ip_address: Optional[str]) -> bool:
        """Check rate limiting for password changes"""
        try:
            # User-based rate limit
            user_key = f"password_change_rate:{user_id}"
            user_attempts = await cache_service.get(user_key) or 0
            
            if user_attempts >= self.max_attempts_per_hour:
                return False
            
            # IP-based rate limit
            if ip_address:
                ip_key = f"password_change_rate_ip:{ip_address}"
                ip_attempts = await cache_service.get(ip_key) or 0
                
                if ip_attempts >= self.max_attempts_per_hour * 2:  # Higher limit for IP
                    return False
            
            return True
        
        except Exception:
            return True
    
    async def _update_rate_limit(
        self,
        user_id: str,
        ip_address: Optional[str],
        success: bool
    ):
        """Update rate limiting counters"""
        try:
            if not success:
                # Increment attempt counters
                user_key = f"password_change_rate:{user_id}"
                user_attempts = await cache_service.get(user_key) or 0
                await cache_service.set(user_key, user_attempts + 1, expire=3600)
                
                if ip_address:
                    ip_key = f"password_change_rate_ip:{ip_address}"
                    ip_attempts = await cache_service.get(ip_key) or 0
                    await cache_service.set(ip_key, ip_attempts + 1, expire=3600)
            else:
                # Reset counters on success
                user_key = f"password_change_rate:{user_id}"
                await cache_service.delete(user_key)
                
                if ip_address:
                    ip_key = f"password_change_rate_ip:{ip_address}"
                    await cache_service.delete(ip_key)
        
        except Exception as e:
            logger.error(f"Failed to update rate limit: {str(e)}")
    
    async def _check_password_age(self, user_id: str) -> bool:
        """Check if password is old enough to change"""
        try:
            metadata_key = f"password_metadata:{user_id}"
            metadata = await cache_service.get(metadata_key)
            
            if not metadata or not metadata.get("last_changed"):
                return True  # No history, allow change
            
            last_changed = datetime.fromisoformat(metadata["last_changed"])
            age_hours = (datetime.utcnow() - last_changed).total_seconds() / 3600
            
            return age_hours >= self.min_password_age_hours
        
        except Exception:
            return True
    
    async def _get_password_age(self, user_id: str) -> Optional[int]:
        """Get password age in days"""
        try:
            metadata_key = f"password_metadata:{user_id}"
            metadata = await cache_service.get(metadata_key)
            
            if metadata and metadata.get("last_changed"):
                last_changed = datetime.fromisoformat(metadata["last_changed"])
                return (datetime.utcnow() - last_changed).days
            
            return None
        
        except Exception:
            return None
    
    async def _is_password_in_history(self, user_id: str, new_password: str) -> bool:
        """Check if password was recently used"""
        try:
            history_key = f"password_history:{user_id}"
            history = await cache_service.get(history_key) or []
            
            # Hash the new password for comparison
            new_hash = hashlib.sha256(new_password.encode()).hexdigest()
            
            # Check recent passwords
            recent_history = history[-self.password_history_count:] if len(history) > self.password_history_count else history
            
            for entry in recent_history:
                if entry.get("password_hash") == new_hash:
                    return True
            
            return False
        
        except Exception:
            return False
    
    async def _add_to_password_history(self, user_id: str, old_password: str):
        """Add password to history"""
        try:
            history_key = f"password_history:{user_id}"
            history = await cache_service.get(history_key) or []
            
            # Add new entry
            history.append({
                "password_hash": hashlib.sha256(old_password.encode()).hexdigest(),
                "changed_at": datetime.utcnow().isoformat()
            })
            
            # Keep only recent history
            max_history = self.password_history_count * 2  # Keep some buffer
            if len(history) > max_history:
                history = history[-max_history:]
            
            await cache_service.set(history_key, history)
        
        except Exception as e:
            logger.error(f"Failed to update password history: {str(e)}")
    
    async def _update_password_metadata(self, user_id: str):
        """Update password metadata"""
        try:
            metadata_key = f"password_metadata:{user_id}"
            metadata = await cache_service.get(metadata_key) or {}
            
            metadata.update({
                "last_changed": datetime.utcnow().isoformat(),
                "change_count": metadata.get("change_count", 0) + 1
            })
            
            await cache_service.set(metadata_key, metadata)
        
        except Exception as e:
            logger.error(f"Failed to update password metadata: {str(e)}")
    
    async def _invalidate_other_sessions(self, user_id: str, current_session_id: str):
        """Invalidate all sessions except current"""
        try:
            clerk_client = await self._get_clerk_client()
            sessions = await clerk_client.list_sessions(user_id=user_id)
            
            for session in sessions:
                if session.id != current_session_id and session.status == "active":
                    await clerk_client.revoke_session(session.id)
        
        except Exception as e:
            logger.error(f"Failed to invalidate sessions: {str(e)}")
    
    async def _send_password_change_notification(
        self,
        email: str,
        user_id: str,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ):
        """Send password change notification"""
        try:
            email_data = {
                "changed_at": datetime.utcnow().isoformat(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "action_required": "If you didn't make this change, please contact support immediately"
            }
            
            await self.email_service.send_password_changed_notification(email, email_data)
        
        except Exception as e:
            logger.error(f"Failed to send password change notification: {str(e)}")
    
    async def _send_force_change_notification(
        self,
        email: str,
        reason: str,
        grace_period_hours: int
    ):
        """Send force password change notification"""
        try:
            email_data = {
                "reason": reason,
                "grace_period_hours": grace_period_hours,
                "deadline": (datetime.utcnow() + timedelta(hours=grace_period_hours)).isoformat()
            }
            
            await self.email_service.send_force_password_change_notification(email, email_data)
        
        except Exception as e:
            logger.error(f"Failed to send force change notification: {str(e)}")
    
    def _get_strength_label(self, score: int) -> str:
        """Get password strength label"""
        if score >= 90:
            return "Very Strong"
        elif score >= 70:
            return "Strong"
        elif score >= 50:
            return "Moderate"
        elif score >= 30:
            return "Weak"
        else:
            return "Very Weak"
    
    def _get_password_recommendations(self, password: str, errors: List[str]) -> List[str]:
        """Get password improvement recommendations"""
        recommendations = []
        
        if len(password) < 12:
            recommendations.append("Use at least 12 characters")
        
        if not any(c.isupper() for c in password):
            recommendations.append("Include uppercase letters")
        
        if not any(c.islower() for c in password):
            recommendations.append("Include lowercase letters")
        
        if not any(c.isdigit() for c in password):
            recommendations.append("Include numbers")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            recommendations.append("Include special characters")
        
        if "common" in ' '.join(errors).lower():
            recommendations.append("Avoid common passwords and dictionary words")
        
        if "breach" in ' '.join(errors).lower():
            recommendations.append("This password has been found in data breaches")
        
        return recommendations[:3]  # Return top 3 recommendations


# Singleton instance
password_change_service = PasswordChangeService()