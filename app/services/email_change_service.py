from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import secrets
import hashlib
import structlog
from enum import Enum

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthorizationError
from app.services.cache_service import cache_service
from app.services.email_service import EmailService
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class EmailChangeStatus(Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class EmailChangeService:
    """
    Service for managing email address changes with verification
    """
    
    def __init__(self):
        self.verification_expiry_hours = 24
        self.max_attempts_per_day = 3
        self.cooldown_minutes = 5
        self.email_service = EmailService()
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def initiate_email_change(
        self,
        user_id: str,
        current_email: str,
        new_email: str,
        password: Optional[str] = None,
        require_password: bool = True
    ) -> Dict[str, Any]:
        """
        Initiate email address change with verification
        """
        try:
            # Validate new email format
            if not self._validate_email_format(new_email):
                raise ValidationError("Invalid email format")
            
            # Check if new email is same as current
            if current_email.lower() == new_email.lower():
                raise ValidationError("New email cannot be the same as current email")
            
            # Check rate limiting
            if not await self._check_rate_limit(user_id):
                raise ValidationError(f"Too many email change attempts. Please wait {self.cooldown_minutes} minutes.")
            
            # Verify password if required
            if require_password and password:
                if not await self._verify_user_password(user_id, password):
                    raise ValidationError("Invalid password")
            
            # Check if new email is already in use
            clerk_client = await self._get_clerk_client()
            existing_users = await clerk_client.list_users(email_address=[new_email])
            
            if existing_users:
                raise ValidationError("Email address is already in use")
            
            # Check for pending email change
            pending_change = await self._get_pending_email_change(user_id)
            if pending_change:
                # Cancel previous request
                await self._cancel_email_change(user_id, pending_change["change_id"])
            
            # Generate verification tokens
            change_id = secrets.token_urlsafe(16)
            old_email_token = secrets.token_urlsafe(32)
            new_email_token = secrets.token_urlsafe(32)
            
            # Create email change request
            change_data = {
                "change_id": change_id,
                "user_id": user_id,
                "current_email": current_email,
                "new_email": new_email,
                "old_email_token": hashlib.sha256(old_email_token.encode()).hexdigest(),
                "new_email_token": hashlib.sha256(new_email_token.encode()).hexdigest(),
                "status": EmailChangeStatus.PENDING.value,
                "old_email_verified": False,
                "new_email_verified": False,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(hours=self.verification_expiry_hours)).isoformat(),
                "ip_address": None,  # Should be passed from request
                "user_agent": None   # Should be passed from request
            }
            
            # Store email change request
            change_key = f"email_change:{change_id}"
            await cache_service.set(
                change_key,
                change_data,
                expire=self.verification_expiry_hours * 3600
            )
            
            # Store user's active change request
            user_change_key = f"user_email_change:{user_id}"
            await cache_service.set(
                user_change_key,
                change_id,
                expire=self.verification_expiry_hours * 3600
            )
            
            # Update rate limiting
            await self._update_rate_limit(user_id)
            
            # Send verification emails
            await self._send_verification_emails(
                change_id=change_id,
                current_email=current_email,
                new_email=new_email,
                old_token=old_email_token,
                new_token=new_email_token
            )
            
            logger.info(
                f"Email change initiated",
                user_id=user_id,
                change_id=change_id,
                new_email=new_email
            )
            
            return {
                "change_id": change_id,
                "status": EmailChangeStatus.PENDING.value,
                "message": "Verification emails sent to both current and new email addresses",
                "expires_at": change_data["expires_at"],
                "verification_required": ["current_email", "new_email"]
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to initiate email change: {str(e)}")
            raise ValidationError("Failed to initiate email change")
    
    async def verify_email_token(
        self,
        change_id: str,
        token: str,
        email_type: str  # "old" or "new"
    ) -> Dict[str, Any]:
        """
        Verify email change token
        """
        try:
            # Get change request
            change_key = f"email_change:{change_id}"
            change_data = await cache_service.get(change_key)
            
            if not change_data:
                raise ValidationError("Invalid or expired email change request")
            
            # Check if already cancelled or completed
            if change_data["status"] != EmailChangeStatus.PENDING.value:
                raise ValidationError(f"Email change request is {change_data['status']}")
            
            # Check expiry
            expires_at = datetime.fromisoformat(change_data["expires_at"])
            if datetime.utcnow() > expires_at:
                change_data["status"] = EmailChangeStatus.EXPIRED.value
                await cache_service.set(change_key, change_data, expire=86400)  # Keep for 1 day
                raise ValidationError("Email change request has expired")
            
            # Verify token
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            if email_type == "old":
                if token_hash != change_data["old_email_token"]:
                    raise ValidationError("Invalid verification token")
                
                change_data["old_email_verified"] = True
                change_data["old_email_verified_at"] = datetime.utcnow().isoformat()
                
            elif email_type == "new":
                if token_hash != change_data["new_email_token"]:
                    raise ValidationError("Invalid verification token")
                
                change_data["new_email_verified"] = True
                change_data["new_email_verified_at"] = datetime.utcnow().isoformat()
                
            else:
                raise ValidationError("Invalid email type")
            
            # Check if both emails are verified
            if change_data["old_email_verified"] and change_data["new_email_verified"]:
                # Complete the email change
                await self._complete_email_change(change_data)
                change_data["status"] = EmailChangeStatus.VERIFIED.value
                change_data["completed_at"] = datetime.utcnow().isoformat()
            
            # Update change data
            remaining_ttl = int((expires_at - datetime.utcnow()).total_seconds())
            await cache_service.set(change_key, change_data, expire=max(remaining_ttl, 3600))
            
            logger.info(
                f"Email token verified",
                change_id=change_id,
                email_type=email_type,
                both_verified=change_data["old_email_verified"] and change_data["new_email_verified"]
            )
            
            if change_data["status"] == EmailChangeStatus.VERIFIED.value:
                return {
                    "verified": True,
                    "completed": True,
                    "message": "Email address successfully changed",
                    "new_email": change_data["new_email"]
                }
            else:
                pending_verification = []
                if not change_data["old_email_verified"]:
                    pending_verification.append("current_email")
                if not change_data["new_email_verified"]:
                    pending_verification.append("new_email")
                
                return {
                    "verified": True,
                    "completed": False,
                    "message": f"{email_type.capitalize()} email verified",
                    "pending_verification": pending_verification
                }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to verify email token: {str(e)}")
            raise ValidationError("Failed to verify email token")
    
    async def cancel_email_change(
        self,
        user_id: str,
        change_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Cancel a pending email change request
        """
        try:
            # Get change request
            if not change_id:
                user_change_key = f"user_email_change:{user_id}"
                change_id = await cache_service.get(user_change_key)
                
                if not change_id:
                    raise ValidationError("No pending email change request")
            
            change_key = f"email_change:{change_id}"
            change_data = await cache_service.get(change_key)
            
            if not change_data:
                raise ValidationError("Email change request not found")
            
            # Verify user owns this request
            if change_data["user_id"] != user_id:
                raise AuthorizationError("Unauthorized to cancel this request")
            
            # Update status
            change_data["status"] = EmailChangeStatus.CANCELLED.value
            change_data["cancelled_at"] = datetime.utcnow().isoformat()
            
            # Save with short expiry
            await cache_service.set(change_key, change_data, expire=86400)  # Keep for 1 day
            
            # Remove user's active change request
            user_change_key = f"user_email_change:{user_id}"
            await cache_service.delete(user_change_key)
            
            logger.info(
                f"Email change cancelled",
                user_id=user_id,
                change_id=change_id
            )
            
            return {
                "cancelled": True,
                "change_id": change_id,
                "message": "Email change request cancelled"
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to cancel email change: {str(e)}")
            raise ValidationError("Failed to cancel email change")
    
    async def resend_verification_email(
        self,
        user_id: str,
        email_type: str  # "old", "new", or "both"
    ) -> Dict[str, Any]:
        """
        Resend verification email(s)
        """
        try:
            # Get active change request
            user_change_key = f"user_email_change:{user_id}"
            change_id = await cache_service.get(user_change_key)
            
            if not change_id:
                raise ValidationError("No pending email change request")
            
            change_key = f"email_change:{change_id}"
            change_data = await cache_service.get(change_key)
            
            if not change_data:
                raise ValidationError("Email change request not found")
            
            # Check status
            if change_data["status"] != EmailChangeStatus.PENDING.value:
                raise ValidationError(f"Cannot resend for {change_data['status']} request")
            
            # Check resend cooldown
            resend_key = f"email_change_resend:{change_id}"
            last_resend = await cache_service.get(resend_key)
            
            if last_resend:
                raise ValidationError("Please wait before requesting another resend")
            
            # Generate new tokens
            old_email_token = None
            new_email_token = None
            
            if email_type in ["old", "both"] and not change_data["old_email_verified"]:
                old_email_token = secrets.token_urlsafe(32)
                change_data["old_email_token"] = hashlib.sha256(old_email_token.encode()).hexdigest()
            
            if email_type in ["new", "both"] and not change_data["new_email_verified"]:
                new_email_token = secrets.token_urlsafe(32)
                change_data["new_email_token"] = hashlib.sha256(new_email_token.encode()).hexdigest()
            
            # Update change data
            expires_at = datetime.fromisoformat(change_data["expires_at"])
            remaining_ttl = int((expires_at - datetime.utcnow()).total_seconds())
            await cache_service.set(change_key, change_data, expire=max(remaining_ttl, 3600))
            
            # Set resend cooldown
            await cache_service.set(resend_key, True, expire=300)  # 5 minute cooldown
            
            # Send emails
            await self._send_verification_emails(
                change_id=change_id,
                current_email=change_data["current_email"] if old_email_token else None,
                new_email=change_data["new_email"] if new_email_token else None,
                old_token=old_email_token,
                new_token=new_email_token
            )
            
            emails_sent = []
            if old_email_token:
                emails_sent.append("current_email")
            if new_email_token:
                emails_sent.append("new_email")
            
            logger.info(
                f"Verification emails resent",
                user_id=user_id,
                change_id=change_id,
                email_type=email_type
            )
            
            return {
                "resent": True,
                "emails_sent": emails_sent,
                "message": f"Verification email(s) resent to {', '.join(emails_sent)}"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to resend verification email: {str(e)}")
            raise ValidationError("Failed to resend verification email")
    
    async def get_email_change_status(
        self,
        user_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get status of pending email change
        """
        try:
            # Get active change request
            user_change_key = f"user_email_change:{user_id}"
            change_id = await cache_service.get(user_change_key)
            
            if not change_id:
                return None
            
            change_key = f"email_change:{change_id}"
            change_data = await cache_service.get(change_key)
            
            if not change_data:
                return None
            
            # Check expiry
            expires_at = datetime.fromisoformat(change_data["expires_at"])
            if datetime.utcnow() > expires_at and change_data["status"] == EmailChangeStatus.PENDING.value:
                change_data["status"] = EmailChangeStatus.EXPIRED.value
            
            # Return safe data
            return {
                "change_id": change_data["change_id"],
                "status": change_data["status"],
                "new_email": change_data["new_email"],
                "old_email_verified": change_data["old_email_verified"],
                "new_email_verified": change_data["new_email_verified"],
                "created_at": change_data["created_at"],
                "expires_at": change_data["expires_at"],
                "time_remaining": max(0, int((expires_at - datetime.utcnow()).total_seconds()))
            }
        
        except Exception as e:
            logger.error(f"Failed to get email change status: {str(e)}")
            return None
    
    # ============= Helper Methods =============
    
    def _validate_email_format(self, email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    async def _verify_user_password(self, user_id: str, password: str) -> bool:
        """Verify user password"""
        try:
            # This would typically verify against Clerk's authentication
            # For now, we'll assume it's validated through Clerk's API
            clerk_client = await self._get_clerk_client()
            # Clerk doesn't expose password verification directly
            # This would need to be handled through a sign-in attempt
            return True  # Placeholder
        except:
            return False
    
    async def _check_rate_limit(self, user_id: str) -> bool:
        """Check rate limiting for email changes"""
        try:
            rate_limit_key = f"email_change_rate:{user_id}"
            attempts = await cache_service.get(rate_limit_key) or []
            
            # Remove old attempts
            cutoff_time = datetime.utcnow() - timedelta(days=1)
            attempts = [a for a in attempts if datetime.fromisoformat(a) > cutoff_time]
            
            # Check if within limits
            if len(attempts) >= self.max_attempts_per_day:
                # Check cooldown
                last_attempt = datetime.fromisoformat(attempts[-1])
                if datetime.utcnow() - last_attempt < timedelta(minutes=self.cooldown_minutes):
                    return False
            
            return True
        
        except Exception:
            return True
    
    async def _update_rate_limit(self, user_id: str):
        """Update rate limiting counter"""
        try:
            rate_limit_key = f"email_change_rate:{user_id}"
            attempts = await cache_service.get(rate_limit_key) or []
            
            # Add new attempt
            attempts.append(datetime.utcnow().isoformat())
            
            # Keep only last 24 hours
            cutoff_time = datetime.utcnow() - timedelta(days=1)
            attempts = [a for a in attempts if datetime.fromisoformat(a) > cutoff_time]
            
            await cache_service.set(rate_limit_key, attempts, expire=86400)
        
        except Exception as e:
            logger.error(f"Failed to update rate limit: {str(e)}")
    
    async def _get_pending_email_change(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get pending email change for user"""
        try:
            user_change_key = f"user_email_change:{user_id}"
            change_id = await cache_service.get(user_change_key)
            
            if change_id:
                change_key = f"email_change:{change_id}"
                return await cache_service.get(change_key)
            
            return None
        
        except Exception:
            return None
    
    async def _cancel_email_change(self, user_id: str, change_id: str):
        """Cancel an email change request"""
        try:
            change_key = f"email_change:{change_id}"
            change_data = await cache_service.get(change_key)
            
            if change_data:
                change_data["status"] = EmailChangeStatus.CANCELLED.value
                change_data["cancelled_at"] = datetime.utcnow().isoformat()
                await cache_service.set(change_key, change_data, expire=3600)
            
            # Remove user's active change
            user_change_key = f"user_email_change:{user_id}"
            await cache_service.delete(user_change_key)
        
        except Exception as e:
            logger.error(f"Failed to cancel email change: {str(e)}")
    
    async def _complete_email_change(self, change_data: Dict[str, Any]):
        """Complete the email change in Clerk"""
        try:
            clerk_client = await self._get_clerk_client()
            user_id = change_data["user_id"]
            new_email = change_data["new_email"]
            
            # Update user email in Clerk
            await clerk_client.update_user(
                user_id,
                primary_email_address_id=new_email
            )
            
            # Log the change
            log_key = f"email_change_log:{user_id}:{datetime.utcnow().timestamp()}"
            log_data = {
                "user_id": user_id,
                "old_email": change_data["current_email"],
                "new_email": new_email,
                "changed_at": datetime.utcnow().isoformat(),
                "change_id": change_data["change_id"]
            }
            await cache_service.set(log_key, log_data, expire=90 * 86400)  # Keep for 90 days
            
            # Send confirmation email
            await self._send_change_confirmation(
                old_email=change_data["current_email"],
                new_email=new_email
            )
            
            # Clean up
            user_change_key = f"user_email_change:{user_id}"
            await cache_service.delete(user_change_key)
            
            logger.info(
                f"Email change completed",
                user_id=user_id,
                old_email=change_data["current_email"],
                new_email=new_email
            )
        
        except Exception as e:
            logger.error(f"Failed to complete email change: {str(e)}")
            raise
    
    async def _send_verification_emails(
        self,
        change_id: str,
        current_email: Optional[str],
        new_email: Optional[str],
        old_token: Optional[str],
        new_token: Optional[str]
    ):
        """Send verification emails"""
        try:
            base_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:3000"
            
            if current_email and old_token:
                old_verify_url = f"{base_url}/email-change/verify?id={change_id}&token={old_token}&type=old"
                await self.email_service.send_email_change_verification(
                    email=current_email,
                    data={
                        "verification_url": old_verify_url,
                        "email_type": "current",
                        "expires_hours": self.verification_expiry_hours
                    }
                )
            
            if new_email and new_token:
                new_verify_url = f"{base_url}/email-change/verify?id={change_id}&token={new_token}&type=new"
                await self.email_service.send_email_change_verification(
                    email=new_email,
                    data={
                        "verification_url": new_verify_url,
                        "email_type": "new",
                        "expires_hours": self.verification_expiry_hours
                    }
                )
        
        except Exception as e:
            logger.error(f"Failed to send verification emails: {str(e)}")
    
    async def _send_change_confirmation(self, old_email: str, new_email: str):
        """Send confirmation emails after successful change"""
        try:
            # Send to old email
            await self.email_service.send_email_change_confirmation(
                email=old_email,
                data={
                    "old_email": old_email,
                    "new_email": new_email,
                    "message": "Your email address has been changed"
                }
            )
            
            # Send to new email
            await self.email_service.send_email_change_confirmation(
                email=new_email,
                data={
                    "old_email": old_email,
                    "new_email": new_email,
                    "message": "This is now your primary email address"
                }
            )
        
        except Exception as e:
            logger.error(f"Failed to send confirmation emails: {str(e)}")


# Singleton instance
email_change_service = EmailChangeService()