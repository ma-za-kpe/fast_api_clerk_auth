from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import secrets
import base64
import io
import pyotp
import qrcode
import qrcode.image.svg
from PIL import Image
import structlog

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthenticationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class MFAService:
    """
    Multi-Factor Authentication service supporting TOTP, SMS, and Email
    """
    
    def __init__(self):
        self.issuer_name = settings.APP_NAME if hasattr(settings, 'APP_NAME') else "FastAPI Auth"
        self.totp_period = 30  # Standard 30-second window
        self.totp_digits = 6   # Standard 6-digit codes
        self.backup_codes_count = 10
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            from app.core.clerk import get_clerk_client
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    # ============= TOTP Methods =============
    
    async def setup_totp(self, user_id: str, user_email: str) -> Dict[str, Any]:
        """
        Set up TOTP for a user - generates secret and QR code
        """
        try:
            # Generate a secure secret
            secret = pyotp.random_base32()
            
            # Create TOTP instance
            totp = pyotp.TOTP(
                secret,
                issuer=self.issuer_name,
                digits=self.totp_digits,
                interval=self.totp_period
            )
            
            # Generate provisioning URI for QR code
            provisioning_uri = totp.provisioning_uri(
                name=user_email,
                issuer_name=self.issuer_name
            )
            
            # Generate QR code
            qr_code_data = self._generate_qr_code(provisioning_uri)
            
            # Generate backup codes
            backup_codes = self._generate_backup_codes()
            
            # Store setup data temporarily (user must verify to complete setup)
            setup_key = f"mfa_setup:{user_id}"
            setup_data = {
                "user_id": user_id,
                "secret": secret,
                "backup_codes": backup_codes,
                "created_at": datetime.utcnow().isoformat(),
                "verified": False,
                "method": "totp"
            }
            
            # Store for 10 minutes
            await cache_service.set(setup_key, setup_data, expire=600)
            
            logger.info(f"TOTP setup initiated for user {user_id}")
            
            return {
                "secret": secret,
                "qr_code": qr_code_data,
                "backup_codes": backup_codes,
                "manual_entry_key": self._format_secret_for_display(secret),
                "issuer": self.issuer_name,
                "period": self.totp_period,
                "digits": self.totp_digits,
                "provisioning_uri": provisioning_uri
            }
        
        except Exception as e:
            logger.error(f"Failed to setup TOTP: {str(e)}")
            raise ValidationError("Failed to setup two-factor authentication")
    
    async def verify_totp_setup(
        self,
        user_id: str,
        code: str
    ) -> Dict[str, Any]:
        """
        Verify TOTP setup with a code to complete activation
        """
        try:
            # Get setup data from cache
            setup_key = f"mfa_setup:{user_id}"
            setup_data = await cache_service.get(setup_key)
            
            if not setup_data:
                raise ValidationError("MFA setup session expired. Please start over.")
            
            if setup_data.get("method") != "totp":
                raise ValidationError("Invalid MFA setup type")
            
            secret = setup_data.get("secret")
            
            # Verify the code
            if not self._verify_totp_code(secret, code):
                raise ValidationError("Invalid verification code")
            
            # Store MFA data permanently
            clerk_client = await self._get_clerk_client()
            
            # Update user metadata with MFA info
            await clerk_client.update_user(
                user_id=user_id,
                private_metadata={
                    "mfa_enabled": True,
                    "mfa_methods": ["totp"],
                    "mfa_secret": secret,  # In production, encrypt this
                    "mfa_backup_codes": setup_data.get("backup_codes"),
                    "mfa_setup_date": datetime.utcnow().isoformat()
                }
            )
            
            # Mark setup as verified and extend cache
            setup_data["verified"] = True
            await cache_service.set(setup_key, setup_data, expire=86400)  # Keep for 24 hours
            
            logger.info(f"TOTP successfully activated for user {user_id}")
            
            return {
                "status": "activated",
                "method": "totp",
                "backup_codes": setup_data.get("backup_codes"),
                "message": "Two-factor authentication has been successfully enabled"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to verify TOTP setup: {str(e)}")
            raise ValidationError("Failed to verify authentication setup")
    
    async def verify_totp(
        self,
        user_id: str,
        code: str,
        allow_backup_code: bool = True
    ) -> Dict[str, Any]:
        """
        Verify a TOTP code for authentication
        """
        try:
            # Get user's MFA data
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise AuthenticationError("User not found")
            
            mfa_data = user.private_metadata or {}
            
            if not mfa_data.get("mfa_enabled"):
                raise ValidationError("MFA is not enabled for this account")
            
            # Check if it's a backup code
            if allow_backup_code:
                backup_codes = mfa_data.get("mfa_backup_codes", [])
                if code in backup_codes:
                    # Remove used backup code
                    backup_codes.remove(code)
                    
                    # Update user with remaining backup codes
                    await clerk_client.update_user(
                        user_id=user_id,
                        private_metadata={
                            **mfa_data,
                            "mfa_backup_codes": backup_codes,
                            "last_backup_code_used": datetime.utcnow().isoformat()
                        }
                    )
                    
                    logger.info(f"Backup code used for user {user_id}")
                    
                    return {
                        "verified": True,
                        "method": "backup_code",
                        "remaining_backup_codes": len(backup_codes),
                        "warning": "Backup code used. Please regenerate backup codes if needed."
                    }
            
            # Verify TOTP code
            secret = mfa_data.get("mfa_secret")
            if not secret:
                raise ValidationError("MFA secret not found")
            
            if not self._verify_totp_code(secret, code):
                # Log failed attempt
                await self._log_failed_mfa_attempt(user_id, "totp")
                raise AuthenticationError("Invalid authentication code")
            
            # Log successful verification
            await self._log_successful_mfa(user_id, "totp")
            
            return {
                "verified": True,
                "method": "totp",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except (ValidationError, AuthenticationError):
            raise
        except Exception as e:
            logger.error(f"Failed to verify TOTP: {str(e)}")
            raise AuthenticationError("Failed to verify authentication code")
    
    async def disable_totp(self, user_id: str, code: str) -> Dict[str, Any]:
        """
        Disable TOTP for a user (requires current code for security)
        """
        try:
            # Verify the code first
            verification = await self.verify_totp(user_id, code, allow_backup_code=False)
            
            if not verification.get("verified"):
                raise AuthenticationError("Invalid authentication code")
            
            # Disable MFA
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            mfa_data = user.private_metadata or {}
            
            # Remove MFA data
            await clerk_client.update_user(
                user_id=user_id,
                private_metadata={
                    **mfa_data,
                    "mfa_enabled": False,
                    "mfa_methods": [],
                    "mfa_secret": None,
                    "mfa_backup_codes": None,
                    "mfa_disabled_date": datetime.utcnow().isoformat()
                }
            )
            
            # Clear any cached MFA data
            cache_key = f"mfa_setup:{user_id}"
            await cache_service.delete(cache_key)
            
            logger.info(f"TOTP disabled for user {user_id}")
            
            return {
                "status": "disabled",
                "method": "totp",
                "message": "Two-factor authentication has been disabled"
            }
        
        except (AuthenticationError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"Failed to disable TOTP: {str(e)}")
            raise ValidationError("Failed to disable two-factor authentication")
    
    async def regenerate_backup_codes(
        self,
        user_id: str,
        current_code: str
    ) -> Dict[str, Any]:
        """
        Regenerate backup codes (requires current TOTP code)
        """
        try:
            # Verify current code
            verification = await self.verify_totp(user_id, current_code, allow_backup_code=False)
            
            if not verification.get("verified"):
                raise AuthenticationError("Invalid authentication code")
            
            # Generate new backup codes
            new_backup_codes = self._generate_backup_codes()
            
            # Update user metadata
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            mfa_data = user.private_metadata or {}
            
            await clerk_client.update_user(
                user_id=user_id,
                private_metadata={
                    **mfa_data,
                    "mfa_backup_codes": new_backup_codes,
                    "backup_codes_regenerated": datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Backup codes regenerated for user {user_id}")
            
            return {
                "backup_codes": new_backup_codes,
                "count": len(new_backup_codes),
                "message": "New backup codes generated. Please save them securely."
            }
        
        except (AuthenticationError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"Failed to regenerate backup codes: {str(e)}")
            raise ValidationError("Failed to regenerate backup codes")
    
    # ============= SMS MFA Methods =============
    
    async def setup_sms_mfa(self, user_id: str, phone_number: str) -> Dict[str, Any]:
        """
        Set up SMS-based MFA
        """
        try:
            # Validate phone number format
            if not self._validate_phone_number(phone_number):
                raise ValidationError("Invalid phone number format")
            
            # Generate and send verification code
            code = self._generate_numeric_code(6)
            
            # Store setup data
            setup_key = f"mfa_sms_setup:{user_id}"
            setup_data = {
                "user_id": user_id,
                "phone_number": phone_number,
                "code": code,
                "created_at": datetime.utcnow().isoformat(),
                "method": "sms"
            }
            
            await cache_service.set(setup_key, setup_data, expire=300)  # 5 minutes
            
            # Send SMS (integrate with SMS service)
            await self._send_sms_code(phone_number, code)
            
            logger.info(f"SMS MFA setup initiated for user {user_id}")
            
            return {
                "status": "code_sent",
                "method": "sms",
                "phone_number": self._mask_phone_number(phone_number),
                "expires_in": 300
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to setup SMS MFA: {str(e)}")
            raise ValidationError("Failed to setup SMS authentication")
    
    async def verify_sms_mfa(
        self,
        user_id: str,
        code: str,
        setup: bool = False
    ) -> Dict[str, Any]:
        """
        Verify SMS MFA code
        """
        try:
            if setup:
                # Verify setup code
                cache_key = f"mfa_sms_setup:{user_id}"
            else:
                # Verify authentication code
                cache_key = f"mfa_sms_auth:{user_id}"
            
            cached_data = await cache_service.get(cache_key)
            
            if not cached_data:
                raise ValidationError("Code expired or invalid")
            
            if cached_data.get("code") != code:
                await self._log_failed_mfa_attempt(user_id, "sms")
                raise AuthenticationError("Invalid verification code")
            
            # If setup, activate SMS MFA
            if setup:
                clerk_client = await self._get_clerk_client()
                user = await clerk_client.get_user(user_id)
                mfa_data = user.private_metadata or {}
                
                methods = mfa_data.get("mfa_methods", [])
                if "sms" not in methods:
                    methods.append("sms")
                
                await clerk_client.update_user(
                    user_id=user_id,
                    private_metadata={
                        **mfa_data,
                        "mfa_enabled": True,
                        "mfa_methods": methods,
                        "mfa_phone": cached_data.get("phone_number"),
                        "mfa_sms_setup_date": datetime.utcnow().isoformat()
                    }
                )
            
            # Clear used code
            await cache_service.delete(cache_key)
            
            await self._log_successful_mfa(user_id, "sms")
            
            return {
                "verified": True,
                "method": "sms",
                "message": "SMS verification successful"
            }
        
        except (ValidationError, AuthenticationError):
            raise
        except Exception as e:
            logger.error(f"Failed to verify SMS MFA: {str(e)}")
            raise AuthenticationError("Failed to verify SMS code")
    
    async def send_sms_mfa_code(self, user_id: str) -> Dict[str, Any]:
        """
        Send MFA code via SMS for authentication
        """
        try:
            # Get user's MFA phone
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            mfa_data = user.private_metadata or {}
            mfa_phone = mfa_data.get("mfa_phone")
            
            if not mfa_phone:
                raise ValidationError("No phone number configured for MFA")
            
            # Generate code
            code = self._generate_numeric_code(6)
            
            # Store for verification
            cache_key = f"mfa_sms_auth:{user_id}"
            await cache_service.set(
                cache_key,
                {
                    "code": code,
                    "phone_number": mfa_phone,
                    "created_at": datetime.utcnow().isoformat()
                },
                expire=300  # 5 minutes
            )
            
            # Send SMS
            await self._send_sms_code(mfa_phone, code)
            
            logger.info(f"MFA SMS code sent to user {user_id}")
            
            return {
                "status": "sent",
                "method": "sms",
                "phone_number": self._mask_phone_number(mfa_phone),
                "expires_in": 300
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to send SMS MFA code: {str(e)}")
            raise ValidationError("Failed to send authentication code")
    
    async def disable_sms_mfa(self, user_id: str, code: str) -> Dict[str, Any]:
        """
        Disable SMS MFA for a user
        """
        try:
            # Verify the code first
            verification = await self.verify_sms_mfa(user_id, code, setup=False)
            
            if not verification.get("verified"):
                raise AuthenticationError("Invalid verification code")
            
            # Remove SMS from MFA methods
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            mfa_data = user.private_metadata or {}
            
            methods = mfa_data.get("mfa_methods", [])
            if "sms" in methods:
                methods.remove("sms")
            
            # Update user metadata
            await clerk_client.update_user(
                user_id=user_id,
                private_metadata={
                    **mfa_data,
                    "mfa_methods": methods,
                    "mfa_phone": None,
                    "mfa_sms_disabled_date": datetime.utcnow().isoformat(),
                    "mfa_enabled": len(methods) > 0  # Disable MFA if no methods left
                }
            )
            
            logger.info(f"SMS MFA disabled for user {user_id}")
            
            return {
                "status": "disabled",
                "method": "sms",
                "message": "SMS authentication has been disabled"
            }
        
        except (AuthenticationError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"Failed to disable SMS MFA: {str(e)}")
            raise ValidationError("Failed to disable SMS authentication")
    
    # ============= Email MFA Methods =============
    
    async def setup_email_mfa(self, user_id: str, email: str) -> Dict[str, Any]:
        """
        Set up email-based MFA
        """
        try:
            # Generate and send verification code
            code = self._generate_numeric_code(6)
            
            # Store setup data
            setup_key = f"mfa_email_setup:{user_id}"
            setup_data = {
                "user_id": user_id,
                "email": email,
                "code": code,
                "created_at": datetime.utcnow().isoformat(),
                "method": "email"
            }
            
            await cache_service.set(setup_key, setup_data, expire=300)  # 5 minutes
            
            # Send email (integrate with email service)
            from app.tasks.email_tasks import send_mfa_code_email
            send_mfa_code_email.delay(email, code)
            
            logger.info(f"Email MFA setup initiated for user {user_id}")
            
            return {
                "status": "code_sent",
                "method": "email",
                "email": self._mask_email(email),
                "expires_in": 300
            }
        
        except Exception as e:
            logger.error(f"Failed to setup email MFA: {str(e)}")
            raise ValidationError("Failed to setup email authentication")
    
    async def verify_email_mfa(
        self,
        user_id: str,
        code: str,
        setup: bool = False
    ) -> Dict[str, Any]:
        """
        Verify email MFA code
        """
        try:
            if setup:
                # Verify setup code
                cache_key = f"mfa_email_setup:{user_id}"
            else:
                # Verify authentication code
                cache_key = f"mfa_email_auth:{user_id}"
            
            cached_data = await cache_service.get(cache_key)
            
            if not cached_data:
                raise ValidationError("Code expired or invalid")
            
            if cached_data.get("code") != code:
                await self._log_failed_mfa_attempt(user_id, "email")
                raise AuthenticationError("Invalid verification code")
            
            # If setup, activate email MFA
            if setup:
                clerk_client = await self._get_clerk_client()
                user = await clerk_client.get_user(user_id)
                mfa_data = user.private_metadata or {}
                
                methods = mfa_data.get("mfa_methods", [])
                if "email" not in methods:
                    methods.append("email")
                
                await clerk_client.update_user(
                    user_id=user_id,
                    private_metadata={
                        **mfa_data,
                        "mfa_enabled": True,
                        "mfa_methods": methods,
                        "mfa_email": cached_data.get("email"),
                        "mfa_email_setup_date": datetime.utcnow().isoformat()
                    }
                )
            
            # Clear used code
            await cache_service.delete(cache_key)
            
            await self._log_successful_mfa(user_id, "email")
            
            return {
                "verified": True,
                "method": "email",
                "message": "Email verification successful"
            }
        
        except (ValidationError, AuthenticationError):
            raise
        except Exception as e:
            logger.error(f"Failed to verify email MFA: {str(e)}")
            raise AuthenticationError("Failed to verify email code")
    
    async def send_email_mfa_code(self, user_id: str) -> Dict[str, Any]:
        """
        Send MFA code via email for authentication
        """
        try:
            # Get user's MFA email
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            mfa_data = user.private_metadata or {}
            mfa_email = mfa_data.get("mfa_email")
            
            if not mfa_email:
                # Use primary email
                mfa_email = user.email_addresses[0].email_address if user.email_addresses else None
            
            if not mfa_email:
                raise ValidationError("No email address configured for MFA")
            
            # Generate code
            code = self._generate_numeric_code(6)
            
            # Store for verification
            cache_key = f"mfa_email_auth:{user_id}"
            await cache_service.set(
                cache_key,
                {
                    "code": code,
                    "email": mfa_email,
                    "created_at": datetime.utcnow().isoformat()
                },
                expire=300  # 5 minutes
            )
            
            # Send email
            from app.tasks.email_tasks import send_mfa_code_email
            send_mfa_code_email.delay(mfa_email, code)
            
            logger.info(f"MFA code sent to user {user_id}")
            
            return {
                "status": "sent",
                "method": "email",
                "email": self._mask_email(mfa_email),
                "expires_in": 300
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to send email MFA code: {str(e)}")
            raise ValidationError("Failed to send authentication code")
    
    # ============= Helper Methods =============
    
    def _verify_totp_code(self, secret: str, code: str) -> bool:
        """Verify a TOTP code"""
        totp = pyotp.TOTP(secret, digits=self.totp_digits, interval=self.totp_period)
        # Allow for time drift (1 period before/after)
        return totp.verify(code, valid_window=1)
    
    def _generate_qr_code(self, data: str) -> str:
        """Generate QR code as base64 encoded PNG"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def _generate_backup_codes(self) -> List[str]:
        """Generate backup codes"""
        codes = []
        for _ in range(self.backup_codes_count):
            # Generate 8-character alphanumeric codes
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            # Format as XXXX-XXXX
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes
    
    def _generate_numeric_code(self, length: int = 6) -> str:
        """Generate numeric code for email/SMS MFA"""
        return ''.join(secrets.choice('0123456789') for _ in range(length))
    
    def _format_secret_for_display(self, secret: str) -> str:
        """Format secret for manual entry (space every 4 chars)"""
        return ' '.join(secret[i:i+4] for i in range(0, len(secret), 4))
    
    def _mask_email(self, email: str) -> str:
        """Mask email for display"""
        parts = email.split('@')
        if len(parts) != 2:
            return email
        
        username = parts[0]
        domain = parts[1]
        
        if len(username) <= 3:
            masked = username[0] + '*' * (len(username) - 1)
        else:
            masked = username[:2] + '*' * (len(username) - 4) + username[-2:]
        
        return f"{masked}@{domain}"
    
    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for display"""
        # Remove non-numeric characters for masking
        digits = ''.join(filter(str.isdigit, phone))
        
        if len(digits) < 4:
            return phone
        
        # Show first 2 and last 2 digits
        if len(digits) >= 10:
            return f"+{digits[0]}***-***-{digits[-4:]}"
        else:
            return f"{digits[:2]}***{digits[-2:]}"
    
    def _validate_phone_number(self, phone: str) -> bool:
        """Validate phone number format"""
        import re
        # Basic phone number validation (supports various formats)
        pattern = r'^[\+]?[1-9][\d]{0,15}$'
        cleaned = re.sub(r'[\s\-\(\)]', '', phone)
        return bool(re.match(pattern, cleaned)) and len(cleaned) >= 10
    
    async def _send_sms_code(self, phone_number: str, code: str):
        """Send SMS code using configured SMS provider"""
        try:
            # Use the new SMS service
            from app.services.sms_service import sms_service
            
            # Send verification code via SMS service
            result = await sms_service.send_verification_code(
                to_phone=phone_number,
                code=code,
                purpose="mfa"
            )
            
            if not result.get("success"):
                error_msg = result.get("error", "Failed to send SMS")
                logger.error(f"SMS send failed: {error_msg}")
                raise ValidationError(error_msg)
            
            logger.info(f"MFA code sent via SMS", 
                       phone=phone_number[:6] + "****",
                       message_id=result.get("message_id"))
                
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to send SMS: {str(e)}")
            raise ValidationError("Failed to send SMS verification code")
    
    async def _log_failed_mfa_attempt(self, user_id: str, method: str):
        """Log failed MFA attempt"""
        key = f"mfa_failures:{user_id}"
        attempts = await cache_service.get(key) or 0
        
        await cache_service.set(key, attempts + 1, expire=3600)
        
        if attempts >= 5:
            logger.warning(f"Multiple failed MFA attempts for user {user_id}")
    
    async def _log_successful_mfa(self, user_id: str, method: str):
        """Log successful MFA verification"""
        # Clear failure counter
        key = f"mfa_failures:{user_id}"
        await cache_service.delete(key)
        
        # Log success
        logger.info(f"MFA verified for user {user_id} using {method}")
    
    async def get_user_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Get MFA status for a user"""
        try:
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise ValidationError("User not found")
            
            mfa_data = user.private_metadata or {}
            
            return {
                "enabled": mfa_data.get("mfa_enabled", False),
                "methods": mfa_data.get("mfa_methods", []),
                "backup_codes_count": len(mfa_data.get("mfa_backup_codes", [])),
                "setup_date": mfa_data.get("mfa_setup_date"),
                "has_totp": "totp" in mfa_data.get("mfa_methods", []),
                "has_email": "email" in mfa_data.get("mfa_methods", []),
                "has_sms": "sms" in mfa_data.get("mfa_methods", [])
            }
        
        except Exception as e:
            logger.error(f"Failed to get MFA status: {str(e)}")
            return {
                "enabled": False,
                "methods": [],
                "error": "Failed to retrieve MFA status"
            }


# Singleton instance
mfa_service = MFAService()