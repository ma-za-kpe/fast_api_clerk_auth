from typing import Dict, Any, Optional, List
import structlog
from datetime import datetime, timedelta
import httpx
import hashlib
import hmac
from app.core.config import settings
from app.services.cache_service import cache_service

logger = structlog.get_logger()


class SMSService:
    """
    SMS service for sending text messages via Twilio or other providers
    """
    
    def __init__(self):
        # Twilio configuration
        self.twilio_account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
        self.twilio_auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
        self.twilio_phone_number = getattr(settings, 'TWILIO_PHONE_NUMBER', None)
        self.twilio_messaging_service_sid = getattr(settings, 'TWILIO_MESSAGING_SERVICE_SID', None)
        
        # Alternative SMS providers can be configured here
        self.provider = getattr(settings, 'SMS_PROVIDER', 'twilio')
        
        # Rate limiting configuration
        self.max_sms_per_phone_per_day = getattr(settings, 'MAX_SMS_PER_PHONE_PER_DAY', 10)
        self.max_sms_per_phone_per_hour = getattr(settings, 'MAX_SMS_PER_PHONE_PER_HOUR', 5)
    
    async def send_sms(
        self,
        to_phone: str,
        message: str,
        priority: str = "normal",
        reference_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send an SMS message
        """
        try:
            # Check rate limits
            if not await self._check_rate_limit(to_phone):
                logger.warning(f"SMS rate limit exceeded for {to_phone}")
                return {
                    "success": False,
                    "error": "Rate limit exceeded. Please try again later.",
                    "rate_limited": True
                }
            
            # Validate phone number format
            if not self._validate_phone_number(to_phone):
                return {
                    "success": False,
                    "error": "Invalid phone number format"
                }
            
            # Send based on provider
            if self.provider == "twilio":
                result = await self._send_via_twilio(to_phone, message, priority)
            elif self.provider == "sns":
                result = await self._send_via_aws_sns(to_phone, message)
            elif self.provider == "development":
                result = await self._send_development_sms(to_phone, message)
            else:
                raise ValueError(f"Unsupported SMS provider: {self.provider}")
            
            # Log the SMS send
            await self._log_sms_send(to_phone, message, result, reference_id)
            
            # Update rate limit counters
            await self._update_rate_limit(to_phone)
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to send SMS: {str(e)}")
            return {
                "success": False,
                "error": "Failed to send SMS",
                "details": str(e)
            }
    
    async def send_verification_code(
        self,
        to_phone: str,
        code: str,
        purpose: str = "verification"
    ) -> Dict[str, Any]:
        """
        Send a verification code via SMS
        """
        message = f"Your verification code is: {code}\n\nThis code expires in 5 minutes.\n\nIf you didn't request this, please ignore this message."
        
        if purpose == "mfa":
            message = f"Your authentication code is: {code}\n\nThis code expires in 5 minutes.\n\nNever share this code with anyone."
        elif purpose == "password_reset":
            message = f"Your password reset code is: {code}\n\nThis code expires in 15 minutes.\n\nIf you didn't request this, please secure your account."
        
        return await self.send_sms(
            to_phone=to_phone,
            message=message,
            priority="high",
            reference_id=f"{purpose}:{code[:4]}"
        )
    
    async def _send_via_twilio(
        self,
        to_phone: str,
        message: str,
        priority: str = "normal"
    ) -> Dict[str, Any]:
        """
        Send SMS via Twilio API
        """
        if not all([self.twilio_account_sid, self.twilio_auth_token]):
            logger.error("Twilio credentials not configured")
            return {
                "success": False,
                "error": "SMS service not configured"
            }
        
        try:
            # Twilio API endpoint
            url = f"https://api.twilio.com/2010-04-01/Accounts/{self.twilio_account_sid}/Messages.json"
            
            # Prepare the request
            auth = (self.twilio_account_sid, self.twilio_auth_token)
            
            data = {
                "Body": message,
                "To": to_phone
            }
            
            # Use messaging service SID if configured, otherwise use phone number
            if self.twilio_messaging_service_sid:
                data["MessagingServiceSid"] = self.twilio_messaging_service_sid
            else:
                data["From"] = self.twilio_phone_number
            
            # Add priority for time-sensitive messages
            if priority == "high":
                data["Priority"] = "high"
                data["Attempt"] = "1"
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    auth=auth,
                    data=data,
                    timeout=30.0
                )
                
                if response.status_code in [200, 201]:
                    result = response.json()
                    logger.info(f"SMS sent via Twilio", sid=result.get("sid"), to=to_phone[:6] + "****")
                    return {
                        "success": True,
                        "message_id": result.get("sid"),
                        "status": result.get("status"),
                        "provider": "twilio"
                    }
                else:
                    error_data = response.json()
                    logger.error(f"Twilio API error: {error_data}")
                    return {
                        "success": False,
                        "error": error_data.get("message", "Failed to send SMS"),
                        "code": error_data.get("code")
                    }
        
        except Exception as e:
            logger.error(f"Twilio send failed: {str(e)}")
            return {
                "success": False,
                "error": "SMS service error",
                "details": str(e)
            }
    
    async def _send_via_aws_sns(
        self,
        to_phone: str,
        message: str
    ) -> Dict[str, Any]:
        """
        Send SMS via AWS SNS
        """
        # This would require boto3 and AWS configuration
        logger.info(f"AWS SNS SMS send (not implemented): {to_phone[:6]}****")
        return {
            "success": False,
            "error": "AWS SNS provider not implemented"
        }
    
    async def _send_development_sms(
        self,
        to_phone: str,
        message: str
    ) -> Dict[str, Any]:
        """
        Development mode - log SMS instead of sending
        """
        logger.info(
            f"[DEVELOPMENT SMS]",
            to=to_phone,
            message=message
        )
        
        # Store in cache for testing
        dev_sms_key = f"dev_sms:{to_phone}:{datetime.utcnow().timestamp()}"
        await cache_service.set(
            dev_sms_key,
            {
                "to": to_phone,
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            },
            expire=3600
        )
        
        return {
            "success": True,
            "message_id": f"dev_{datetime.utcnow().timestamp()}",
            "status": "development",
            "provider": "development",
            "message": "[Development Mode] SMS logged but not sent"
        }
    
    def _validate_phone_number(self, phone: str) -> bool:
        """
        Validate phone number format
        """
        # Remove common formatting characters
        cleaned = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        
        # Check if it starts with + and contains only digits
        if not cleaned.startswith("+"):
            return False
        
        # Check if the rest are digits and length is reasonable
        digits = cleaned[1:]
        if not digits.isdigit():
            return False
        
        # International phone numbers are typically 7-15 digits
        if len(digits) < 7 or len(digits) > 15:
            return False
        
        return True
    
    async def _check_rate_limit(self, phone: str) -> bool:
        """
        Check if phone number has exceeded rate limits
        """
        # Hourly limit check
        hourly_key = f"sms_rate:hourly:{phone}"
        hourly_count = await cache_service.get(hourly_key) or 0
        
        if hourly_count >= self.max_sms_per_phone_per_hour:
            return False
        
        # Daily limit check
        daily_key = f"sms_rate:daily:{phone}"
        daily_count = await cache_service.get(daily_key) or 0
        
        if daily_count >= self.max_sms_per_phone_per_day:
            return False
        
        return True
    
    async def _update_rate_limit(self, phone: str):
        """
        Update rate limit counters for a phone number
        """
        # Update hourly counter
        hourly_key = f"sms_rate:hourly:{phone}"
        hourly_count = await cache_service.get(hourly_key) or 0
        await cache_service.set(hourly_key, hourly_count + 1, expire=3600)
        
        # Update daily counter
        daily_key = f"sms_rate:daily:{phone}"
        daily_count = await cache_service.get(daily_key) or 0
        await cache_service.set(daily_key, daily_count + 1, expire=86400)
    
    async def _log_sms_send(
        self,
        phone: str,
        message: str,
        result: Dict[str, Any],
        reference_id: Optional[str] = None
    ):
        """
        Log SMS send attempt for auditing
        """
        log_key = f"sms_log:{datetime.utcnow().strftime('%Y%m%d')}:{phone}"
        log_entry = {
            "phone": phone[:6] + "****",  # Mask phone number
            "message_length": len(message),
            "success": result.get("success"),
            "provider": result.get("provider"),
            "message_id": result.get("message_id"),
            "reference_id": reference_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Store in a list for the day
        await cache_service.push_to_list(log_key, log_entry)
        await cache_service.expire(log_key, 86400 * 7)  # Keep logs for 7 days
    
    async def get_sms_status(self, message_id: str) -> Dict[str, Any]:
        """
        Get the delivery status of an SMS (if supported by provider)
        """
        if self.provider == "twilio":
            return await self._get_twilio_status(message_id)
        else:
            return {
                "success": False,
                "error": "Status checking not supported for this provider"
            }
    
    async def _get_twilio_status(self, message_sid: str) -> Dict[str, Any]:
        """
        Get SMS status from Twilio
        """
        if not all([self.twilio_account_sid, self.twilio_auth_token]):
            return {
                "success": False,
                "error": "Twilio not configured"
            }
        
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{self.twilio_account_sid}/Messages/{message_sid}.json"
            auth = (self.twilio_account_sid, self.twilio_auth_token)
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url, auth=auth, timeout=10.0)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "success": True,
                        "status": data.get("status"),
                        "date_sent": data.get("date_sent"),
                        "date_updated": data.get("date_updated"),
                        "error_code": data.get("error_code"),
                        "error_message": data.get("error_message")
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to get message status"
                    }
        
        except Exception as e:
            logger.error(f"Failed to get Twilio status: {str(e)}")
            return {
                "success": False,
                "error": "Failed to retrieve status"
            }
    
    async def validate_phone_ownership(
        self,
        phone: str,
        code: str
    ) -> bool:
        """
        Validate that a user owns a phone number via verification code
        """
        # Check verification code in cache
        verify_key = f"phone_verify:{phone}"
        stored_data = await cache_service.get(verify_key)
        
        if not stored_data:
            return False
        
        stored_code = stored_data.get("code")
        attempts = stored_data.get("attempts", 0)
        
        # Check max attempts
        if attempts >= 3:
            await cache_service.delete(verify_key)
            return False
        
        if stored_code == code:
            await cache_service.delete(verify_key)
            return True
        else:
            # Increment attempts
            stored_data["attempts"] = attempts + 1
            await cache_service.set(verify_key, stored_data, expire=300)
            return False
    
    async def send_phone_verification(self, phone: str) -> Dict[str, Any]:
        """
        Send a phone verification code
        """
        import secrets
        
        # Generate 6-digit code
        code = str(secrets.randbelow(900000) + 100000)
        
        # Store in cache
        verify_key = f"phone_verify:{phone}"
        await cache_service.set(
            verify_key,
            {
                "code": code,
                "attempts": 0,
                "created_at": datetime.utcnow().isoformat()
            },
            expire=300  # 5 minutes
        )
        
        # Send SMS
        result = await self.send_verification_code(phone, code, "verification")
        
        if result.get("success"):
            return {
                "success": True,
                "message": "Verification code sent",
                "expires_in": 300
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "Failed to send verification code")
            }


# Create global SMS service instance
sms_service = SMSService()