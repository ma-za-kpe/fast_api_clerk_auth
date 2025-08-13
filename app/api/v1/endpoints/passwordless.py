from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Body, HTTPException, BackgroundTasks, Request
from datetime import datetime, timedelta
import secrets
import hashlib
import base64
import structlog

from app.core.config import settings
from app.core.exceptions import ValidationError, NotFoundError, AuthenticationError
from app.services.email_service import EmailService
from app.services.cache_service import cache_service
from app.api.v1.deps import get_optional_current_user
from app.core.clerk import get_clerk_client
from app.tasks.email_tasks import send_magic_link_email, send_verification_email
from app.schemas.passwordless import (
    MagicLinkRequest,
    MagicLinkVerify,
    OTPRequest,
    OTPVerify,
    WebAuthnRegisterRequest,
    WebAuthnLoginRequest,
    DeviceTrustRequest
)

router = APIRouter()
logger = structlog.get_logger()


@router.post("/magic-link/send")
async def send_magic_link(
    request: MagicLinkRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    clerk_client = Depends(get_clerk_client)
):
    """
    Send a magic link for passwordless authentication with enhanced security
    """
    try:
        # Rate limiting check
        rate_limit_key = f"magic_link_rate:{request.email}"
        attempts = await cache_service.get(rate_limit_key) or 0
        
        if attempts >= 3:
            raise ValidationError("Too many magic link requests. Please wait before trying again.")
        
        # Check if user exists in Clerk
        user = await clerk_client.get_user_by_email(request.email)
        
        # Generate secure token with hash
        token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Get client information for security
        client_ip = req.client.host if req.client else "unknown"
        user_agent = req.headers.get("user-agent", "unknown")
        
        # Store token in cache with enhanced data
        cache_key = f"magic_link:{token_hash}"
        cache_data = {
            "email": request.email,
            "redirect_url": request.redirect_url,
            "created_at": datetime.utcnow().isoformat(),
            "ip_address": client_ip,
            "user_agent": user_agent,
            "user_exists": user is not None,
            "user_id": user.id if user else None,
            "expiry_time": (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        }
        
        # Set expiration based on configuration
        expiry_seconds = settings.MAGIC_LINK_EXPIRY if hasattr(settings, 'MAGIC_LINK_EXPIRY') else 900
        
        await cache_service.set(
            cache_key,
            cache_data,
            expire=expiry_seconds
        )
        
        # Update rate limiting
        await cache_service.set(rate_limit_key, attempts + 1, expire=300)
        
        # Generate magic link URL
        magic_link = f"{settings.FRONTEND_URL}/auth/magic-link?token={token}"
        if request.redirect_url:
            encoded_redirect = base64.urlsafe_b64encode(request.redirect_url.encode()).decode()
            magic_link += f"&redirect={encoded_redirect}"
        
        # Send email using background task
        background_tasks.add_task(
            send_magic_link_email.delay,
            request.email,
            magic_link
        )
        
        logger.info(
            "Magic link sent",
            email=request.email,
            user_exists=user is not None,
            ip=client_ip
        )
        
        return {
            "message": "If an account exists with this email, a magic link has been sent.",
            "expires_in": expiry_seconds,
            "sent_to": request.email[:3] + "*" * (len(request.email) - 6) + request.email[-3:]
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to send magic link", error=str(e))
        # Don't reveal if email exists
        return {
            "message": "If an account exists with this email, a magic link has been sent.",
            "expires_in": 900
        }


@router.post("/magic-link/verify")
async def verify_magic_link(
    request: MagicLinkVerify,
    req: Request,
    clerk_client = Depends(get_clerk_client)
):
    """
    Verify a magic link token and authenticate user with security checks
    """
    try:
        # Hash the token for lookup
        token_hash = hashlib.sha256(request.token.encode()).hexdigest()
        
        # Retrieve token from cache
        cache_key = f"magic_link:{token_hash}"
        cache_data = await cache_service.get(cache_key)
        
        if not cache_data:
            # Log failed attempt
            logger.warning(
                "Invalid magic link attempt",
                token_hash=token_hash[:8],
                ip=req.client.host if req.client else "unknown"
            )
            raise ValidationError("Invalid or expired magic link")
        
        # Check expiry time
        expiry_time = datetime.fromisoformat(cache_data.get("expiry_time"))
        if datetime.utcnow() > expiry_time:
            await cache_service.delete(cache_key)
            raise ValidationError("Magic link has expired")
        
        # Verify IP address if strict mode enabled
        if settings.MAGIC_LINK_STRICT_IP if hasattr(settings, 'MAGIC_LINK_STRICT_IP') else False:
            original_ip = cache_data.get("ip_address")
            current_ip = req.client.host if req.client else "unknown"
            if original_ip != current_ip:
                logger.warning(
                    "Magic link IP mismatch",
                    original_ip=original_ip,
                    current_ip=current_ip
                )
                raise ValidationError("Security validation failed. Please request a new magic link.")
        
        email = cache_data.get("email")
        user_id = cache_data.get("user_id")
        
        # Get or create user in Clerk
        if user_id:
            user = await clerk_client.get_user(user_id)
        else:
            user = await clerk_client.get_user_by_email(email)
        
        if not user:
            # Create user without password
            user = await clerk_client.create_user(
                email_address=email,
                password=None,
                public_metadata={"auth_method": "magic_link"},
                private_metadata={"first_login": datetime.utcnow().isoformat()}
            )
            
            # Mark email as verified
            await clerk_client.update_user(
                user_id=user.id,
                email_verified=True
            )
        
        # Create session in Clerk
        session_data = {
            "user_id": user.id,
            "auth_method": "magic_link",
            "ip_address": req.client.host if req.client else "unknown",
            "user_agent": req.headers.get("user-agent", "unknown")
        }
        
        # Store session data
        session_id = secrets.token_urlsafe(32)
        session_key = f"session:{session_id}"
        await cache_service.cache_user_session(
            session_id=session_id,
            user_id=user.id,
            data=session_data,
            expire=86400  # 24 hours
        )
        
        # Delete used token
        await cache_service.delete(cache_key)
        
        # Decode redirect URL if present
        redirect_url = cache_data.get("redirect_url")
        if redirect_url:
            try:
                redirect_url = base64.urlsafe_b64decode(redirect_url.encode()).decode()
            except:
                pass
        
        logger.info(
            "Magic link verified",
            email=email,
            user_id=user.id,
            new_user=user_id is None
        )
        
        return {
            "message": "Authentication successful",
            "user_id": user.id,
            "email": email,
            "session_id": session_id,
            "redirect_url": redirect_url,
            "is_new_user": user_id is None
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to verify magic link", error=str(e))
        raise ValidationError("Failed to verify magic link")


@router.post("/otp/send")
async def send_otp(
    request: OTPRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    clerk_client = Depends(get_clerk_client)
):
    """
    Send a one-time password for authentication with enhanced security
    """
    try:
        # Rate limiting per identifier
        rate_key = f"otp_rate:{request.identifier}"
        rate_attempts = await cache_service.get(rate_key) or 0
        
        if rate_attempts >= settings.OTP_MAX_SEND_ATTEMPTS if hasattr(settings, 'OTP_MAX_SEND_ATTEMPTS') else 5:
            raise ValidationError("Too many OTP requests. Please wait before trying again.")
        
        # Check for existing valid OTP
        existing_key = f"otp_valid:{request.identifier}"
        existing_otp = await cache_service.get(existing_key)
        
        if existing_otp:
            # Check if we should resend or wait
            created_at = datetime.fromisoformat(existing_otp.get("created_at"))
            if (datetime.utcnow() - created_at).seconds < 60:
                raise ValidationError("Please wait 60 seconds before requesting a new OTP")
        
        # Generate OTP based on configuration
        otp_length = settings.OTP_LENGTH if hasattr(settings, 'OTP_LENGTH') else 6
        if otp_length == 6:
            otp_code = str(secrets.randbelow(900000) + 100000)
        elif otp_length == 8:
            otp_code = str(secrets.randbelow(90000000) + 10000000)
        else:
            otp_code = ''.join([str(secrets.randbelow(10)) for _ in range(otp_length)])
        
        # Hash OTP for storage (more secure)
        otp_hash = hashlib.sha256(f"{request.identifier}:{otp_code}".encode()).hexdigest()
        
        # Get client info for security
        client_ip = req.client.host if req.client else "unknown"
        user_agent = req.headers.get("user-agent", "unknown")
        
        # Store OTP with metadata
        cache_key = f"otp_valid:{request.identifier}"
        cache_data = {
            "otp_hash": otp_hash,
            "identifier": request.identifier,
            "type": request.type,
            "attempts": 0,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
            "ip_address": client_ip,
            "user_agent": user_agent,
            "purpose": request.purpose if hasattr(request, 'purpose') else "authentication"
        }
        
        # Set expiration
        expiry_seconds = settings.OTP_EXPIRY if hasattr(settings, 'OTP_EXPIRY') else 300
        
        await cache_service.set(
            cache_key,
            cache_data,
            expire=expiry_seconds
        )
        
        # Update rate limiting
        await cache_service.set(rate_key, rate_attempts + 1, expire=3600)
        
        # Send OTP based on type
        if request.type == "email":
            # Check if email exists in Clerk
            user = await clerk_client.get_user_by_email(request.identifier)
            
            # Send verification email
            background_tasks.add_task(
                send_verification_email.delay,
                request.identifier,
                otp_code
            )
            
            logger.info(
                "Email OTP sent",
                identifier=request.identifier,
                user_exists=user is not None
            )
            
        elif request.type == "sms":
            # Use the new SMS service
            from app.services.sms_service import sms_service
            
            # Send OTP via SMS
            sms_result = await sms_service.send_verification_code(
                to_phone=request.identifier,
                code=otp_code,
                purpose="verification"
            )
            
            if not sms_result.get("success"):
                # Still store the OTP for development/testing
                if settings.is_development:
                    logger.debug(f"Development OTP: {otp_code}")
                else:
                    raise ValidationError(sms_result.get("error", "Failed to send SMS"))
            
            logger.info(
                "SMS OTP sent",
                phone=request.identifier[:6] + "****",
                message_id=sms_result.get("message_id")
            )
        
        # Mask identifier for response
        masked_identifier = request.identifier
        if request.type == "email" and "@" in masked_identifier:
            parts = masked_identifier.split("@")
            masked_identifier = parts[0][:2] + "*" * (len(parts[0]) - 2) + "@" + parts[1]
        elif request.type == "sms":
            masked_identifier = masked_identifier[:3] + "*" * (len(masked_identifier) - 6) + masked_identifier[-3:]
        
        return {
            "message": f"OTP has been sent to {masked_identifier}",
            "type": request.type,
            "expires_in": expiry_seconds,
            "resend_available_in": 60,
            "otp_length": otp_length
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to send OTP", error=str(e))
        raise ValidationError("Failed to send OTP")


@router.post("/otp/verify")
async def verify_otp(
    request: OTPVerify,
    req: Request,
    clerk_client = Depends(get_clerk_client)
):
    """
    Verify a one-time password with security enhancements
    """
    try:
        # Check rate limiting for verification attempts
        attempt_key = f"otp_verify_attempts:{request.identifier}"
        attempts = await cache_service.get(attempt_key) or 0
        
        max_attempts = settings.OTP_MAX_VERIFY_ATTEMPTS if hasattr(settings, 'OTP_MAX_VERIFY_ATTEMPTS') else 5
        if attempts >= max_attempts:
            # Lock out for extended period
            await cache_service.set(attempt_key, attempts, expire=1800)  # 30 minutes
            raise ValidationError("Too many failed attempts. Account temporarily locked.")
        
        # Retrieve valid OTP data
        cache_key = f"otp_valid:{request.identifier}"
        cache_data = await cache_service.get(cache_key)
        
        if not cache_data:
            # Increment failed attempts
            await cache_service.set(attempt_key, attempts + 1, expire=300)
            logger.warning(
                "OTP verification failed - no valid OTP",
                identifier=request.identifier,
                attempts=attempts + 1
            )
            raise ValidationError("Invalid or expired OTP")
        
        # Check expiry
        expires_at = datetime.fromisoformat(cache_data.get("expires_at"))
        if datetime.utcnow() > expires_at:
            await cache_service.delete(cache_key)
            await cache_service.set(attempt_key, attempts + 1, expire=300)
            raise ValidationError("OTP has expired. Please request a new one.")
        
        # Verify OTP hash
        otp_hash = hashlib.sha256(f"{request.identifier}:{request.code}".encode()).hexdigest()
        stored_hash = cache_data.get("otp_hash")
        
        if otp_hash != stored_hash:
            # Increment failed attempts in cache data
            cache_data["attempts"] = cache_data.get("attempts", 0) + 1
            
            if cache_data["attempts"] >= 3:
                # Delete OTP after 3 failed attempts
                await cache_service.delete(cache_key)
                logger.warning(
                    "OTP deleted after max attempts",
                    identifier=request.identifier
                )
                raise ValidationError("Maximum verification attempts exceeded. Please request a new OTP.")
            
            # Update cache with incremented attempts
            await cache_service.set(cache_key, cache_data, expire=300)
            await cache_service.set(attempt_key, attempts + 1, expire=300)
            
            logger.warning(
                "Invalid OTP attempt",
                identifier=request.identifier,
                attempt=cache_data["attempts"]
            )
            raise ValidationError(f"Invalid OTP. {3 - cache_data['attempts']} attempts remaining.")
        
        # OTP is valid - get client info
        client_ip = req.client.host if req.client else "unknown"
        user_agent = req.headers.get("user-agent", "unknown")
        
        # Check IP if strict validation enabled
        if settings.OTP_STRICT_IP if hasattr(settings, 'OTP_STRICT_IP') else False:
            original_ip = cache_data.get("ip_address")
            if original_ip != client_ip:
                logger.warning(
                    "OTP IP mismatch",
                    original_ip=original_ip,
                    current_ip=client_ip
                )
                raise ValidationError("Security validation failed. Please request a new OTP.")
        
        # Get identifier details
        identifier = cache_data.get("identifier")
        id_type = cache_data.get("type")
        purpose = cache_data.get("purpose", "authentication")
        
        # Handle based on type
        user = None
        if id_type == "email":
            user = await clerk_client.get_user_by_email(identifier)
            if not user and purpose == "authentication":
                # Create new user for authentication
                user = await clerk_client.create_user(
                    email_address=identifier,
                    password=None,
                    public_metadata={"auth_method": "otp"},
                    private_metadata={"verified_via": "email_otp"}
                )
                # Mark email as verified
                await clerk_client.update_user(
                    user_id=user.id,
                    email_verified=True
                )
        elif id_type == "sms":
            # For SMS, you would look up user by phone
            # This requires Clerk phone number support or custom implementation
            logger.info("SMS OTP verified", phone=identifier)
            # In production:
            # user = await clerk_client.get_user_by_phone(identifier)
        
        # Delete used OTP
        await cache_service.delete(cache_key)
        await cache_service.delete(attempt_key)
        
        # Create session if for authentication
        session_id = None
        if purpose == "authentication" and user:
            session_id = secrets.token_urlsafe(32)
            await cache_service.cache_user_session(
                session_id=session_id,
                user_id=user.id,
                data={
                    "auth_method": "otp",
                    "identifier_type": id_type,
                    "ip_address": client_ip,
                    "user_agent": user_agent
                },
                expire=86400
            )
        
        logger.info(
            "OTP verified successfully",
            identifier=identifier,
            type=id_type,
            purpose=purpose,
            user_id=user.id if user else None
        )
        
        return {
            "message": "Verification successful",
            "verified": True,
            "identifier": identifier,
            "type": id_type,
            "purpose": purpose,
            "user_id": user.id if user else None,
            "session_id": session_id,
            "is_new_user": user and cache_data.get("user_exists") is False
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to verify OTP", error=str(e))
        raise ValidationError("Failed to verify OTP")


@router.post("/webauthn/register/begin")
async def begin_webauthn_registration(
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
):
    """
    Begin WebAuthn registration for biometric authentication
    """
    try:
        if not current_user:
            raise ValidationError("Authentication required")
        
        user_id = current_user.get("user_id")
        
        # Generate challenge
        challenge = secrets.token_bytes(32)
        
        # Store challenge in cache
        cache_key = f"webauthn_reg:{user_id}"
        await cache_service.set(
            cache_key,
            {
                "challenge": challenge.hex(),
                "user_id": user_id,
                "created_at": datetime.utcnow().isoformat()
            },
            expire=300
        )
        
        # Return registration options
        return {
            "challenge": challenge.hex(),
            "rp": {
                "name": "FastAPI Clerk Auth",
                "id": settings.FRONTEND_URL.replace("https://", "").replace("http://", "").split(":")[0]
            },
            "user": {
                "id": user_id,
                "name": current_user.get("email", "user"),
                "displayName": current_user.get("name", "User")
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "timeout": 60000,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": False,
                "userVerification": "preferred"
            }
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to begin WebAuthn registration", error=str(e))
        raise ValidationError("Failed to begin registration")


@router.post("/webauthn/register/complete")
async def complete_webauthn_registration(
    request: WebAuthnRegisterRequest,
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
):
    """
    Complete WebAuthn registration
    """
    try:
        if not current_user:
            raise ValidationError("Authentication required")
        
        user_id = current_user.get("user_id")
        
        # Retrieve challenge from cache
        cache_key = f"webauthn_reg:{user_id}"
        cache_data = await cache_service.get(cache_key)
        
        if not cache_data:
            raise ValidationError("Registration session expired")
        
        # In production, you would verify the attestation here
        # This requires a WebAuthn library like python-fido2
        
        # Store credential for user
        credential_key = f"webauthn_cred:{user_id}:{request.credential_id}"
        await cache_service.set(
            credential_key,
            {
                "credential_id": request.credential_id,
                "public_key": request.public_key,
                "created_at": datetime.utcnow().isoformat()
            }
        )
        
        # Clean up challenge
        await cache_service.delete(cache_key)
        
        logger.info("WebAuthn credential registered", user_id=user_id)
        
        return {
            "message": "Biometric authentication registered successfully",
            "credential_id": request.credential_id
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to complete WebAuthn registration", error=str(e))
        raise ValidationError("Failed to complete registration")


@router.post("/webauthn/login/begin")
async def begin_webauthn_login(
    email: Optional[str] = None,
):
    """
    Begin WebAuthn login
    """
    try:
        # Generate challenge
        challenge = secrets.token_bytes(32)
        
        # Store challenge in cache
        cache_key = f"webauthn_auth:{challenge.hex()[:16]}"
        await cache_service.set(
            cache_key,
            {
                "challenge": challenge.hex(),
                "email": email,
                "created_at": datetime.utcnow().isoformat()
            },
            expire=300
        )
        
        return {
            "challenge": challenge.hex(),
            "timeout": 60000,
            "rpId": settings.FRONTEND_URL.replace("https://", "").replace("http://", "").split(":")[0],
            "userVerification": "preferred"
        }
    
    except Exception as e:
        logger.error("Failed to begin WebAuthn login", error=str(e))
        raise ValidationError("Failed to begin login")


@router.post("/webauthn/login/complete")
async def complete_webauthn_login(
    request: WebAuthnLoginRequest,
    cache_service = Depends(lambda: cache_service),
    clerk_client = Depends(get_clerk_client)
):
    """
    Complete WebAuthn login
    """
    try:
        # In production, verify the assertion signature
        # This requires a WebAuthn library
        
        logger.info("WebAuthn login completed")
        
        return {
            "message": "Biometric authentication successful",
            "authenticated": True
        }
    
    except Exception as e:
        logger.error("Failed to complete WebAuthn login", error=str(e))
        raise ValidationError("Failed to complete login")


@router.post("/device/trust")
async def trust_device(
    request: DeviceTrustRequest,
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
):
    """
    Mark a device as trusted for future logins
    """
    try:
        if not current_user:
            raise ValidationError("Authentication required")
        
        user_id = current_user.get("user_id")
        
        # Generate device token
        device_token = secrets.token_urlsafe(32)
        
        # Create device fingerprint
        fingerprint = f"{request.user_agent}:{request.platform}:{request.screen_resolution}"
        
        # Store trusted device
        cache_key = f"trusted_device:{user_id}:{device_token}"
        await cache_service.set(
            cache_key,
            {
                "user_id": user_id,
                "device_name": request.device_name,
                "fingerprint": fingerprint,
                "ip_address": request.ip_address,
                "trusted_at": datetime.utcnow().isoformat(),
                "last_used": datetime.utcnow().isoformat()
            },
            expire=2592000  # 30 days
        )
        
        logger.info("Device trusted", user_id=user_id, device_name=request.device_name)
        
        return {
            "message": "Device trusted successfully",
            "device_token": device_token,
            "expires_in": 2592000
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to trust device", error=str(e))
        raise ValidationError("Failed to trust device")


@router.get("/device/list")
async def list_trusted_devices(
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
):
    """
    List all trusted devices for the current user
    """
    try:
        if not current_user:
            raise ValidationError("Authentication required")
        
        user_id = current_user.get("user_id")
        
        # Get all trusted devices from cache
        pattern = f"trusted_device:{user_id}:*"
        devices = await cache_service.get_pattern(pattern)
        
        device_list = []
        for key, data in devices.items():
            device_token = key.split(":")[-1]
            device_list.append({
                "device_token": device_token,
                "device_name": data.get("device_name"),
                "trusted_at": data.get("trusted_at"),
                "last_used": data.get("last_used"),
                "ip_address": data.get("ip_address")
            })
        
        return {
            "devices": device_list,
            "total": len(device_list)
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to list trusted devices", error=str(e))
        raise ValidationError("Failed to list devices")


@router.delete("/device/{device_token}")
async def revoke_device_trust(
    device_token: str,
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
):
    """
    Revoke trust for a specific device
    """
    try:
        if not current_user:
            raise ValidationError("Authentication required")
        
        user_id = current_user.get("user_id")
        
        # Delete trusted device
        cache_key = f"trusted_device:{user_id}:{device_token}"
        deleted = await cache_service.delete(cache_key)
        
        if not deleted:
            raise NotFoundError("Device not found")
        
        logger.info("Device trust revoked", user_id=user_id, device_token=device_token)
        
        return {"message": "Device trust revoked successfully"}
    
    except (ValidationError, NotFoundError):
        raise
    except Exception as e:
        logger.error("Failed to revoke device trust", error=str(e))
        raise ValidationError("Failed to revoke device trust")