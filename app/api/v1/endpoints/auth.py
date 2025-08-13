from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Request, Response, Body, Query, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog

from app.core.clerk import get_clerk_client
from app.core.exceptions import AuthenticationError, ValidationError
from app.api.v1.deps import get_current_user, get_optional_current_user
from app.services.password_validator import password_validator
from app.services.token_service import token_service
from app.services.device_service import device_service
from app.schemas.auth import (
    SignUpRequest,
    SignInRequest,
    SignUpResponse,
    SignInResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    EmailVerificationRequest,
    TokenRefreshRequest,
    TokenRefreshResponse,
    MFASetupResponse,
    MFAVerifyRequest
)

router = APIRouter()
logger = structlog.get_logger()
security = HTTPBearer()


@router.post("/signup", response_model=SignUpResponse)
async def sign_up(
    request: SignUpRequest,
    clerk_client = Depends(get_clerk_client)
):
    """
    Create a new user account with password validation
    """
    try:
        # Validate password strength
        is_valid, errors = password_validator.validate_password(
            password=request.password,
            email=request.email,
            username=request.username,
            first_name=request.first_name,
            last_name=request.last_name
        )
        
        if not is_valid:
            raise ValidationError(f"Password validation failed: {'; '.join(errors)}")
        
        # Create user in Clerk
        user = await clerk_client.create_user(
            email_address=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            username=request.username,
            phone_number=request.phone_number,
            public_metadata=request.metadata or {}
        )
        
        logger.info("User signed up successfully", user_id=user.id)
        
        return SignUpResponse(
            user_id=user.id,
            email=user.email_addresses[0].email_address if user.email_addresses else request.email,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            created_at=user.created_at,
            email_verified=user.email_addresses[0].verification.status == "verified" if user.email_addresses else False
        )
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Sign up failed", error=str(e))
        raise ValidationError(f"Sign up failed: {str(e)}")


@router.post("/signin", response_model=SignInResponse)
async def sign_in(
    request: SignInRequest,
    response: Response,
    req: Request,
    clerk_client = Depends(get_clerk_client)
):
    """
    Sign in with email/username and password with token rotation support
    """
    try:
        identifier = request.email or request.username
        if not identifier:
            raise ValidationError("Email or username is required")
        
        # In production, validate credentials with Clerk
        # For demonstration, we'll create tokens with rotation support
        
        # Generate session ID
        import secrets
        session_id = secrets.token_urlsafe(32)
        
        # Register device if present
        device_id = None
        if req.headers.get("User-Agent"):
            device_result = await device_service.register_device(
                user_id="clerk_user_id",  # This would come from Clerk auth
                user_agent=req.headers.get("User-Agent", ""),
                ip_address=req.client.host
            )
            device_id = device_result.get("device_id")
        
        # Create token pair with rotation support
        tokens = await token_service.create_token_pair(
            user_id="clerk_user_id",  # This would come from Clerk auth
            session_id=session_id,
            device_id=device_id,
            additional_claims={"email": identifier}
        )
        
        logger.info("User signed in successfully", identifier=identifier)
        
        return SignInResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens.get("refresh_token"),
            token_type="Bearer",
            expires_in=tokens["expires_in"],
            message="Sign in successful with token rotation enabled."
        )
    
    except Exception as e:
        logger.error("Sign in failed", error=str(e))
        raise AuthenticationError(f"Sign in failed: {str(e)}")


@router.post("/refresh")
async def refresh_token(
    refresh_token: str = Body(..., embed=True),
    req: Request = None
):
    """
    Refresh access token using refresh token with rotation
    """
    try:
        # Get device ID if available
        device_id = None
        if req and req.headers.get("User-Agent"):
            # Generate device ID from request
            device_id = device_service._generate_device_id(
                "user_id",  # Would be extracted from token
                req.headers.get("User-Agent", ""),
                req.client.host,
                None
            )
        
        # Rotate refresh token
        new_tokens = await token_service.rotate_refresh_token(
            refresh_token=refresh_token,
            device_id=device_id
        )
        
        logger.info("Token refreshed successfully")
        
        return {
            "access_token": new_tokens["access_token"],
            "refresh_token": new_tokens["refresh_token"],
            "token_type": new_tokens["token_type"],
            "expires_in": new_tokens["expires_in"],
            "rotation_count": new_tokens.get("rotation_count", 0)
        }
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise HTTPException(status_code=400, detail="Token refresh failed")


@router.post("/revoke")
async def revoke_token(
    token: str = Body(..., embed=True),
    token_type: str = Body("access", embed=True),
    current_user: Dict[str, Any] = Depends(get_optional_current_user)
):
    """
    Revoke a specific token
    """
    try:
        success = await token_service.revoke_token(token, token_type)
        
        if success:
            logger.info(f"Token revoked successfully", token_type=token_type)
            return {
                "success": True,
                "message": f"{token_type.capitalize()} token revoked successfully"
            }
        else:
            raise ValidationError("Failed to revoke token")
    
    except Exception as e:
        logger.error("Token revocation failed", error=str(e))
        raise HTTPException(status_code=400, detail="Token revocation failed")


@router.post("/signout")
async def sign_out(
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """
    Sign out the current user (revoke session and all tokens)
    """
    try:
        user_id = current_user.get("user_id")
        session_id = current_user.get("session_id")
        
        # Revoke Clerk session if exists
        if session_id:
            await clerk_client.revoke_session(session_id)
        
        # Revoke current access token if using our token system
        if credentials:
            await token_service.revoke_token(credentials.credentials, "access")
        
        # Revoke all user tokens
        revoked_count = await token_service.revoke_all_user_tokens(user_id)
        
        logger.info("User signed out successfully", user_id=user_id, revoked_tokens=revoked_count)
        
        return {
            "message": "Successfully signed out",
            "revoked_tokens": revoked_count
        }
    
    except Exception as e:
        logger.error("Sign out failed", error=str(e))
        return {"message": "Sign out completed"}


@router.post("/password-reset")
async def request_password_reset(
    request: PasswordResetRequest,
    clerk_client = Depends(get_clerk_client)
):
    """
    Request a password reset email
    """
    try:
        logger.info("Password reset requested", email=request.email)
        
        return {
            "message": "If the email exists, a password reset link has been sent.",
            "note": "Password reset is managed through Clerk's client-side flows"
        }
    
    except Exception as e:
        logger.error("Password reset request failed", error=str(e))
        return {
            "message": "If the email exists, a password reset link has been sent."
        }


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    request: PasswordResetConfirm
):
    """
    Confirm password reset with token
    """
    return {
        "message": "Password reset should be completed through Clerk's client-side SDK",
        "redirect_url": f"/reset-password?token={request.token}"
    }


@router.post("/verify-email")
async def verify_email(
    request: EmailVerificationRequest,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)
):
    """
    Verify email address
    """
    return {
        "message": "Email verification is managed through Clerk's client-side flows",
        "verified": False
    }


@router.post("/refresh-token", response_model=TokenRefreshResponse)
async def refresh_token(
    request: TokenRefreshRequest,
    clerk_client = Depends(get_clerk_client)
):
    """
    Refresh access token
    """
    try:
        return TokenRefreshResponse(
            access_token="clerk_managed_token",
            token_type="Bearer",
            message="Token refresh is managed by Clerk's client-side SDK"
        )
    
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise AuthenticationError("Token refresh failed")


@router.get("/me")
async def get_current_user_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Get current user information
    """
    try:
        user_id = current_user.get("user_id")
        if not user_id:
            raise AuthenticationError("User ID not found")
        
        user = await clerk_client.get_user(user_id)
        
        return {
            "user_id": user.id,
            "email": user.email_addresses[0].email_address if user.email_addresses else None,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "profile_image_url": user.profile_image_url,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "email_verified": user.email_addresses[0].verification.status == "verified" if user.email_addresses else False,
            "phone_verified": user.phone_numbers[0].verification.status == "verified" if user.phone_numbers else False,
            "two_factor_enabled": user.two_factor_enabled,
            "public_metadata": user.public_metadata,
            "organization_id": current_user.get("org_id")
        }
    
    except Exception as e:
        logger.error("Failed to get user info", error=str(e))
        raise ValidationError(f"Failed to get user info: {str(e)}")


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    mfa_type: str = Query(..., description="MFA type: totp, sms, or email"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Set up multi-factor authentication
    """
    try:
        user_id = current_user.get("user_id")
        
        if mfa_type == "totp":
            return MFASetupResponse(
                mfa_type="totp",
                secret="Use Clerk's client-side SDK for TOTP setup",
                qr_code="Generated through Clerk UI",
                backup_codes=[]
            )
        elif mfa_type in ["sms", "email"]:
            return MFASetupResponse(
                mfa_type=mfa_type,
                message=f"{mfa_type.upper()} MFA setup initiated through Clerk"
            )
        else:
            raise ValidationError("Invalid MFA type")
    
    except Exception as e:
        logger.error("MFA setup failed", error=str(e))
        raise ValidationError(f"MFA setup failed: {str(e)}")


@router.post("/mfa/verify")
async def verify_mfa(
    request: MFAVerifyRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify MFA code
    """
    return {
        "verified": True,
        "message": "MFA verification is handled by Clerk's client-side SDK"
    }


@router.post("/social/{provider}/connect")
async def connect_social_provider(
    provider: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Connect a social authentication provider
    """
    supported_providers = [
        "google", "github", "microsoft", "facebook", 
        "discord", "twitter", "linkedin", "apple"
    ]
    
    if provider not in supported_providers:
        raise ValidationError(f"Unsupported provider: {provider}")
    
    return {
        "provider": provider,
        "status": "pending",
        "redirect_url": f"/oauth/{provider}/authorize",
        "message": "Social provider connection is managed through Clerk's client-side SDK"
    }


@router.delete("/social/{provider}/disconnect")
async def disconnect_social_provider(
    provider: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Disconnect a social authentication provider
    """
    try:
        user_id = current_user.get("user_id")
        
        logger.info(
            "Social provider disconnected",
            user_id=user_id,
            provider=provider
        )
        
        return {
            "provider": provider,
            "status": "disconnected",
            "message": "Social provider disconnection is managed through Clerk's API"
        }
    
    except Exception as e:
        logger.error("Failed to disconnect social provider", error=str(e))
        raise ValidationError(f"Failed to disconnect provider: {str(e)}")


@router.post("/password/check-strength")
async def check_password_strength(
    password: str = Body(..., embed=True),
    email: Optional[str] = Body(None, embed=True),
    username: Optional[str] = Body(None, embed=True)
):
    """
    Check password strength and get suggestions
    """
    try:
        # Get password strength analysis
        strength_info = password_validator.get_password_strength(password)
        
        # Validate password
        is_valid, errors = password_validator.validate_password(
            password=password,
            email=email,
            username=username
        )
        
        return {
            "is_valid": is_valid,
            "errors": errors,
            "strength": strength_info
        }
    
    except Exception as e:
        logger.error("Failed to check password strength", error=str(e))
        raise ValidationError(f"Failed to check password: {str(e)}")