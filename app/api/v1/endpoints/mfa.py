from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Body, HTTPException
from datetime import datetime
import structlog

from app.core.exceptions import AuthenticationError, ValidationError
from app.api.v1.deps import get_current_user
from app.services.mfa_service import mfa_service
from app.schemas.auth import MFASetupRequest, MFAVerifyRequest

router = APIRouter()
logger = structlog.get_logger()


@router.get("/status")
async def get_mfa_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get MFA status for the current user
    """
    try:
        user_id = current_user.get("user_id")
        status = await mfa_service.get_user_mfa_status(user_id)
        
        return {
            "user_id": user_id,
            **status
        }
    
    except Exception as e:
        logger.error(f"Failed to get MFA status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve MFA status")


@router.post("/totp/setup")
async def setup_totp(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Set up TOTP (authenticator app) for the current user
    """
    try:
        user_id = current_user.get("user_id")
        user_email = current_user.get("email", "user@example.com")
        
        # Check if MFA is already enabled
        status = await mfa_service.get_user_mfa_status(user_id)
        if status.get("has_totp"):
            raise ValidationError("TOTP is already enabled for this account")
        
        # Set up TOTP
        setup_data = await mfa_service.setup_totp(user_id, user_email)
        
        return {
            "status": "setup_required",
            "qr_code": f"data:image/png;base64,{setup_data['qr_code']}",
            "secret": setup_data["secret"],
            "manual_entry_key": setup_data["manual_entry_key"],
            "backup_codes": setup_data["backup_codes"],
            "issuer": setup_data["issuer"],
            "message": "Scan the QR code with your authenticator app and verify with a code"
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Failed to setup TOTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to setup authenticator")


@router.post("/totp/verify-setup")
async def verify_totp_setup(
    code: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify TOTP setup with a code to complete activation
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify and activate TOTP
        result = await mfa_service.verify_totp_setup(user_id, code)
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify TOTP setup: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify setup")


@router.post("/totp/verify")
async def verify_totp(
    code: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify a TOTP code for authentication
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify TOTP code
        result = await mfa_service.verify_totp(user_id, code)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify TOTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify code")


@router.post("/totp/disable")
async def disable_totp(
    code: str = Body(..., embed=True, description="Current TOTP code required for security"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Disable TOTP for the current user
    """
    try:
        user_id = current_user.get("user_id")
        
        # Disable TOTP
        result = await mfa_service.disable_totp(user_id, code)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to disable TOTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disable authenticator")


@router.post("/backup-codes/regenerate")
async def regenerate_backup_codes(
    code: str = Body(..., embed=True, description="Current TOTP code required"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Regenerate backup codes
    """
    try:
        user_id = current_user.get("user_id")
        
        # Regenerate backup codes
        result = await mfa_service.regenerate_backup_codes(user_id, code)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to regenerate backup codes: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to regenerate codes")


@router.post("/email/setup")
async def setup_email_mfa(
    email: Optional[str] = Body(None, embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Set up email-based MFA
    """
    try:
        user_id = current_user.get("user_id")
        
        # Use provided email or user's primary email
        if not email:
            email = current_user.get("email")
        
        if not email:
            raise ValidationError("Email address is required")
        
        # Check if email MFA is already enabled
        status = await mfa_service.get_user_mfa_status(user_id)
        if status.get("has_email"):
            raise ValidationError("Email MFA is already enabled for this account")
        
        # Set up email MFA
        result = await mfa_service.setup_email_mfa(user_id, email)
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to setup email MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to setup email authentication")


@router.post("/email/verify-setup")
async def verify_email_mfa_setup(
    code: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify email MFA setup
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify email MFA setup
        result = await mfa_service.verify_email_mfa(user_id, code, setup=True)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify email MFA setup: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify setup")


@router.post("/email/send-code")
async def send_email_mfa_code(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Send MFA code via email
    """
    try:
        user_id = current_user.get("user_id")
        
        # Send email MFA code
        result = await mfa_service.send_email_mfa_code(user_id)
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to send email MFA code: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send code")


@router.post("/email/verify")
async def verify_email_mfa(
    code: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify email MFA code
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify email MFA code
        result = await mfa_service.verify_email_mfa(user_id, code, setup=False)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify email MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify code")


@router.post("/sms/setup")
async def setup_sms_mfa(
    phone_number: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Set up SMS-based MFA
    """
    try:
        user_id = current_user.get("user_id")
        
        # Check if SMS MFA is already enabled
        status = await mfa_service.get_user_mfa_status(user_id)
        if status.get("has_sms"):
            raise ValidationError("SMS MFA is already enabled for this account")
        
        # Set up SMS MFA
        result = await mfa_service.setup_sms_mfa(user_id, phone_number)
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to setup SMS MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to setup SMS authentication")


@router.post("/sms/verify-setup")
async def verify_sms_mfa_setup(
    code: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify SMS MFA setup
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify SMS MFA setup
        result = await mfa_service.verify_sms_mfa(user_id, code, setup=True)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify SMS MFA setup: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify setup")


@router.post("/sms/send-code")
async def send_sms_mfa_code(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Send MFA code via SMS
    """
    try:
        user_id = current_user.get("user_id")
        
        # Send SMS MFA code
        result = await mfa_service.send_sms_mfa_code(user_id)
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to send SMS MFA code: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send code")


@router.post("/sms/verify")
async def verify_sms_mfa(
    code: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify SMS MFA code
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify SMS MFA code
        result = await mfa_service.verify_sms_mfa(user_id, code, setup=False)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify SMS MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify code")


@router.post("/sms/disable")
async def disable_sms_mfa(
    code: str = Body(..., embed=True, description="Current SMS code required for security"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Disable SMS MFA for the current user
    """
    try:
        user_id = current_user.get("user_id")
        
        # Disable SMS MFA
        result = await mfa_service.disable_sms_mfa(user_id, code)
        
        return result
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to disable SMS MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disable SMS authentication")


@router.post("/verify")
async def verify_mfa_unified(
    request: MFAVerifyRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Unified MFA verification endpoint (supports all methods)
    """
    try:
        user_id = current_user.get("user_id")
        
        if request.method == "totp":
            result = await mfa_service.verify_totp(user_id, request.code)
        elif request.method == "email":
            result = await mfa_service.verify_email_mfa(user_id, request.code, setup=False)
        elif request.method == "sms":
            result = await mfa_service.verify_sms_mfa(user_id, request.code, setup=False)
        else:
            raise ValidationError(f"Unsupported MFA method: {request.method}")
        
        return {
            **result,
            "user_id": user_id,
            "session_valid": True
        }
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify authentication")


@router.get("/methods")
async def get_available_mfa_methods():
    """
    Get available MFA methods
    """
    return {
        "methods": [
            {
                "type": "totp",
                "name": "Authenticator App",
                "description": "Use an authenticator app like Google Authenticator or Authy",
                "enabled": True
            },
            {
                "type": "email",
                "name": "Email",
                "description": "Receive codes via email",
                "enabled": True
            },
            {
                "type": "sms",
                "name": "SMS",
                "description": "Receive codes via text message",
                "enabled": True,
                "message": "SMS codes sent to your mobile phone"
            },
            {
                "type": "backup_codes",
                "name": "Backup Codes",
                "description": "Use one-time backup codes",
                "enabled": True
            }
        ]
    }


@router.get("/dashboard")
async def get_mfa_dashboard(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get comprehensive MFA dashboard information
    """
    try:
        user_id = current_user.get("user_id")
        
        # Get MFA status
        status = await mfa_service.get_user_mfa_status(user_id)
        
        # Get available methods
        methods_info = await get_available_mfa_methods()
        
        # Additional dashboard data
        dashboard_data = {
            "user_id": user_id,
            "mfa_status": status,
            "available_methods": methods_info["methods"],
            "security_recommendations": [],
            "recent_activity": {
                "last_mfa_setup": status.get("setup_date"),
                "active_methods": status.get("methods", []),
                "backup_codes_remaining": status.get("backup_codes_count", 0)
            }
        }
        
        # Add security recommendations
        if not status.get("enabled"):
            dashboard_data["security_recommendations"].append({
                "type": "warning",
                "message": "Enable multi-factor authentication to secure your account",
                "action": "setup_mfa"
            })
        elif len(status.get("methods", [])) == 1:
            dashboard_data["security_recommendations"].append({
                "type": "info",
                "message": "Consider adding a backup MFA method for account recovery",
                "action": "add_backup_method"
            })
        
        if status.get("backup_codes_count", 0) < 3:
            dashboard_data["security_recommendations"].append({
                "type": "warning",
                "message": "Generate new backup codes - you have fewer than 3 remaining",
                "action": "regenerate_backup_codes"
            })
        
        return dashboard_data
    
    except Exception as e:
        logger.error(f"Failed to get MFA dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load MFA dashboard")


@router.post("/disable-all")
async def disable_all_mfa_methods(
    verification_code: str = Body(..., embed=True, description="TOTP, SMS, or Email code required"),
    method: str = Body(..., embed=True, description="Method type for verification (totp/sms/email)"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Disable all MFA methods (requires verification)
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify with any available method first
        if method == "totp":
            verification = await mfa_service.verify_totp(user_id, verification_code, allow_backup_code=False)
        elif method == "sms":
            verification = await mfa_service.verify_sms_mfa(user_id, verification_code, setup=False)
        elif method == "email":
            verification = await mfa_service.verify_email_mfa(user_id, verification_code, setup=False)
        else:
            raise ValidationError("Invalid verification method")
        
        if not verification.get("verified"):
            raise AuthenticationError("Verification failed")
        
        # Disable all MFA methods
        from app.core.clerk import get_clerk_client
        clerk_client = get_clerk_client()
        
        await clerk_client.update_user(
            user_id=user_id,
            private_metadata={
                "mfa_enabled": False,
                "mfa_methods": [],
                "mfa_secret": None,
                "mfa_backup_codes": None,
                "mfa_email": None,
                "mfa_phone": None,
                "mfa_disabled_all_date": datetime.utcnow().isoformat()
            }
        )
        
        logger.info(f"All MFA methods disabled for user {user_id}")
        
        return {
            "status": "disabled",
            "message": "All multi-factor authentication methods have been disabled",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except (AuthenticationError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Failed to disable all MFA: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disable MFA")