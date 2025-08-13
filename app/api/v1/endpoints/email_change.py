from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Body, Query, HTTPException, Request
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user
from app.services.email_change_service import email_change_service
from app.core.config import settings

router = APIRouter()
logger = structlog.get_logger()


@router.post("/initiate")
async def initiate_email_change(
    new_email: str = Body(...),
    password: Optional[str] = Body(None),
    require_password: bool = Body(True),
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Initiate email address change with verification
    """
    try:
        # Get current email from user
        current_email = current_user.get("email")
        if not current_email:
            raise ValidationError("Current email not found")
        
        result = await email_change_service.initiate_email_change(
            user_id=current_user.get("user_id"),
            current_email=current_email,
            new_email=new_email,
            password=password,
            require_password=require_password
        )
        
        logger.info(
            f"Email change initiated",
            user_id=current_user.get("user_id"),
            new_email=new_email
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to initiate email change: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate email change")


@router.post("/verify")
async def verify_email_token(
    change_id: str = Body(...),
    token: str = Body(...),
    email_type: str = Body(..., description="'old' or 'new'")
):
    """
    Verify email change token
    """
    try:
        if email_type not in ["old", "new"]:
            raise ValidationError("Email type must be 'old' or 'new'")
        
        result = await email_change_service.verify_email_token(
            change_id=change_id,
            token=token,
            email_type=email_type
        )
        
        logger.info(
            f"Email token verified",
            change_id=change_id,
            email_type=email_type,
            completed=result.get("completed", False)
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify email token: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify email token")


@router.post("/cancel")
async def cancel_email_change(
    change_id: Optional[str] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Cancel a pending email change request
    """
    try:
        result = await email_change_service.cancel_email_change(
            user_id=current_user.get("user_id"),
            change_id=change_id
        )
        
        logger.info(
            f"Email change cancelled",
            user_id=current_user.get("user_id"),
            change_id=result.get("change_id")
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to cancel email change: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cancel email change")


@router.post("/resend")
async def resend_verification_email(
    email_type: str = Body(..., description="'old', 'new', or 'both'"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Resend verification email(s)
    """
    try:
        if email_type not in ["old", "new", "both"]:
            raise ValidationError("Email type must be 'old', 'new', or 'both'")
        
        result = await email_change_service.resend_verification_email(
            user_id=current_user.get("user_id"),
            email_type=email_type
        )
        
        logger.info(
            f"Verification emails resent",
            user_id=current_user.get("user_id"),
            email_type=email_type
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to resend verification email: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to resend verification email")


@router.get("/status")
async def get_email_change_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get status of pending email change
    """
    try:
        status = await email_change_service.get_email_change_status(
            user_id=current_user.get("user_id")
        )
        
        if status:
            return {
                "has_pending_change": True,
                **status
            }
        else:
            return {
                "has_pending_change": False,
                "message": "No pending email change requests"
            }
    
    except Exception as e:
        logger.error(f"Failed to get email change status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get status")


@router.get("/verify")
async def verify_email_from_link(
    id: str = Query(..., description="Change ID"),
    token: str = Query(..., description="Verification token"),
    type: str = Query(..., description="Email type (old/new)")
):
    """
    Verify email from link (for direct browser access)
    """
    try:
        if type not in ["old", "new"]:
            raise ValidationError("Invalid email type")
        
        result = await email_change_service.verify_email_token(
            change_id=id,
            token=token,
            email_type=type
        )
        
        logger.info(
            f"Email verified from link",
            change_id=id,
            email_type=type,
            completed=result.get("completed", False)
        )
        
        # Return user-friendly response
        if result.get("completed"):
            return {
                "success": True,
                "message": "Email address successfully changed!",
                "redirect_url": "/dashboard",
                **result
            }
        else:
            return {
                "success": True,
                "message": f"{type.capitalize()} email verified. Please check the other email to complete the process.",
                **result
            }
    
    except ValidationError as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Verification failed. Please try again or request a new verification email."
        }
    except Exception as e:
        logger.error(f"Failed to verify email from link: {str(e)}")
        return {
            "success": False,
            "error": "Internal error",
            "message": "Something went wrong. Please try again later."
        }


@router.get("/history")
async def get_email_change_history(
    limit: int = Query(10, ge=1, le=50),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get email change history for the user
    """
    try:
        # Get email change logs from cache
        from app.services.cache_service import cache_service
        
        user_id = current_user.get("user_id")
        pattern = f"email_change_log:{user_id}:*"
        logs = await cache_service.get_pattern(pattern)
        
        # Sort by timestamp and limit
        history = []
        for key, log_data in logs.items():
            if isinstance(log_data, dict):
                history.append({
                    "old_email": log_data.get("old_email"),
                    "new_email": log_data.get("new_email"),
                    "changed_at": log_data.get("changed_at"),
                    "change_id": log_data.get("change_id")
                })
        
        # Sort by changed_at descending
        history.sort(key=lambda x: x.get("changed_at", ""), reverse=True)
        
        return {
            "history": history[:limit],
            "total": len(history),
            "limit": limit
        }
    
    except Exception as e:
        logger.error(f"Failed to get email change history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get history")


@router.get("/validation")
async def validate_new_email(
    email: str = Query(..., description="Email to validate")
):
    """
    Validate if an email can be used for email change
    """
    try:
        # Check email format
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid_format = re.match(pattern, email) is not None
        
        if not is_valid_format:
            return {
                "valid": False,
                "error": "Invalid email format"
            }
        
        # Check if email is already in use
        from app.core.clerk import get_clerk_client
        clerk_client = get_clerk_client()
        existing_users = await clerk_client.list_users(email_address=[email])
        
        if existing_users:
            return {
                "valid": False,
                "error": "Email address is already in use"
            }
        
        # Check domain restrictions if any
        domain = email.split("@")[1].lower()
        blocked_domains = getattr(settings, 'BLOCKED_EMAIL_DOMAINS', [])
        
        if domain in blocked_domains:
            return {
                "valid": False,
                "error": "Email domain is not allowed"
            }
        
        return {
            "valid": True,
            "message": "Email address is available"
        }
    
    except Exception as e:
        logger.error(f"Failed to validate email: {str(e)}")
        return {
            "valid": False,
            "error": "Unable to validate email"
        }