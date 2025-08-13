from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Body, Query, HTTPException, Request
import structlog

from app.core.exceptions import AuthenticationError, ValidationError
from app.api.v1.deps import get_current_user
from app.services.password_change_service import password_change_service

router = APIRouter()
logger = structlog.get_logger()


def get_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent")
    }


@router.post("/change")
async def change_password(
    old_password: str = Body(...),
    new_password: str = Body(...),
    invalidate_other_sessions: bool = Body(False),
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Change user password with old password verification
    """
    try:
        client_info = get_client_info(request)
        
        result = await password_change_service.change_password(
            user_id=current_user.get("user_id"),
            old_password=old_password,
            new_password=new_password,
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            session_id=current_user.get("session_id") if invalidate_other_sessions else None
        )
        
        logger.info(
            f"Password changed",
            user_id=current_user.get("user_id"),
            ip_address=client_info.get("ip_address")
        )
        
        return result
    
    except (ValidationError, AuthenticationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to change password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to change password")


@router.post("/force-change")
async def force_password_change(
    user_id: str = Body(...),
    reason: str = Body("Security policy"),
    grace_period_hours: int = Body(24, ge=1, le=168),  # Max 7 days
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Force a user to change their password (admin only)
    """
    try:
        # Check if current user has admin privileges
        # This should be enhanced with proper role checking
        if not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        result = await password_change_service.force_password_change(
            user_id=user_id,
            reason=reason,
            grace_period_hours=grace_period_hours
        )
        
        logger.info(
            f"Password change forced",
            admin_id=current_user.get("user_id"),
            target_user_id=user_id,
            reason=reason
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to force password change: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to force password change")


@router.get("/requirements")
async def check_password_requirements(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Check if user needs to change password
    """
    try:
        requirements = await password_change_service.check_password_requirements(
            user_id=current_user.get("user_id")
        )
        
        return requirements
    
    except Exception as e:
        logger.error(f"Failed to check password requirements: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check requirements")


@router.get("/history")
async def get_password_history(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get password change history for the user
    """
    try:
        history = await password_change_service.get_password_history(
            user_id=current_user.get("user_id"),
            include_hashes=False  # Never include hashes in API response
        )
        
        return {
            "history": history,
            "total": len(history)
        }
    
    except Exception as e:
        logger.error(f"Failed to get password history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get history")


@router.post("/validate")
async def validate_password_strength(
    password: str = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Validate password strength without changing it
    """
    try:
        validation = await password_change_service.validate_password_strength(
            password=password,
            user_id=current_user.get("user_id")
        )
        
        return validation
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to validate password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to validate password")


@router.get("/policy")
async def get_password_policy():
    """
    Get password policy requirements
    """
    try:
        from app.core.config import settings
        
        policy = {
            "min_length": getattr(settings, 'PASSWORD_MIN_LENGTH', 8),
            "max_length": getattr(settings, 'PASSWORD_MAX_LENGTH', 128),
            "require_uppercase": getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True),
            "require_lowercase": getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True),
            "require_numbers": getattr(settings, 'PASSWORD_REQUIRE_NUMBERS', True),
            "require_special_chars": getattr(settings, 'PASSWORD_REQUIRE_SPECIAL', True),
            "min_password_age_hours": 1,
            "max_password_age_days": getattr(settings, 'MAX_PASSWORD_AGE_DAYS', 90),
            "password_history_count": 5,
            "max_attempts_per_hour": 5,
            "allowed_special_chars": "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "breach_check_enabled": getattr(settings, 'PASSWORD_BREACH_CHECK', True),
            "common_passwords_check": True
        }
        
        return {
            "policy": policy,
            "guidelines": [
                "Use a mix of uppercase and lowercase letters",
                "Include at least one number",
                "Include at least one special character",
                "Avoid common passwords and dictionary words",
                "Don't reuse recent passwords",
                "Consider using a passphrase with random words"
            ]
        }
    
    except Exception as e:
        logger.error(f"Failed to get password policy: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get policy")


@router.post("/bulk-force-change")
async def bulk_force_password_change(
    user_ids: list[str] = Body(..., description="List of user IDs"),
    reason: str = Body("Security policy"),
    grace_period_hours: int = Body(24, ge=1, le=168),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Force password change for multiple users (admin only)
    """
    try:
        # Check admin privileges
        if not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        if len(user_ids) > 100:
            raise ValidationError("Maximum 100 users can be processed at once")
        
        successful = []
        failed = []
        
        for user_id in user_ids:
            try:
                result = await password_change_service.force_password_change(
                    user_id=user_id,
                    reason=reason,
                    grace_period_hours=grace_period_hours
                )
                
                successful.append({
                    "user_id": user_id,
                    "forced": result["forced"],
                    "grace_period_end": result["grace_period_end"]
                })
                
            except Exception as e:
                failed.append({
                    "user_id": user_id,
                    "error": str(e)
                })
        
        logger.info(
            f"Bulk password change forced",
            admin_id=current_user.get("user_id"),
            successful_count=len(successful),
            failed_count=len(failed)
        )
        
        return {
            "successful": successful,
            "failed": failed,
            "total_processed": len(user_ids),
            "success_count": len(successful),
            "failure_count": len(failed)
        }
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed bulk force password change: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process bulk operation")


@router.get("/security-events")
async def get_password_security_events(
    limit: int = Query(20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get password-related security events for the user
    """
    try:
        from app.services.security_service import security_service
        
        events = await security_service.get_user_security_events(
            user_id=current_user.get("user_id"),
            event_types=["password_changed", "password_change_failed", "password_change_forced"],
            limit=limit
        )
        
        return {
            "events": events,
            "total": len(events),
            "limit": limit
        }
    
    except Exception as e:
        logger.error(f"Failed to get security events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get security events")


@router.get("/strength-meter")
async def get_password_strength_info():
    """
    Get information about password strength calculation
    """
    return {
        "scoring": {
            "very_weak": "0-29",
            "weak": "30-49", 
            "moderate": "50-69",
            "strong": "70-89",
            "very_strong": "90-100"
        },
        "factors": [
            {
                "factor": "Length",
                "weight": "High",
                "description": "Longer passwords are exponentially stronger"
            },
            {
                "factor": "Character variety",
                "weight": "High", 
                "description": "Mix of uppercase, lowercase, numbers, symbols"
            },
            {
                "factor": "Common patterns",
                "weight": "High",
                "description": "Avoiding sequential or repetitive patterns"
            },
            {
                "factor": "Dictionary words",
                "weight": "Medium",
                "description": "Avoiding common words and names"
            },
            {
                "factor": "Breach check",
                "weight": "Critical",
                "description": "Not found in known data breaches"
            }
        ],
        "tips": [
            "Use 12+ characters for better security",
            "Combine random words with numbers/symbols",
            "Avoid personal information like names, dates",
            "Use a password manager for unique passwords",
            "Enable two-factor authentication when available"
        ]
    }