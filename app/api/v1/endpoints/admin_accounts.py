from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, Body, Query, HTTPException
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user
from app.services.admin_account_service import admin_account_service
from app.services.cache_service import cache_service
from app.core.config import settings

router = APIRouter()
logger = structlog.get_logger()


@router.post("/create")
async def create_user_account(
    email: str = Body(...),
    first_name: Optional[str] = Body(None),
    last_name: Optional[str] = Body(None),
    username: Optional[str] = Body(None),
    phone_number: Optional[str] = Body(None),
    organization_id: Optional[str] = Body(None),
    role: str = Body("member", description="Role in organization (member, admin, owner)"),
    send_welcome_email: bool = Body(True),
    require_password_change: bool = Body(True),
    generate_temp_password: bool = Body(True),
    custom_password: Optional[str] = Body(None),
    metadata: Optional[Dict[str, Any]] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create a new user account as an admin
    """
    try:
        result = await admin_account_service.create_user_account(
            admin_id=current_user.get("user_id"),
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            phone_number=phone_number,
            organization_id=organization_id,
            role=role,
            send_welcome_email=send_welcome_email,
            require_password_change=require_password_change,
            generate_temp_password=generate_temp_password,
            custom_password=custom_password,
            metadata=metadata
        )
        
        logger.info(
            f"Admin created user account",
            admin_id=current_user.get("user_id"),
            email=email
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create user account: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create account")


@router.post("/create-bulk")
async def create_bulk_accounts(
    accounts: List[Dict[str, Any]] = Body(..., description="List of account details"),
    organization_id: Optional[str] = Body(None),
    default_role: str = Body("member"),
    send_welcome_emails: bool = Body(True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create multiple user accounts in bulk
    """
    try:
        result = await admin_account_service.create_bulk_accounts(
            admin_id=current_user.get("user_id"),
            accounts=accounts,
            organization_id=organization_id,
            default_role=default_role,
            send_welcome_emails=send_welcome_emails
        )
        
        logger.info(
            f"Bulk account creation completed",
            admin_id=current_user.get("user_id"),
            success_count=result["success_count"],
            failure_count=result["failure_count"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create bulk accounts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create bulk accounts")


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: str,
    new_password: Optional[str] = Body(None),
    generate_temp: bool = Body(True),
    send_notification: bool = Body(True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Reset a user's password as an admin
    """
    try:
        result = await admin_account_service.reset_user_password(
            admin_id=current_user.get("user_id"),
            user_id=user_id,
            new_password=new_password,
            generate_temp=generate_temp,
            send_notification=send_notification
        )
        
        logger.info(
            f"Admin reset user password",
            admin_id=current_user.get("user_id"),
            user_id=user_id
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to reset password: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to reset password")


@router.post("/{user_id}/suspend")
async def suspend_user_account(
    user_id: str,
    reason: str = Body(...),
    duration_hours: Optional[int] = Body(None, description="Suspension duration in hours"),
    notify_user: bool = Body(True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Suspend a user account
    """
    try:
        result = await admin_account_service.suspend_user_account(
            admin_id=current_user.get("user_id"),
            user_id=user_id,
            reason=reason,
            duration_hours=duration_hours,
            notify_user=notify_user
        )
        
        logger.info(
            f"User account suspended",
            admin_id=current_user.get("user_id"),
            user_id=user_id,
            reason=reason
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to suspend account: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to suspend account")


@router.post("/{user_id}/unsuspend")
async def unsuspend_user_account(
    user_id: str,
    reason: str = Body(...),
    notify_user: bool = Body(True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Unsuspend a user account
    """
    try:
        result = await admin_account_service.unsuspend_user_account(
            admin_id=current_user.get("user_id"),
            user_id=user_id,
            reason=reason,
            notify_user=notify_user
        )
        
        logger.info(
            f"User account unsuspended",
            admin_id=current_user.get("user_id"),
            user_id=user_id,
            reason=reason
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to unsuspend account: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to unsuspend account")


@router.get("/admin-created")
async def get_admin_created_accounts(
    organization_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get list of accounts created by the current admin
    """
    try:
        accounts = await admin_account_service.get_admin_created_accounts(
            admin_id=current_user.get("user_id"),
            organization_id=organization_id,
            limit=limit,
            offset=offset
        )
        
        return {
            "accounts": accounts,
            "total": len(accounts),
            "limit": limit,
            "offset": offset
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get admin-created accounts: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve accounts")


@router.post("/import-csv")
async def import_accounts_from_csv(
    csv_content: str = Body(..., description="CSV content with headers: email,first_name,last_name,username,role"),
    organization_id: Optional[str] = Body(None),
    send_welcome_emails: bool = Body(True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Import multiple accounts from CSV data
    """
    try:
        import csv
        from io import StringIO
        
        # Parse CSV content
        csv_reader = csv.DictReader(StringIO(csv_content))
        accounts = []
        
        for row in csv_reader:
            account = {
                "email": row.get("email", "").strip(),
                "first_name": row.get("first_name", "").strip() or None,
                "last_name": row.get("last_name", "").strip() or None,
                "username": row.get("username", "").strip() or None,
                "role": row.get("role", "member").strip()
            }
            
            # Skip empty rows
            if account["email"]:
                accounts.append(account)
        
        if not accounts:
            raise ValidationError("No valid accounts found in CSV")
        
        # Create accounts in bulk
        result = await admin_account_service.create_bulk_accounts(
            admin_id=current_user.get("user_id"),
            accounts=accounts,
            organization_id=organization_id,
            send_welcome_emails=send_welcome_emails
        )
        
        logger.info(
            f"CSV import completed",
            admin_id=current_user.get("user_id"),
            total_accounts=len(accounts),
            success_count=result["success_count"]
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to import accounts from CSV: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to import accounts")


@router.get("/template/csv")
async def get_csv_template():
    """
    Get CSV template for bulk account import
    """
    template = """email,first_name,last_name,username,role
john.doe@example.com,John,Doe,johndoe,member
jane.smith@example.com,Jane,Smith,janesmith,admin
bob.wilson@example.com,Bob,Wilson,bobw,member"""
    
    return {
        "template": template,
        "headers": ["email", "first_name", "last_name", "username", "role"],
        "required_fields": ["email"],
        "optional_fields": ["first_name", "last_name", "username", "role"],
        "valid_roles": ["member", "admin", "owner"],
        "instructions": [
            "Email is required for each account",
            "Role defaults to 'member' if not specified",
            "Username must be unique if provided",
            "Empty fields should be left blank (not 'null' or 'N/A')",
            "Maximum 100 accounts can be imported at once"
        ]
    }


@router.get("/stats")
async def get_admin_account_stats(
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get statistics about admin-created accounts
    """
    try:
        # Get admin-created accounts
        accounts = await admin_account_service.get_admin_created_accounts(
            admin_id=current_user.get("user_id"),
            organization_id=organization_id,
            limit=1000,
            offset=0
        )
        
        # Calculate statistics
        total_created = len(accounts)
        onboarding_complete = len([a for a in accounts if a.get("onboarding_complete")])
        onboarding_pending = total_created - onboarding_complete
        suspended = len([a for a in accounts if a.get("suspended")])
        
        return {
            "total_accounts_created": total_created,
            "onboarding_complete": onboarding_complete,
            "onboarding_pending": onboarding_pending,
            "suspended_accounts": suspended,
            "completion_rate": round((onboarding_complete / total_created * 100) if total_created > 0 else 0, 2),
            "admin_id": current_user.get("user_id"),
            "organization_id": organization_id
        }
    
    except Exception as e:
        logger.error(f"Failed to get admin account stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.post("/onboarding/complete")
async def complete_onboarding(
    token: str = Body(..., embed=True),
    new_password: Optional[str] = Body(None, embed=True)
):
    """
    Complete onboarding for admin-created account
    """
    try:
        # Get onboarding data
        onboarding_key = f"onboarding:{token}"
        onboarding_data = await cache_service.get(onboarding_key)
        
        if not onboarding_data:
            raise ValidationError("Invalid or expired onboarding token")
        
        # Check expiry
        from datetime import datetime
        expires_at = datetime.fromisoformat(onboarding_data["expires_at"])
        if datetime.utcnow() > expires_at:
            raise ValidationError("Onboarding link has expired")
        
        user_id = onboarding_data["user_id"]
        
        # Update password if required and provided
        if onboarding_data.get("require_password_change") and new_password:
            # Validate new password
            from app.services.password_validator import password_validator
            is_valid, errors = password_validator.validate_password(
                new_password,
                email=onboarding_data.get("email")
            )
            if not is_valid:
                raise ValidationError(f"Password validation failed: {', '.join(errors)}")
            
            # Update password in Clerk
            from app.core.clerk import get_clerk_client
            clerk_client = get_clerk_client()
            await clerk_client.update_user(
                user_id,
                password=new_password,
                skip_password_checks=True
            )
        
        # Update user metadata to mark onboarding complete
        from app.core.clerk import get_clerk_client
        clerk_client = get_clerk_client()
        user = await clerk_client.get_user(user_id)
        
        await clerk_client.update_user(
            user_id,
            unsafe_metadata={
                **user.unsafe_metadata,
                "onboarding_required": False,
                "require_password_change": False,
                "onboarding_completed_at": datetime.utcnow().isoformat()
            }
        )
        
        # Delete onboarding token
        await cache_service.delete(onboarding_key)
        
        # Delete temp password if exists
        temp_pass_key = f"temp_password:{user_id}"
        await cache_service.delete(temp_pass_key)
        
        logger.info(
            f"Onboarding completed",
            user_id=user_id
        )
        
        return {
            "success": True,
            "user_id": user_id,
            "message": "Onboarding completed successfully",
            "redirect_url": settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "/dashboard"
        }
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to complete onboarding: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to complete onboarding")