from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Body, Query
from fastapi.responses import Response
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, EmailStr
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.bulk_operations_service import get_bulk_operations_service, BulkOperationType
from app.core.exceptions import ValidationError, AuthorizationError
from app.api.v1.deps import require_admin, get_db
from app.services.cache_service import cache_service

router = APIRouter()
logger = structlog.get_logger()


# ============= Request Models =============

class BulkUserCreateRequest(BaseModel):
    users: List[Dict[str, Any]]
    send_invitations: bool = True
    validate_only: bool = False


class BulkUserUpdateRequest(BaseModel):
    updates: List[Dict[str, Any]]


class BulkUserActionRequest(BaseModel):
    user_ids: List[str]
    reason: str
    notify_users: bool = True


class BulkPasswordResetRequest(BaseModel):
    user_ids: List[str]
    send_email: bool = True


class ExportRequest(BaseModel):
    fields: Optional[List[str]] = None
    filters: Optional[Dict[str, Any]] = None
    format: str = "csv"  # csv, json, excel


# ============= Bulk User Operations =============

@router.post("/users/create")
async def bulk_create_users(
    request: BulkUserCreateRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Create multiple users in bulk (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.bulk_create_users(
            users_data=request.users,
            admin_id=admin_user.get("user_id"),
            send_invitations=request.send_invitations,
            validate_only=request.validate_only
        )
        
        logger.info(
            "Bulk user creation initiated",
            operation_id=result["operation_id"],
            total=len(request.users),
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk user creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk creation failed")


@router.post("/users/update")
async def bulk_update_users(
    request: BulkUserUpdateRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Update multiple users in bulk (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.bulk_update_users(
            updates=request.updates,
            admin_id=admin_user.get("user_id")
        )
        
        logger.info(
            "Bulk user update initiated",
            operation_id=result["operation_id"],
            total=len(request.updates),
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk user update failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk update failed")


@router.post("/users/delete")
async def bulk_delete_users(
    request: BulkUserActionRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete multiple users in bulk (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.bulk_delete_users(
            user_ids=request.user_ids,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        logger.warning(
            "Bulk user deletion completed",
            operation_id=result["operation_id"],
            total=len(request.user_ids),
            deleted=result["deleted"],
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk user deletion failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk deletion failed")


@router.post("/users/ban")
async def bulk_ban_users(
    request: BulkUserActionRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Ban multiple users in bulk (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.bulk_ban_users(
            user_ids=request.user_ids,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        logger.info(
            "Bulk user ban completed",
            operation_id=result["operation_id"],
            total=len(request.user_ids),
            success=result["success"],
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk user ban failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk ban failed")


@router.post("/users/unban")
async def bulk_unban_users(
    request: BulkUserActionRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Unban multiple users in bulk (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.bulk_unban_users(
            user_ids=request.user_ids,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        logger.info(
            "Bulk user unban completed",
            operation_id=result["operation_id"],
            total=len(request.user_ids),
            success=result["success"],
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk user unban failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk unban failed")


@router.post("/users/reset-passwords")
async def bulk_reset_passwords(
    request: BulkPasswordResetRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Reset passwords for multiple users (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.bulk_reset_passwords(
            user_ids=request.user_ids,
            admin_id=admin_user.get("user_id"),
            send_email=request.send_email
        )
        
        logger.info(
            "Bulk password reset initiated",
            operation_id=result["operation_id"],
            total=len(request.user_ids),
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk password reset failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk password reset failed")


# ============= Import/Export Operations =============

@router.post("/import/users/csv")
async def import_users_csv(
    file: UploadFile = File(...),
    send_invitations: bool = Query(True),
    validate_only: bool = Query(False),
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Import users from CSV file (admin only)
    
    CSV format:
    - email (required)
    - first_name
    - last_name
    - username
    - phone_number
    - role
    - organization
    - metadata (JSON string)
    - send_invitation (true/false)
    """
    try:
        # Validate file type
        if not file.filename.endswith('.csv'):
            raise ValidationError("File must be a CSV")
        
        # Check file size (max 10MB)
        if file.size > 10 * 1024 * 1024:
            raise ValidationError("File size must be less than 10MB")
        
        bulk_service = get_bulk_operations_service(db)
        
        result = await bulk_service.import_users_from_csv(
            csv_file=file.file,
            admin_id=admin_user.get("user_id"),
            send_invitations=send_invitations,
            validate_only=validate_only
        )
        
        logger.info(
            "CSV import completed",
            operation_id=result["operation_id"],
            total=result["total"],
            admin_id=admin_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"CSV import failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Import failed")


@router.post("/export/users")
async def export_users(
    request: ExportRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Export users to CSV/JSON (admin only)
    """
    try:
        if request.format not in ["csv", "json"]:
            raise ValidationError("Format must be 'csv' or 'json'")
        
        bulk_service = get_bulk_operations_service(db)
        
        export_id = await bulk_service.export_users_to_csv(
            admin_id=admin_user.get("user_id"),
            filters=request.filters,
            fields=request.fields
        )
        
        logger.info(
            "User export completed",
            export_id=export_id,
            format=request.format,
            admin_id=admin_user.get("user_id")
        )
        
        return {
            "export_id": export_id,
            "format": request.format,
            "download_url": f"/api/v1/bulk/export/download/{export_id}",
            "expires_in": 3600
        }
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"User export failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Export failed")


@router.get("/export/download/{export_id}")
async def download_export(
    export_id: str,
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Download exported file (admin only)
    """
    try:
        # Get export from cache
        cache_key = f"bulk_export:{export_id}"
        export_data = await cache_service.get(cache_key)
        
        if not export_data:
            raise HTTPException(status_code=404, detail="Export not found or expired")
        
        # Verify ownership
        if export_data.get("created_by") != admin_user.get("user_id"):
            raise HTTPException(status_code=403, detail="Access denied")
        
        content = export_data.get("content", "")
        content_type = "text/csv" if export_data.get("type") == "csv" else "application/json"
        
        return Response(
            content=content,
            media_type=content_type,
            headers={
                "Content-Disposition": f"attachment; filename=export_{export_id}.{export_data.get('type', 'csv')}"
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export download failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Download failed")


# ============= Operation Status =============

@router.get("/operations/{operation_id}")
async def get_operation_status(
    operation_id: str,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get status of a bulk operation (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        status = await bulk_service.get_operation_status(operation_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Operation not found")
        
        # Verify ownership
        if status.get("initiated_by") != admin_user.get("user_id"):
            # Allow if user is super admin
            if not admin_user.get("is_super_admin"):
                raise HTTPException(status_code=403, detail="Access denied")
        
        return status
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get operation status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve status")


@router.post("/operations/{operation_id}/cancel")
async def cancel_operation(
    operation_id: str,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Cancel a bulk operation (admin only)
    """
    try:
        bulk_service = get_bulk_operations_service(db)
        
        # Get operation to verify ownership
        status = await bulk_service.get_operation_status(operation_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Operation not found")
        
        if status.get("initiated_by") != admin_user.get("user_id"):
            if not admin_user.get("is_super_admin"):
                raise HTTPException(status_code=403, detail="Access denied")
        
        if status.get("status") in ["completed", "failed", "cancelled"]:
            raise ValidationError("Operation already completed or cancelled")
        
        success = await bulk_service.cancel_operation(operation_id)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to cancel operation")
        
        logger.info(
            "Bulk operation cancelled",
            operation_id=operation_id,
            admin_id=admin_user.get("user_id")
        )
        
        return {
            "message": "Operation cancelled successfully",
            "operation_id": operation_id
        }
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel operation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cancel operation")


# ============= Templates =============

@router.get("/templates/csv/users")
async def get_user_import_template(
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Get CSV template for user import (admin only)
    """
    template = """email,first_name,last_name,username,phone_number,role,organization,metadata,send_invitation
john.doe@example.com,John,Doe,johndoe,+1234567890,user,,"{"department":"Engineering"}",true
jane.smith@example.com,Jane,Smith,janesmith,+0987654321,admin,,"{"department":"HR"}",true
"""
    
    return Response(
        content=template,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=user_import_template.csv"
        }
    )