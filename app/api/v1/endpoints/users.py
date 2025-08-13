from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
import structlog
from pathlib import Path

from app.core.config import settings

from app.core.clerk import get_clerk_client
from app.core.exceptions import NotFoundError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user, require_admin
from app.core.permissions import require_permission, require_any_permission
from app.schemas.user import (
    UserResponse,
    UserUpdateRequest,
    UserListResponse,
    UserMetadataUpdate
)
from app.services.avatar_service import avatar_service

router = APIRouter()
logger = structlog.get_logger()


@router.get("/", response_model=UserListResponse)
@require_permission("users:read")
async def list_users(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    email: Optional[str] = None,
    username: Optional[str] = None,
    phone: Optional[str] = None,
    order_by: str = Query("-created_at"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    List all users (admin only)
    """
    try:
        users = await clerk_client.list_users(
            limit=limit,
            offset=offset,
            email_address=[email] if email else None,
            username=[username] if username else None,
            phone_number=[phone] if phone else None,
            order_by=order_by
        )
        
        return UserListResponse(
            users=[
                UserResponse(
                    user_id=user.id,
                    email=user.email_addresses[0].email_address if user.email_addresses else None,
                    username=user.username,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    profile_image_url=user.profile_image_url,
                    created_at=user.created_at,
                    updated_at=user.updated_at,
                    email_verified=user.email_addresses[0].verification.status == "verified" if user.email_addresses else False,
                    phone_verified=user.phone_numbers[0].verification.status == "verified" if user.phone_numbers else False,
                    two_factor_enabled=user.two_factor_enabled,
                    public_metadata=user.public_metadata
                )
                for user in users
            ],
            total=len(users),
            limit=limit,
            offset=offset
        )
    
    except Exception as e:
        logger.error("Failed to list users", error=str(e))
        raise ValidationError(f"Failed to list users: {str(e)}")


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Get user by ID
    """
    try:
        if user_id != current_user.get("user_id"):
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if not is_admin:
                raise AuthorizationError("Cannot view other users' profiles")
        
        user = await clerk_client.get_user(user_id)
        
        if not user:
            raise NotFoundError(f"User {user_id} not found")
        
        return UserResponse(
            user_id=user.id,
            email=user.email_addresses[0].email_address if user.email_addresses else None,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            profile_image_url=user.profile_image_url,
            created_at=user.created_at,
            updated_at=user.updated_at,
            email_verified=user.email_addresses[0].verification.status == "verified" if user.email_addresses else False,
            phone_verified=user.phone_numbers[0].verification.status == "verified" if user.phone_numbers else False,
            two_factor_enabled=user.two_factor_enabled,
            public_metadata=user.public_metadata
        )
    
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Failed to get user {user_id}", error=str(e))
        raise ValidationError(f"Failed to get user: {str(e)}")


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    update_data: UserUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Update user information
    """
    try:
        if user_id != current_user.get("user_id"):
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if not is_admin:
                raise AuthorizationError("Cannot update other users' profiles")
        
        update_dict = update_data.dict(exclude_unset=True)
        
        user = await clerk_client.update_user(user_id, **update_dict)
        
        logger.info(f"User updated successfully", user_id=user_id)
        
        return UserResponse(
            user_id=user.id,
            email=user.email_addresses[0].email_address if user.email_addresses else None,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            profile_image_url=user.profile_image_url,
            created_at=user.created_at,
            updated_at=user.updated_at,
            email_verified=user.email_addresses[0].verification.status == "verified" if user.email_addresses else False,
            phone_verified=user.phone_numbers[0].verification.status == "verified" if user.phone_numbers else False,
            two_factor_enabled=user.two_factor_enabled,
            public_metadata=user.public_metadata
        )
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to update user {user_id}", error=str(e))
        raise ValidationError(f"Failed to update user: {str(e)}")


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Delete user account
    """
    try:
        if user_id != current_user.get("user_id"):
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if not is_admin:
                raise AuthorizationError("Cannot delete other users' accounts")
        
        success = await clerk_client.delete_user(user_id)
        
        if success:
            logger.info(f"User deleted successfully", user_id=user_id)
            return {"message": "User deleted successfully"}
        else:
            raise ValidationError("Failed to delete user")
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user {user_id}", error=str(e))
        raise ValidationError(f"Failed to delete user: {str(e)}")


@router.patch("/{user_id}/metadata", response_model=UserResponse)
async def update_user_metadata(
    user_id: str,
    metadata: UserMetadataUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Update user metadata
    """
    try:
        if user_id != current_user.get("user_id"):
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if not is_admin:
                raise AuthorizationError("Cannot update other users' metadata")
        
        update_data = {}
        if metadata.public_metadata is not None:
            update_data["public_metadata"] = metadata.public_metadata
        if metadata.private_metadata is not None and user_id == current_user.get("user_id"):
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if is_admin:
                update_data["private_metadata"] = metadata.private_metadata
        if metadata.unsafe_metadata is not None:
            update_data["unsafe_metadata"] = metadata.unsafe_metadata
        
        user = await clerk_client.update_user(user_id, **update_data)
        
        logger.info(f"User metadata updated successfully", user_id=user_id)
        
        return UserResponse(
            user_id=user.id,
            email=user.email_addresses[0].email_address if user.email_addresses else None,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            profile_image_url=user.profile_image_url,
            created_at=user.created_at,
            updated_at=user.updated_at,
            email_verified=user.email_addresses[0].verification.status == "verified" if user.email_addresses else False,
            phone_verified=user.phone_numbers[0].verification.status == "verified" if user.phone_numbers else False,
            two_factor_enabled=user.two_factor_enabled,
            public_metadata=user.public_metadata
        )
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to update user metadata", error=str(e))
        raise ValidationError(f"Failed to update metadata: {str(e)}")


@router.post("/{user_id}/upload-avatar")
async def upload_avatar(
    user_id: str,
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Upload user avatar
    """
    try:
        if user_id != current_user.get("user_id"):
            raise AuthorizationError("Cannot upload avatar for other users")
        
        # Read file contents
        contents = await file.read()
        
        # Upload avatar
        result = await avatar_service.upload_avatar(
            user_id=user_id,
            file_data=contents,
            filename=file.filename,
            content_type=file.content_type
        )
        
        logger.info(f"Avatar uploaded successfully for user {user_id}")
        
        return result
    
    except AuthorizationError:
        raise
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to upload avatar", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to upload avatar")


@router.delete("/{user_id}/avatar")
async def remove_avatar(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove user avatar and set to default
    """
    try:
        if user_id != current_user.get("user_id"):
            raise AuthorizationError("Cannot remove avatar for other users")
        
        result = await avatar_service.remove_avatar(user_id)
        
        logger.info(f"Avatar removed for user {user_id}")
        
        return result
    
    except AuthorizationError:
        raise
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to remove avatar", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to remove avatar")


@router.get("/{user_id}/avatar")
async def get_avatar_info(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get avatar information for a user
    """
    try:
        avatar_data = await avatar_service.get_avatar(user_id)
        
        if not avatar_data:
            # Generate default avatar
            default_avatar = await avatar_service.generate_default_avatar(user_id)
            return {
                "avatar_url": default_avatar,
                "is_default": True
            }
        
        return avatar_data
    
    except Exception as e:
        logger.error(f"Failed to get avatar info", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get avatar information")


@router.post("/{user_id}/avatar/from-url")
async def update_avatar_from_url(
    user_id: str,
    image_url: str = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update avatar from an external URL
    """
    try:
        if user_id != current_user.get("user_id"):
            raise AuthorizationError("Cannot update avatar for other users")
        
        result = await avatar_service.update_avatar_from_url(user_id, image_url)
        
        logger.info(f"Avatar updated from URL for user {user_id}")
        
        return result
    
    except AuthorizationError:
        raise
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update avatar from URL", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update avatar")


@router.post("/{user_id}/avatar/crop")
async def crop_avatar(
    user_id: str,
    x: int = Form(...),
    y: int = Form(...),
    width: int = Form(...),
    height: int = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Crop existing avatar
    """
    try:
        if user_id != current_user.get("user_id"):
            raise AuthorizationError("Cannot crop avatar for other users")
        
        crop_data = {
            "x": x,
            "y": y,
            "width": width,
            "height": height
        }
        
        result = await avatar_service.crop_avatar(user_id, crop_data)
        
        logger.info(f"Avatar cropped for user {user_id}")
        
        return result
    
    except AuthorizationError:
        raise
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to crop avatar", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to crop avatar")


@router.get("/avatar/{filename}")
async def serve_avatar(filename: str):
    """
    Serve avatar file
    """
    try:
        # Construct file path
        avatar_path = Path(settings.UPLOAD_DIR if hasattr(settings, 'UPLOAD_DIR') else "./uploads/avatars") / filename
        
        if not avatar_path.exists():
            raise HTTPException(status_code=404, detail="Avatar not found")
        
        # Determine content type from extension
        ext = filename.rsplit(".", 1)[-1].lower()
        content_type_map = {
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "webp": "image/webp"
        }
        content_type = content_type_map.get(ext, "image/jpeg")
        
        return FileResponse(
            path=avatar_path,
            media_type=content_type,
            headers={
                "Cache-Control": "public, max-age=86400"  # Cache for 24 hours
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to serve avatar", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to serve avatar")


@router.get("/{user_id}/avatar/stats")
async def get_avatar_stats(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get avatar statistics for a user
    """
    try:
        if user_id != current_user.get("user_id"):
            # Check if admin
            from app.core.clerk import get_clerk_client
            clerk_client = get_clerk_client()
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if not is_admin:
                raise AuthorizationError("Cannot view other users' avatar stats")
        
        stats = await avatar_service.get_avatar_stats(user_id)
        
        return stats
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get avatar stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get avatar statistics")


@router.get("/{user_id}/sessions")
async def get_user_sessions(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Get all active sessions for a user
    """
    try:
        if user_id != current_user.get("user_id"):
            user = await clerk_client.get_user(current_user.get("user_id"))
            is_admin = user.private_metadata.get("is_admin", False)
            if not is_admin:
                raise AuthorizationError("Cannot view other users' sessions")
        
        sessions = await clerk_client.list_user_sessions(user_id)
        
        return {
            "sessions": [
                {
                    "session_id": session.id,
                    "status": session.status,
                    "last_active_at": session.last_active_at,
                    "expire_at": session.expire_at,
                    "client_id": session.client_id,
                    "user_agent": session.latest_activity.user_agent if session.latest_activity else None,
                    "ip_address": session.latest_activity.ip_address if session.latest_activity else None
                }
                for session in sessions
            ],
            "total": len(sessions)
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get user sessions", error=str(e))
        raise ValidationError(f"Failed to get sessions: {str(e)}")