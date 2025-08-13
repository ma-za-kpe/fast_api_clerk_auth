from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, Body, Query, HTTPException, Request, Header
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user, require_admin
from app.services.api_key_service import api_key_service, APIKeyScope

router = APIRouter()
logger = structlog.get_logger()


@router.post("/create")
async def create_api_key(
    name: str = Body(...),
    key_type: str = Body("secret", description="Type: 'publishable' or 'secret'"),
    scopes: Optional[List[str]] = Body(None, description="List of permission scopes"),
    expires_in_days: Optional[int] = Body(None, ge=1, le=365),
    allowed_ips: Optional[List[str]] = Body(None),
    allowed_origins: Optional[List[str]] = Body(None),
    rate_limit: Optional[int] = Body(None, ge=1, le=10000),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create a new API key with specified permissions
    """
    try:
        user_id = current_user.get("user_id")
        
        result = await api_key_service.create_api_key(
            user_id=user_id,
            name=name,
            key_type=key_type,
            scopes=scopes,
            expires_in_days=expires_in_days,
            allowed_ips=allowed_ips,
            allowed_origins=allowed_origins,
            rate_limit=rate_limit
        )
        
        logger.info(f"API key created", user_id=user_id, key_id=result["key_id"])
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create API key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create API key")


@router.get("/")
async def list_api_keys(
    include_revoked: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List all API keys for the current user
    """
    try:
        user_id = current_user.get("user_id")
        
        keys = await api_key_service.get_user_api_keys(
            user_id=user_id,
            include_revoked=include_revoked
        )
        
        return {
            "keys": keys,
            "total": len(keys),
            "active": len([k for k in keys if k.get("active")]),
            "max_allowed": api_key_service.max_keys_per_user
        }
    
    except Exception as e:
        logger.error(f"Failed to list API keys: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve API keys")


@router.get("/scopes")
async def get_available_scopes():
    """
    Get all available API key scopes
    """
    return {
        "all_scopes": APIKeyScope.get_all_scopes(),
        "read_scopes": APIKeyScope.get_read_scopes(),
        "write_scopes": APIKeyScope.get_write_scopes(),
        "descriptions": {
            APIKeyScope.READ_USERS.value: "Read user information",
            APIKeyScope.WRITE_USERS.value: "Create and update users",
            APIKeyScope.READ_ORGANIZATIONS.value: "Read organization information",
            APIKeyScope.WRITE_ORGANIZATIONS.value: "Create and update organizations",
            APIKeyScope.READ_SESSIONS.value: "Read session information",
            APIKeyScope.WRITE_SESSIONS.value: "Create and manage sessions",
            APIKeyScope.READ_WEBHOOKS.value: "Read webhook configurations",
            APIKeyScope.WRITE_WEBHOOKS.value: "Create and manage webhooks",
            APIKeyScope.ADMIN.value: "Full administrative access"
        }
    }


@router.post("/{key_id}/rotate")
async def rotate_api_key(
    key_id: str,
    immediate: bool = Body(False, description="Revoke old key immediately without grace period"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Rotate an API key with optional grace period
    """
    try:
        user_id = current_user.get("user_id")
        
        result = await api_key_service.rotate_api_key(
            user_id=user_id,
            key_id=key_id,
            immediate=immediate
        )
        
        logger.info(
            f"API key rotated",
            user_id=user_id,
            old_key_id=key_id,
            new_key_id=result["new_key_id"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to rotate API key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to rotate API key")


@router.patch("/{key_id}")
async def update_api_key(
    key_id: str,
    name: Optional[str] = Body(None),
    scopes: Optional[List[str]] = Body(None),
    allowed_ips: Optional[List[str]] = Body(None),
    allowed_origins: Optional[List[str]] = Body(None),
    rate_limit: Optional[int] = Body(None, ge=1, le=10000),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update API key settings
    """
    try:
        user_id = current_user.get("user_id")
        
        result = await api_key_service.update_api_key(
            user_id=user_id,
            key_id=key_id,
            name=name,
            scopes=scopes,
            allowed_ips=allowed_ips,
            allowed_origins=allowed_origins,
            rate_limit=rate_limit
        )
        
        logger.info(f"API key updated", user_id=user_id, key_id=key_id)
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update API key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update API key")


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    reason: Optional[str] = Body(None, embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Revoke an API key
    """
    try:
        user_id = current_user.get("user_id")
        
        success = await api_key_service.revoke_api_key(
            user_id=user_id,
            key_id=key_id,
            reason=reason
        )
        
        if success:
            logger.info(f"API key revoked", user_id=user_id, key_id=key_id)
            return {
                "success": True,
                "message": "API key revoked successfully"
            }
        else:
            raise ValidationError("Failed to revoke API key")
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to revoke API key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke API key")


@router.post("/validate")
async def validate_api_key(
    api_key: str = Header(..., alias="X-API-Key"),
    required_scopes: Optional[List[str]] = Body(None),
    request: Request = None
):
    """
    Validate an API key and check permissions
    """
    try:
        # Get IP and origin from request
        ip_address = request.client.host if request else None
        origin = request.headers.get("Origin") if request else None
        
        # Validate key
        is_valid, key_data = await api_key_service.validate_api_key(
            api_key=api_key,
            required_scopes=required_scopes,
            ip_address=ip_address,
            origin=origin
        )
        
        if is_valid:
            return {
                "valid": True,
                "key_id": key_data["key_id"],
                "user_id": key_data["user_id"],
                "type": key_data["type"],
                "scopes": key_data["scopes"],
                "rate_limit": key_data["rate_limit"]
            }
        else:
            raise AuthenticationError("Invalid API key")
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to validate API key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to validate API key")


@router.get("/analytics")
async def get_api_key_analytics(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get API key usage analytics
    """
    try:
        user_id = current_user.get("user_id")
        
        analytics = await api_key_service.get_api_key_analytics(user_id)
        
        return analytics
    
    except Exception as e:
        logger.error(f"Failed to get API key analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analytics")


@router.post("/bulk-revoke")
async def bulk_revoke_api_keys(
    key_ids: List[str] = Body(...),
    reason: Optional[str] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Revoke multiple API keys at once
    """
    try:
        user_id = current_user.get("user_id")
        
        revoked = []
        failed = []
        
        for key_id in key_ids:
            try:
                success = await api_key_service.revoke_api_key(
                    user_id=user_id,
                    key_id=key_id,
                    reason=reason
                )
                if success:
                    revoked.append(key_id)
                else:
                    failed.append(key_id)
            except Exception:
                failed.append(key_id)
        
        logger.info(
            f"Bulk API key revocation",
            user_id=user_id,
            revoked_count=len(revoked),
            failed_count=len(failed)
        )
        
        return {
            "revoked": revoked,
            "failed": failed,
            "total_revoked": len(revoked),
            "total_failed": len(failed)
        }
    
    except Exception as e:
        logger.error(f"Failed to bulk revoke API keys: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke API keys")


# Middleware for API key authentication
@router.middleware("http")
async def api_key_auth_middleware(request: Request, call_next):
    """
    Middleware to validate API key for protected endpoints
    """
    # Skip validation for certain paths
    skip_paths = ["/api/v1/api-keys/validate", "/api/v1/api-keys/scopes"]
    if request.url.path in skip_paths:
        return await call_next(request)
    
    # Check for API key in header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        # Extract required scopes based on method and path
        required_scopes = []
        if request.method == "GET":
            required_scopes.append("read:*")
        elif request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            required_scopes.append("write:*")
        
        # Validate API key
        is_valid, key_data = await api_key_service.validate_api_key(
            api_key=api_key,
            required_scopes=required_scopes,
            ip_address=request.client.host,
            origin=request.headers.get("Origin")
        )
        
        if is_valid:
            # Add key data to request state
            request.state.api_key_data = key_data
        else:
            return HTTPException(status_code=401, detail="Invalid API key")
    
    return await call_next(request)