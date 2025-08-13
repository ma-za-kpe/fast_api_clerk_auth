from typing import Optional, Dict, Any
from fastapi import Depends, Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog

from app.core.clerk import get_clerk_client
from app.core.exceptions import AuthenticationError, AuthorizationError

logger = structlog.get_logger()
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Get current authenticated user from request
    """
    if not hasattr(request.state, "is_authenticated") or not request.state.is_authenticated:
        raise AuthenticationError("Not authenticated")
    
    return {
        "user_id": request.state.user_id,
        "session_id": request.state.session_id,
        "org_id": request.state.org_id,
        "auth_payload": request.state.auth_payload
    }


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """
    Get current user if authenticated, otherwise return None
    """
    if hasattr(request.state, "is_authenticated") and request.state.is_authenticated:
        return {
            "user_id": request.state.user_id,
            "session_id": request.state.session_id,
            "org_id": request.state.org_id,
            "auth_payload": request.state.auth_payload
        }
    return None


async def require_organization(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> str:
    """
    Require user to be part of an organization
    """
    org_id = current_user.get("org_id")
    if not org_id:
        raise AuthorizationError("Organization membership required")
    return org_id


async def require_admin(
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
) -> Dict[str, Any]:
    """
    Require user to have admin privileges
    """
    user_id = current_user.get("user_id")
    
    try:
        user = await clerk_client.get_user(user_id)
        
        is_admin = user.private_metadata.get("is_admin", False)
        
        if not is_admin:
            raise AuthorizationError("Admin privileges required")
        
        return current_user
    
    except Exception as e:
        logger.error("Failed to check admin privileges", error=str(e))
        raise AuthorizationError("Failed to verify admin privileges")


async def require_organization_admin(
    current_user: Dict[str, Any] = Depends(get_current_user),
    org_id: str = Depends(require_organization),
    clerk_client = Depends(get_clerk_client)
) -> Dict[str, Any]:
    """
    Require user to be an admin of their organization
    """
    try:
        members = await clerk_client.list_organization_members(org_id)
        
        user_id = current_user.get("user_id")
        for member in members:
            if member.user_id == user_id and member.role in ["admin", "owner"]:
                return current_user
        
        raise AuthorizationError("Organization admin privileges required")
    
    except Exception as e:
        logger.error("Failed to check organization admin privileges", error=str(e))
        raise AuthorizationError("Failed to verify organization admin privileges")


class PermissionChecker:
    """
    Dependency to check for specific permissions
    """
    
    def __init__(self, required_permissions: list):
        self.required_permissions = required_permissions
    
    async def __call__(
        self,
        current_user: Dict[str, Any] = Depends(get_current_user),
        clerk_client = Depends(get_clerk_client)
    ) -> Dict[str, Any]:
        """
        Check if user has required permissions
        """
        user_id = current_user.get("user_id")
        
        try:
            user = await clerk_client.get_user(user_id)
            
            user_permissions = user.public_metadata.get("permissions", [])
            
            for permission in self.required_permissions:
                if permission not in user_permissions:
                    raise AuthorizationError(f"Missing required permission: {permission}")
            
            return current_user
        
        except AuthorizationError:
            raise
        except Exception as e:
            logger.error("Failed to check permissions", error=str(e))
            raise AuthorizationError("Failed to verify permissions")


def require_permissions(*permissions):
    """
    Decorator to require specific permissions
    """
    return Depends(PermissionChecker(list(permissions)))