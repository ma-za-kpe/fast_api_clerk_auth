from typing import Dict, Any, Optional, Callable, List, Union
from functools import wraps
from fastapi import HTTPException, Depends
import structlog

from app.core.exceptions import AuthorizationError
from app.api.v1.deps import get_current_user
from app.services.rbac_service import rbac_service

logger = structlog.get_logger()


def require_permission(
    permission: str,
    organization_param: Optional[str] = None,
    resource_param: Optional[str] = None,
    allow_self: bool = False,
    self_param: str = "user_id"
):
    """
    Decorator to require specific permissions for endpoint access
    
    Args:
        permission: The required permission string (e.g., "users:read")
        organization_param: Name of the parameter containing organization_id
        resource_param: Name of the parameter containing resource_id
        allow_self: Allow access if user is accessing their own resource
        self_param: Parameter name to check for self-access
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependencies
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, dict) and "user_id" in value:
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            # Extract organization_id and resource_id from parameters
            organization_id = kwargs.get(organization_param) if organization_param else None
            resource_id = kwargs.get(resource_param) if resource_param else None
            
            # Check self-access
            if allow_self and self_param in kwargs:
                target_user_id = kwargs[self_param]
                if current_user["user_id"] == target_user_id:
                    logger.info(f"Self-access granted for {permission}", user_id=current_user["user_id"])
                    return await func(*args, **kwargs)
            
            # Check permission
            has_permission = await rbac_service.check_permission(
                user_id=current_user["user_id"],
                permission=permission,
                organization_id=organization_id,
                resource_id=resource_id
            )
            
            if not has_permission:
                logger.warning(
                    f"Permission denied: {permission}",
                    user_id=current_user["user_id"],
                    organization_id=organization_id,
                    resource_id=resource_id
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions: {permission}"
                )
            
            logger.info(
                f"Permission granted: {permission}",
                user_id=current_user["user_id"],
                organization_id=organization_id
            )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(
    permissions: List[str],
    organization_param: Optional[str] = None,
    resource_param: Optional[str] = None
):
    """
    Decorator to require any one of the specified permissions
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, dict) and "user_id" in value:
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            organization_id = kwargs.get(organization_param) if organization_param else None
            resource_id = kwargs.get(resource_param) if resource_param else None
            
            # Check if user has any of the required permissions
            for permission in permissions:
                has_permission = await rbac_service.check_permission(
                    user_id=current_user["user_id"],
                    permission=permission,
                    organization_id=organization_id,
                    resource_id=resource_id
                )
                
                if has_permission:
                    logger.info(
                        f"Permission granted: {permission}",
                        user_id=current_user["user_id"],
                        required_permissions=permissions
                    )
                    return await func(*args, **kwargs)
            
            logger.warning(
                "No required permissions found",
                user_id=current_user["user_id"],
                required_permissions=permissions
            )
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required: {', '.join(permissions)}"
            )
        return wrapper
    return decorator


def require_all_permissions(
    permissions: List[str],
    organization_param: Optional[str] = None,
    resource_param: Optional[str] = None
):
    """
    Decorator to require all specified permissions
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, dict) and "user_id" in value:
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            organization_id = kwargs.get(organization_param) if organization_param else None
            resource_id = kwargs.get(resource_param) if resource_param else None
            
            # Check that user has all required permissions
            missing_permissions = []
            for permission in permissions:
                has_permission = await rbac_service.check_permission(
                    user_id=current_user["user_id"],
                    permission=permission,
                    organization_id=organization_id,
                    resource_id=resource_id
                )
                
                if not has_permission:
                    missing_permissions.append(permission)
            
            if missing_permissions:
                logger.warning(
                    "Missing required permissions",
                    user_id=current_user["user_id"],
                    missing_permissions=missing_permissions
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Missing permissions: {', '.join(missing_permissions)}"
                )
            
            logger.info(
                "All permissions granted",
                user_id=current_user["user_id"],
                required_permissions=permissions
            )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(
    role: Union[str, List[str]],
    organization_param: Optional[str] = None
):
    """
    Decorator to require specific role(s)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, dict) and "user_id" in value:
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            organization_id = kwargs.get(organization_param) if organization_param else None
            
            # Get user roles
            user_roles = await rbac_service.get_user_roles(
                current_user["user_id"], 
                organization_id
            )
            
            user_role_names = [r["name"] for r in user_roles]
            required_roles = [role] if isinstance(role, str) else role
            
            # Check if user has any of the required roles
            has_required_role = any(r in user_role_names for r in required_roles)
            
            if not has_required_role:
                logger.warning(
                    "Role requirement not met",
                    user_id=current_user["user_id"],
                    user_roles=user_role_names,
                    required_roles=required_roles
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Required role not found. Required: {', '.join(required_roles)}"
                )
            
            logger.info(
                "Role requirement satisfied",
                user_id=current_user["user_id"],
                user_roles=user_role_names
            )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


async def check_user_permission(
    user_id: str,
    permission: str,
    organization_id: Optional[str] = None,
    resource_id: Optional[str] = None
) -> bool:
    """
    Utility function to check user permissions programmatically
    """
    try:
        return await rbac_service.check_permission(
            user_id=user_id,
            permission=permission,
            organization_id=organization_id,
            resource_id=resource_id
        )
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        return False


async def get_user_effective_permissions(
    user_id: str,
    organization_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get comprehensive permission information for a user
    """
    try:
        user_roles = await rbac_service.get_user_roles(user_id, organization_id)
        user_permissions = await rbac_service.get_user_permissions(user_id, organization_id)
        
        # Group permissions by resource
        grouped_permissions = {}
        for permission in user_permissions:
            if ':' in permission:
                resource, action = permission.split(':', 1)
                if resource not in grouped_permissions:
                    grouped_permissions[resource] = []
                grouped_permissions[resource].append(action)
        
        return {
            "user_id": user_id,
            "organization_id": organization_id,
            "roles": [r["name"] for r in user_roles],
            "permissions": sorted(list(user_permissions)),
            "grouped_permissions": grouped_permissions,
            "permission_count": len(user_permissions),
            "role_count": len(user_roles)
        }
    
    except Exception as e:
        logger.error(f"Error getting user permissions: {str(e)}")
        return {
            "user_id": user_id,
            "organization_id": organization_id,
            "roles": [],
            "permissions": [],
            "grouped_permissions": {},
            "permission_count": 0,
            "role_count": 0,
            "error": str(e)
        }


class PermissionChecker:
    """
    Context manager for checking multiple permissions
    """
    
    def __init__(self, user_id: str, organization_id: Optional[str] = None):
        self.user_id = user_id
        self.organization_id = organization_id
        self.permission_cache = {}
    
    async def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        if permission in self.permission_cache:
            return self.permission_cache[permission]
        
        result = await rbac_service.check_permission(
            user_id=self.user_id,
            permission=permission,
            organization_id=self.organization_id
        )
        
        self.permission_cache[permission] = result
        return result
    
    async def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if user has any of the specified permissions"""
        for permission in permissions:
            if await self.has_permission(permission):
                return True
        return False
    
    async def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if user has all specified permissions"""
        for permission in permissions:
            if not await self.has_permission(permission):
                return False
        return True
    
    def get_cached_results(self) -> Dict[str, bool]:
        """Get all cached permission check results"""
        return self.permission_cache.copy()