from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, Body, HTTPException, Query
from datetime import datetime
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user
from app.services.rbac_service import rbac_service
from app.schemas.rbac import (
    RoleCreateRequest,
    RoleUpdateRequest,
    RoleAssignmentRequest,
    PermissionCheckRequest
)

router = APIRouter()
logger = structlog.get_logger()


# ============= Role Management Endpoints =============

@router.get("/roles")
async def list_roles(
    organization_id: Optional[str] = Query(None),
    include_system: bool = Query(True),
    assignable_only: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List all available roles
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:read", 
            organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to view roles")
        
        roles = await rbac_service.list_roles(
            organization_id=organization_id,
            include_system=include_system,
            assignable_only=assignable_only
        )
        
        return {
            "roles": roles,
            "total": len(roles),
            "organization_id": organization_id,
            "filters": {
                "include_system": include_system,
                "assignable_only": assignable_only
            }
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to list roles: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list roles")


@router.post("/roles")
async def create_role(
    request: RoleCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create a new custom role
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:create", 
            request.organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to create roles")
        
        result = await rbac_service.create_role(
            name=request.name,
            display_name=request.display_name,
            description=request.description,
            permissions=request.permissions,
            organization_id=request.organization_id,
            created_by=current_user["user_id"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to create role: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create role")


@router.get("/roles/{role_name}")
async def get_role(
    role_name: str,
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get a specific role by name
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:read", 
            organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to view roles")
        
        role = await rbac_service.get_role(role_name, organization_id)
        
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        return {
            "role": role.to_dict(),
            "organization_id": organization_id
        }
    
    except AuthorizationError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get role")


@router.put("/roles/{role_name}")
async def update_role(
    role_name: str,
    request: RoleUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update a custom role
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:update", 
            request.organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to update roles")
        
        updates = {}
        if request.display_name is not None:
            updates["display_name"] = request.display_name
        if request.description is not None:
            updates["description"] = request.description
        if request.permissions is not None:
            updates["permissions"] = request.permissions
        
        result = await rbac_service.update_role(
            name=role_name,
            updates=updates,
            organization_id=request.organization_id,
            updated_by=current_user["user_id"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to update role: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update role")


@router.delete("/roles/{role_name}")
async def delete_role(
    role_name: str,
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Delete a custom role
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:delete", 
            organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to delete roles")
        
        result = await rbac_service.delete_role(
            name=role_name,
            organization_id=organization_id,
            deleted_by=current_user["user_id"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to delete role: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete role")


# ============= User Role Assignment Endpoints =============

@router.post("/users/{user_id}/roles")
async def assign_role_to_user(
    user_id: str,
    request: RoleAssignmentRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Assign a role to a user
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:assign", 
            request.organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to assign roles")
        
        result = await rbac_service.assign_role_to_user(
            user_id=user_id,
            role_name=request.role_name,
            organization_id=request.organization_id,
            assigned_by=current_user["user_id"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to assign role: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to assign role")


@router.delete("/users/{user_id}/roles/{role_name}")
async def remove_role_from_user(
    user_id: str,
    role_name: str,
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove a role from a user
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:assign", 
            organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to remove roles")
        
        result = await rbac_service.remove_role_from_user(
            user_id=user_id,
            role_name=role_name,
            organization_id=organization_id,
            removed_by=current_user["user_id"]
        )
        
        return result
    
    except (ValidationError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to remove role: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to remove role")


@router.get("/users/{user_id}/roles")
async def get_user_roles(
    user_id: str,
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all roles assigned to a user
    """
    try:
        # Users can view their own roles, or admins can view any user's roles
        if user_id != current_user["user_id"]:
            has_permission = await rbac_service.check_permission(
                current_user["user_id"], 
                "roles:read", 
                organization_id
            )
            
            if not has_permission:
                raise AuthorizationError("Insufficient permissions to view user roles")
        
        roles = await rbac_service.get_user_roles(user_id, organization_id)
        
        return {
            "user_id": user_id,
            "roles": roles,
            "total_roles": len(roles),
            "organization_id": organization_id
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get user roles: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user roles")


@router.get("/users/{user_id}/permissions")
async def get_user_permissions(
    user_id: str,
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all permissions for a user
    """
    try:
        # Users can view their own permissions, or admins can view any user's permissions
        if user_id != current_user["user_id"]:
            has_permission = await rbac_service.check_permission(
                current_user["user_id"], 
                "roles:read", 
                organization_id
            )
            
            if not has_permission:
                raise AuthorizationError("Insufficient permissions to view user permissions")
        
        permissions = await rbac_service.get_user_permissions(user_id, organization_id)
        
        return {
            "user_id": user_id,
            "permissions": sorted(list(permissions)),
            "total_permissions": len(permissions),
            "organization_id": organization_id
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get user permissions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user permissions")


# ============= Permission Checking Endpoints =============

@router.post("/check-permission")
async def check_permission(
    request: PermissionCheckRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Check if current user has a specific permission
    """
    try:
        has_permission = await rbac_service.check_permission(
            current_user["user_id"],
            request.permission,
            request.organization_id,
            request.resource_id
        )
        
        return {
            "user_id": current_user["user_id"],
            "permission": request.permission,
            "has_permission": has_permission,
            "organization_id": request.organization_id,
            "resource_id": request.resource_id,
            "checked_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to check permission: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check permission")


@router.get("/permissions")
async def get_available_permissions(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all available permissions in the system
    """
    try:
        # Check if user can view permissions
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:read"
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to view available permissions")
        
        permissions = rbac_service.get_available_permissions()
        
        # Group permissions by resource
        grouped_permissions = {}
        for perm in permissions:
            resource = perm["resource"]
            if resource not in grouped_permissions:
                grouped_permissions[resource] = []
            grouped_permissions[resource].append(perm)
        
        return {
            "permissions": permissions,
            "grouped_permissions": grouped_permissions,
            "total_permissions": len(permissions)
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get available permissions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get permissions")


@router.get("/system-roles")
async def get_system_roles():
    """
    Get all system-defined roles
    """
    try:
        system_roles = rbac_service.get_system_roles()
        
        return {
            "system_roles": system_roles,
            "total_roles": len(system_roles)
        }
    
    except Exception as e:
        logger.error(f"Failed to get system roles: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get system roles")


# ============= RBAC Dashboard =============

@router.get("/dashboard")
async def get_rbac_dashboard(
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get RBAC dashboard with overview of roles, permissions, and assignments
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:read", 
            organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to view RBAC dashboard")
        
        # Get dashboard data
        all_roles = await rbac_service.list_roles(organization_id, include_system=True)
        user_roles = await rbac_service.get_user_roles(current_user["user_id"], organization_id)
        user_permissions = await rbac_service.get_user_permissions(current_user["user_id"], organization_id)
        available_permissions = rbac_service.get_available_permissions()
        
        # Calculate statistics
        system_roles = [r for r in all_roles if r.get("is_system", False)]
        custom_roles = [r for r in all_roles if not r.get("is_system", False)]
        assignable_roles = [r for r in all_roles if r.get("is_assignable", True)]
        
        # Security recommendations
        recommendations = []
        
        if len(user_roles) == 0:
            recommendations.append({
                "type": "warning",
                "message": "No roles assigned - default permissions may be limited",
                "action": "assign_role"
            })
        elif len(user_roles) > 5:
            recommendations.append({
                "type": "info",
                "message": "Multiple roles assigned - review for privilege escalation",
                "action": "review_roles"
            })
        
        if len(user_permissions) > 20:
            recommendations.append({
                "type": "security",
                "message": "High number of permissions - consider role consolidation",
                "action": "optimize_permissions"
            })
        
        return {
            "user_id": current_user["user_id"],
            "organization_id": organization_id,
            "statistics": {
                "total_roles": len(all_roles),
                "system_roles": len(system_roles),
                "custom_roles": len(custom_roles),
                "assignable_roles": len(assignable_roles),
                "total_permissions": len(available_permissions),
                "user_roles": len(user_roles),
                "user_permissions": len(user_permissions)
            },
            "user_roles": user_roles,
            "user_permissions": sorted(list(user_permissions)),
            "recent_activity": {
                "roles_created": 0,  # Would be fetched from audit logs
                "roles_assigned": 0,
                "permissions_checked": 0
            },
            "recommendations": recommendations,
            "rbac_score": min(100, max(0, 70 + len(user_roles) * 5 - len(user_permissions) * 0.5))
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get RBAC dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get RBAC dashboard")


# ============= Bulk Operations =============

@router.post("/bulk-assign")
async def bulk_assign_roles(
    user_ids: List[str] = Body(...),
    role_name: str = Body(...),
    organization_id: Optional[str] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Assign a role to multiple users
    """
    try:
        # Check permission
        has_permission = await rbac_service.check_permission(
            current_user["user_id"], 
            "roles:assign", 
            organization_id
        )
        
        if not has_permission:
            raise AuthorizationError("Insufficient permissions to assign roles")
        
        results = []
        
        for user_id in user_ids:
            try:
                result = await rbac_service.assign_role_to_user(
                    user_id=user_id,
                    role_name=role_name,
                    organization_id=organization_id,
                    assigned_by=current_user["user_id"]
                )
                results.append({
                    "user_id": user_id,
                    "success": True,
                    "status": "assigned"
                })
            except Exception as e:
                results.append({
                    "user_id": user_id,
                    "success": False,
                    "status": "failed",
                    "error": str(e)
                })
        
        successful_assignments = [r for r in results if r["success"]]
        failed_assignments = [r for r in results if not r["success"]]
        
        return {
            "total_attempted": len(user_ids),
            "successful": len(successful_assignments),
            "failed": len(failed_assignments),
            "role_name": role_name,
            "results": results,
            "message": f"Assigned role to {len(successful_assignments)} of {len(user_ids)} users"
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to bulk assign roles: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to bulk assign roles")