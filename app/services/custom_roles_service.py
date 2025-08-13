"""
Custom Roles Service
Implements custom role creation with granular permissions and hierarchies
"""

from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import uuid

from sqlalchemy import select, and_, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.cache import cache_service
from app.services.audit_service import audit_service
from app.core.exceptions import (
    BadRequestError,
    NotFoundError,
    ForbiddenError,
    ConflictError
)


class PermissionScope(str, Enum):
    """Permission scopes"""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    WORKSPACE = "workspace"
    PROJECT = "project"
    RESOURCE = "resource"


class PermissionAction(str, Enum):
    """Permission actions"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    MANAGE = "manage"
    ADMIN = "admin"


@dataclass
class Permission:
    """Permission definition"""
    id: str
    name: str
    resource: str
    action: str
    scope: str
    description: Optional[str] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CustomRole:
    """Custom role definition"""
    id: str
    name: str
    organization_id: str
    description: Optional[str]
    permissions: List[Permission]
    parent_role_id: Optional[str]  # For role hierarchy
    priority: int  # Higher priority overrides lower
    is_system: bool
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: Optional[datetime]
    metadata: Dict[str, Any]


class CustomRolesService:
    """Service for managing custom roles and permissions"""
    
    def __init__(self):
        self.cache_ttl = 3600
        self.max_roles_per_org = 50
        self.max_permissions_per_role = 100
        self.max_hierarchy_depth = 5
        
        # System roles that cannot be deleted
        self.system_roles = ["owner", "admin", "member", "viewer", "guest"]
        
        # Default permissions for system roles
        self.system_permissions = self._initialize_system_permissions()
    
    def _initialize_system_permissions(self) -> Dict[str, List[Permission]]:
        """Initialize default system permissions"""
        return {
            "owner": [
                Permission(
                    id="perm_owner_all",
                    name="Full Access",
                    resource="*",
                    action="*",
                    scope=PermissionScope.ORGANIZATION,
                    description="Complete access to all resources"
                )
            ],
            "admin": [
                Permission(
                    id="perm_admin_manage",
                    name="Admin Management",
                    resource="*",
                    action=PermissionAction.MANAGE,
                    scope=PermissionScope.ORGANIZATION,
                    description="Manage all resources except ownership"
                ),
                Permission(
                    id="perm_admin_users",
                    name="User Management",
                    resource="users",
                    action="*",
                    scope=PermissionScope.ORGANIZATION
                ),
                Permission(
                    id="perm_admin_roles",
                    name="Role Management",
                    resource="roles",
                    action="*",
                    scope=PermissionScope.ORGANIZATION
                )
            ],
            "member": [
                Permission(
                    id="perm_member_read",
                    name="Read Access",
                    resource="*",
                    action=PermissionAction.READ,
                    scope=PermissionScope.WORKSPACE
                ),
                Permission(
                    id="perm_member_create",
                    name="Create Resources",
                    resource="projects",
                    action=PermissionAction.CREATE,
                    scope=PermissionScope.WORKSPACE
                ),
                Permission(
                    id="perm_member_update_own",
                    name="Update Own Resources",
                    resource="*",
                    action=PermissionAction.UPDATE,
                    scope=PermissionScope.RESOURCE,
                    conditions={"owner": "self"}
                )
            ],
            "viewer": [
                Permission(
                    id="perm_viewer_read",
                    name="Read Only Access",
                    resource="*",
                    action=PermissionAction.READ,
                    scope=PermissionScope.WORKSPACE
                )
            ],
            "guest": [
                Permission(
                    id="perm_guest_limited",
                    name="Limited Read Access",
                    resource="public",
                    action=PermissionAction.READ,
                    scope=PermissionScope.RESOURCE
                )
            ]
        }
    
    async def create_custom_role(
        self,
        organization_id: str,
        name: str,
        created_by: str,
        description: Optional[str] = None,
        permissions: Optional[List[Dict[str, Any]]] = None,
        parent_role_id: Optional[str] = None,
        priority: int = 0
    ) -> CustomRole:
        """Create a custom role for an organization"""
        # Check role limit
        existing_count = await self._count_organization_roles(organization_id)
        if existing_count >= self.max_roles_per_org:
            raise BadRequestError(f"Maximum roles limit ({self.max_roles_per_org}) reached")
        
        # Check name uniqueness
        if await self._role_exists(organization_id, name):
            raise ConflictError(f"Role with name '{name}' already exists")
        
        # Validate parent role if specified
        if parent_role_id:
            parent_role = await self.get_role(parent_role_id)
            if not parent_role or parent_role.organization_id != organization_id:
                raise NotFoundError("Parent role not found")
            
            # Check hierarchy depth
            depth = await self._get_hierarchy_depth(parent_role_id)
            if depth >= self.max_hierarchy_depth:
                raise BadRequestError(f"Maximum hierarchy depth ({self.max_hierarchy_depth}) exceeded")
        
        # Parse and validate permissions
        role_permissions = []
        if permissions:
            if len(permissions) > self.max_permissions_per_role:
                raise BadRequestError(f"Maximum permissions ({self.max_permissions_per_role}) exceeded")
            
            for perm_data in permissions:
                permission = Permission(
                    id=f"perm_{uuid.uuid4().hex[:8]}",
                    name=perm_data.get("name", ""),
                    resource=perm_data.get("resource", "*"),
                    action=perm_data.get("action", "read"),
                    scope=perm_data.get("scope", PermissionScope.RESOURCE),
                    description=perm_data.get("description"),
                    conditions=perm_data.get("conditions", {}),
                    metadata=perm_data.get("metadata", {})
                )
                role_permissions.append(permission)
        
        # Create role
        role = CustomRole(
            id=str(uuid.uuid4()),
            name=name,
            organization_id=organization_id,
            description=description,
            permissions=role_permissions,
            parent_role_id=parent_role_id,
            priority=priority,
            is_system=False,
            is_active=True,
            created_by=created_by,
            created_at=datetime.utcnow(),
            updated_at=None,
            metadata={}
        )
        
        # Store role
        await self._store_role(role)
        
        # Clear cache
        await self._clear_organization_cache(organization_id)
        
        # Log activity
        await audit_service.log_audit_event(
            user_id=created_by,
            action="role.created",
            resource_type="role",
            resource_id=role.id,
            details={
                "role_name": name,
                "organization_id": organization_id,
                "permissions_count": len(role_permissions)
            }
        )
        
        return role
    
    async def update_role(
        self,
        role_id: str,
        updated_by: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[Dict[str, Any]]] = None,
        priority: Optional[int] = None,
        is_active: Optional[bool] = None
    ) -> CustomRole:
        """Update a custom role"""
        role = await self.get_role(role_id)
        if not role:
            raise NotFoundError("Role not found")
        
        if role.is_system:
            raise ForbiddenError("Cannot modify system roles")
        
        # Update fields
        if name and name != role.name:
            if await self._role_exists(role.organization_id, name):
                raise ConflictError(f"Role with name '{name}' already exists")
            role.name = name
        
        if description is not None:
            role.description = description
        
        if priority is not None:
            role.priority = priority
        
        if is_active is not None:
            role.is_active = is_active
        
        # Update permissions if provided
        if permissions is not None:
            if len(permissions) > self.max_permissions_per_role:
                raise BadRequestError(f"Maximum permissions ({self.max_permissions_per_role}) exceeded")
            
            role_permissions = []
            for perm_data in permissions:
                permission = Permission(
                    id=perm_data.get("id", f"perm_{uuid.uuid4().hex[:8]}"),
                    name=perm_data.get("name", ""),
                    resource=perm_data.get("resource", "*"),
                    action=perm_data.get("action", "read"),
                    scope=perm_data.get("scope", PermissionScope.RESOURCE),
                    description=perm_data.get("description"),
                    conditions=perm_data.get("conditions", {}),
                    metadata=perm_data.get("metadata", {})
                )
                role_permissions.append(permission)
            
            role.permissions = role_permissions
        
        role.updated_at = datetime.utcnow()
        
        # Update in storage
        await self._update_role(role)
        
        # Clear cache
        await self._clear_organization_cache(role.organization_id)
        
        # Log activity
        await audit_service.log_audit_event(
            user_id=updated_by,
            action="role.updated",
            resource_type="role",
            resource_id=role_id,
            details={"changes": {"name": name, "is_active": is_active}}
        )
        
        return role
    
    async def delete_role(
        self,
        role_id: str,
        deleted_by: str,
        reassign_to_role_id: Optional[str] = None
    ) -> Dict[str, str]:
        """Delete a custom role"""
        role = await self.get_role(role_id)
        if not role:
            raise NotFoundError("Role not found")
        
        if role.is_system:
            raise ForbiddenError("Cannot delete system roles")
        
        # Check if role has members
        member_count = await self._count_role_members(role_id)
        if member_count > 0:
            if not reassign_to_role_id:
                raise BadRequestError(
                    f"Role has {member_count} members. Provide reassign_to_role_id"
                )
            
            # Reassign members
            await self._reassign_role_members(role_id, reassign_to_role_id)
        
        # Check for child roles
        child_roles = await self._get_child_roles(role_id)
        if child_roles:
            # Update child roles to have no parent
            for child_role in child_roles:
                child_role.parent_role_id = None
                await self._update_role(child_role)
        
        # Delete role
        await self._delete_role(role_id)
        
        # Clear cache
        await self._clear_organization_cache(role.organization_id)
        
        # Log activity
        await audit_service.log_audit_event(
            user_id=deleted_by,
            action="role.deleted",
            resource_type="role",
            resource_id=role_id,
            details={
                "role_name": role.name,
                "reassigned_to": reassign_to_role_id
            }
        )
        
        return {"message": "Role deleted successfully"}
    
    async def get_role(self, role_id: str) -> Optional[CustomRole]:
        """Get a role by ID"""
        # Check cache
        cache_key = f"role:{role_id}"
        cached = await cache_service.get(cache_key)
        if cached:
            return CustomRole(**cached)
        
        # Get from storage
        role_data = await self._get_role_from_storage(role_id)
        if role_data:
            role = CustomRole(**role_data)
            
            # Cache result
            await cache_service.set(cache_key, role.__dict__, ttl=self.cache_ttl)
            
            return role
        
        return None
    
    async def get_organization_roles(
        self,
        organization_id: str,
        include_system: bool = True,
        include_inactive: bool = False
    ) -> List[CustomRole]:
        """Get all roles for an organization"""
        # Check cache
        cache_key = f"org_roles:{organization_id}:{include_system}:{include_inactive}"
        cached = await cache_service.get(cache_key)
        if cached:
            return [CustomRole(**r) for r in cached]
        
        # Get from storage
        roles = await self._get_organization_roles_from_storage(
            organization_id,
            include_system,
            include_inactive
        )
        
        # Cache result
        await cache_service.set(cache_key, [r.__dict__ for r in roles], ttl=self.cache_ttl)
        
        return roles
    
    async def get_effective_permissions(
        self,
        user_id: str,
        organization_id: str,
        role_ids: List[str]
    ) -> Set[Permission]:
        """Get effective permissions for a user based on their roles"""
        # Check cache
        cache_key = f"user_perms:{user_id}:{organization_id}"
        cached = await cache_service.get(cache_key)
        if cached:
            return {Permission(**p) for p in cached}
        
        all_permissions = set()
        
        for role_id in role_ids:
            # Get role and its hierarchy
            role_permissions = await self._get_role_hierarchy_permissions(role_id)
            all_permissions.update(role_permissions)
        
        # Apply permission precedence rules
        effective_permissions = self._apply_permission_precedence(all_permissions)
        
        # Cache result
        await cache_service.set(
            cache_key,
            [p.__dict__ for p in effective_permissions],
            ttl=300  # Shorter TTL for permissions
        )
        
        return effective_permissions
    
    async def check_permission(
        self,
        user_id: str,
        organization_id: str,
        role_ids: List[str],
        resource: str,
        action: str,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Check if user has specific permission"""
        permissions = await self.get_effective_permissions(
            user_id,
            organization_id,
            role_ids
        )
        
        for permission in permissions:
            if self._permission_matches(permission, resource, action, context):
                return True
        
        return False
    
    async def clone_role(
        self,
        role_id: str,
        new_name: str,
        cloned_by: str,
        organization_id: Optional[str] = None
    ) -> CustomRole:
        """Clone an existing role"""
        source_role = await self.get_role(role_id)
        if not source_role:
            raise NotFoundError("Source role not found")
        
        # Use same org or specified one
        target_org = organization_id or source_role.organization_id
        
        # Create new role with cloned permissions
        return await self.create_custom_role(
            organization_id=target_org,
            name=new_name,
            created_by=cloned_by,
            description=f"Cloned from {source_role.name}",
            permissions=[p.__dict__ for p in source_role.permissions],
            priority=source_role.priority
        )
    
    async def get_role_hierarchy(self, role_id: str) -> Dict[str, Any]:
        """Get complete role hierarchy"""
        role = await self.get_role(role_id)
        if not role:
            raise NotFoundError("Role not found")
        
        # Get ancestors
        ancestors = await self._get_role_ancestors(role_id)
        
        # Get descendants
        descendants = await self._get_role_descendants(role_id)
        
        return {
            "role": role.__dict__,
            "ancestors": [a.__dict__ for a in ancestors],
            "descendants": [d.__dict__ for d in descendants],
            "depth": len(ancestors),
            "total_permissions": len(await self._get_role_hierarchy_permissions(role_id))
        }
    
    def _permission_matches(
        self,
        permission: Permission,
        resource: str,
        action: str,
        context: Optional[Dict[str, Any]]
    ) -> bool:
        """Check if permission matches request"""
        # Check resource match (support wildcards)
        if permission.resource != "*" and permission.resource != resource:
            return False
        
        # Check action match (support wildcards)
        if permission.action != "*" and permission.action != action:
            return False
        
        # Check conditions
        if permission.conditions and context:
            for key, value in permission.conditions.items():
                if key not in context or context[key] != value:
                    return False
        
        return True
    
    def _apply_permission_precedence(
        self,
        permissions: Set[Permission]
    ) -> Set[Permission]:
        """Apply precedence rules to permissions"""
        # Sort by priority and scope
        sorted_perms = sorted(
            permissions,
            key=lambda p: (
                p.scope == PermissionScope.GLOBAL,
                p.scope == PermissionScope.ORGANIZATION,
                p.scope == PermissionScope.WORKSPACE,
                p.action == PermissionAction.ADMIN,
                p.action == PermissionAction.MANAGE
            ),
            reverse=True
        )
        
        # Remove duplicates keeping higher precedence
        effective = set()
        seen_resources = set()
        
        for perm in sorted_perms:
            resource_key = f"{perm.resource}:{perm.action}"
            if resource_key not in seen_resources:
                effective.add(perm)
                seen_resources.add(resource_key)
        
        return effective
    
    async def _get_role_hierarchy_permissions(self, role_id: str) -> Set[Permission]:
        """Get all permissions including inherited ones"""
        role = await self.get_role(role_id)
        if not role:
            return set()
        
        all_permissions = set(role.permissions)
        
        # Get parent permissions recursively
        if role.parent_role_id:
            parent_permissions = await self._get_role_hierarchy_permissions(
                role.parent_role_id
            )
            all_permissions.update(parent_permissions)
        
        return all_permissions
    
    async def _get_role_ancestors(self, role_id: str) -> List[CustomRole]:
        """Get all ancestor roles"""
        ancestors = []
        current_role = await self.get_role(role_id)
        
        while current_role and current_role.parent_role_id:
            parent = await self.get_role(current_role.parent_role_id)
            if parent:
                ancestors.append(parent)
                current_role = parent
            else:
                break
        
        return ancestors
    
    async def _get_role_descendants(self, role_id: str) -> List[CustomRole]:
        """Get all descendant roles"""
        descendants = []
        
        # Get direct children
        child_roles = await self._get_child_roles(role_id)
        
        for child in child_roles:
            descendants.append(child)
            # Recursively get their descendants
            child_descendants = await self._get_role_descendants(child.id)
            descendants.extend(child_descendants)
        
        return descendants
    
    async def _get_hierarchy_depth(self, role_id: str) -> int:
        """Get depth of role in hierarchy"""
        ancestors = await self._get_role_ancestors(role_id)
        return len(ancestors)
    
    async def _role_exists(self, organization_id: str, name: str) -> bool:
        """Check if role name exists in organization"""
        roles = await self.get_organization_roles(organization_id)
        return any(r.name.lower() == name.lower() for r in roles)
    
    async def _count_organization_roles(self, organization_id: str) -> int:
        """Count roles in organization"""
        roles = await self.get_organization_roles(organization_id, include_system=False)
        return len(roles)
    
    async def _count_role_members(self, role_id: str) -> int:
        """Count members with this role"""
        # This would query actual member assignments
        return 0
    
    async def _reassign_role_members(self, from_role_id: str, to_role_id: str):
        """Reassign members from one role to another"""
        # This would update member role assignments
        pass
    
    async def _get_child_roles(self, parent_role_id: str) -> List[CustomRole]:
        """Get direct child roles"""
        # This would query roles with parent_role_id
        return []
    
    async def _clear_organization_cache(self, organization_id: str):
        """Clear organization-related cache"""
        pattern = f"org_roles:{organization_id}:*"
        await cache_service.delete_pattern(pattern)
    
    # Storage methods (would be actual database operations)
    async def _store_role(self, role: CustomRole):
        """Store role in database"""
        cache_key = f"role:{role.id}"
        await cache_service.set(cache_key, role.__dict__)
    
    async def _update_role(self, role: CustomRole):
        """Update role in database"""
        cache_key = f"role:{role.id}"
        await cache_service.set(cache_key, role.__dict__)
    
    async def _delete_role(self, role_id: str):
        """Delete role from database"""
        cache_key = f"role:{role_id}"
        await cache_service.delete(cache_key)
    
    async def _get_role_from_storage(self, role_id: str) -> Optional[Dict[str, Any]]:
        """Get role from database"""
        cache_key = f"role:{role_id}"
        return await cache_service.get(cache_key)
    
    async def _get_organization_roles_from_storage(
        self,
        organization_id: str,
        include_system: bool,
        include_inactive: bool
    ) -> List[CustomRole]:
        """Get organization roles from database"""
        # This would query actual database
        # For now, return system roles
        roles = []
        
        if include_system:
            for role_name in self.system_roles:
                roles.append(CustomRole(
                    id=f"role_{role_name}",
                    name=role_name.capitalize(),
                    organization_id=organization_id,
                    description=f"System {role_name} role",
                    permissions=self.system_permissions.get(role_name, []),
                    parent_role_id=None,
                    priority=100 if role_name == "owner" else 50,
                    is_system=True,
                    is_active=True,
                    created_by="system",
                    created_at=datetime.utcnow(),
                    updated_at=None,
                    metadata={}
                ))
        
        return roles


# Create singleton instance
custom_roles_service = CustomRolesService()