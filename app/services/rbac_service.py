from typing import Dict, Any, Optional, List, Set, Union
from datetime import datetime, timedelta
from enum import Enum
import structlog
import json

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthenticationError, AuthorizationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class PermissionScope(str, Enum):
    """Permission scopes for different resource types"""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    USER = "user"
    RESOURCE = "resource"


class PermissionAction(str, Enum):
    """Standard CRUD actions for permissions"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"
    ADMIN = "admin"


class SystemRole(str, Enum):
    """System-defined roles"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"
    GUEST = "guest"


class Permission:
    """Permission object representing a specific permission"""
    
    def __init__(
        self,
        name: str,
        resource: str,
        action: PermissionAction,
        scope: PermissionScope = PermissionScope.GLOBAL,
        description: Optional[str] = None,
        conditions: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.resource = resource
        self.action = action
        self.scope = scope
        self.description = description
        self.conditions = conditions or {}
        self.created_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "resource": self.resource,
            "action": self.action.value,
            "scope": self.scope.value,
            "description": self.description,
            "conditions": self.conditions,
            "created_at": self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Permission':
        return cls(
            name=data["name"],
            resource=data["resource"],
            action=PermissionAction(data["action"]),
            scope=PermissionScope(data["scope"]),
            description=data.get("description"),
            conditions=data.get("conditions", {})
        )


class Role:
    """Role object containing permissions and metadata"""
    
    def __init__(
        self,
        name: str,
        display_name: str,
        description: Optional[str] = None,
        permissions: Optional[List[Permission]] = None,
        is_system: bool = False,
        is_assignable: bool = True,
        organization_id: Optional[str] = None
    ):
        self.name = name
        self.display_name = display_name
        self.description = description
        self.permissions = permissions or []
        self.is_system = is_system
        self.is_assignable = is_assignable
        self.organization_id = organization_id
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def add_permission(self, permission: Permission):
        """Add a permission to this role"""
        if permission not in self.permissions:
            self.permissions.append(permission)
            self.updated_at = datetime.utcnow()
    
    def remove_permission(self, permission_name: str):
        """Remove a permission from this role"""
        self.permissions = [p for p in self.permissions if p.name != permission_name]
        self.updated_at = datetime.utcnow()
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if role has a specific permission"""
        return any(p.name == permission_name for p in self.permissions)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "permissions": [p.to_dict() for p in self.permissions],
            "is_system": self.is_system,
            "is_assignable": self.is_assignable,
            "organization_id": self.organization_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Role':
        role = cls(
            name=data["name"],
            display_name=data["display_name"],
            description=data.get("description"),
            is_system=data.get("is_system", False),
            is_assignable=data.get("is_assignable", True),
            organization_id=data.get("organization_id")
        )
        role.permissions = [Permission.from_dict(p) for p in data.get("permissions", [])]
        if data.get("created_at"):
            role.created_at = datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
        if data.get("updated_at"):
            role.updated_at = datetime.fromisoformat(data["updated_at"].replace('Z', '+00:00'))
        return role


class RBACService:
    """
    Role-Based Access Control service
    """
    
    def __init__(self):
        self.clerk_client = None
        self._default_permissions = self._initialize_default_permissions()
        self._system_roles = self._initialize_system_roles()
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            from app.core.clerk import get_clerk_client
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    def _initialize_default_permissions(self) -> Dict[str, Permission]:
        """Initialize default system permissions"""
        permissions = {}
        
        # User management permissions
        permissions["users:create"] = Permission("users:create", "users", PermissionAction.CREATE, description="Create new users")
        permissions["users:read"] = Permission("users:read", "users", PermissionAction.READ, description="View user information")
        permissions["users:update"] = Permission("users:update", "users", PermissionAction.UPDATE, description="Update user information")
        permissions["users:delete"] = Permission("users:delete", "users", PermissionAction.DELETE, description="Delete users")
        permissions["users:manage"] = Permission("users:manage", "users", PermissionAction.MANAGE, description="Full user management")
        
        # Organization permissions
        permissions["orgs:create"] = Permission("orgs:create", "organizations", PermissionAction.CREATE, description="Create organizations")
        permissions["orgs:read"] = Permission("orgs:read", "organizations", PermissionAction.READ, description="View organization information")
        permissions["orgs:update"] = Permission("orgs:update", "organizations", PermissionAction.UPDATE, description="Update organization settings")
        permissions["orgs:delete"] = Permission("orgs:delete", "organizations", PermissionAction.DELETE, description="Delete organizations")
        permissions["orgs:manage"] = Permission("orgs:manage", "organizations", PermissionAction.MANAGE, description="Full organization management")
        
        # Role and permission management
        permissions["roles:create"] = Permission("roles:create", "roles", PermissionAction.CREATE, description="Create custom roles")
        permissions["roles:read"] = Permission("roles:read", "roles", PermissionAction.READ, description="View roles and permissions")
        permissions["roles:update"] = Permission("roles:update", "roles", PermissionAction.UPDATE, description="Update roles and permissions")
        permissions["roles:delete"] = Permission("roles:delete", "roles", PermissionAction.DELETE, description="Delete custom roles")
        permissions["roles:assign"] = Permission("roles:assign", "roles", PermissionAction.EXECUTE, description="Assign roles to users")
        
        # Session management
        permissions["sessions:read"] = Permission("sessions:read", "sessions", PermissionAction.READ, description="View user sessions")
        permissions["sessions:delete"] = Permission("sessions:delete", "sessions", PermissionAction.DELETE, description="Terminate user sessions")
        permissions["sessions:manage"] = Permission("sessions:manage", "sessions", PermissionAction.MANAGE, description="Full session management")
        
        # Security permissions
        permissions["security:audit"] = Permission("security:audit", "security", PermissionAction.READ, description="View audit logs")
        permissions["security:manage"] = Permission("security:manage", "security", PermissionAction.MANAGE, description="Manage security settings")
        
        # API and webhook permissions
        permissions["api:read"] = Permission("api:read", "api", PermissionAction.READ, description="Access API endpoints")
        permissions["api:manage"] = Permission("api:manage", "api", PermissionAction.MANAGE, description="Manage API settings")
        permissions["webhooks:read"] = Permission("webhooks:read", "webhooks", PermissionAction.READ, description="View webhook configurations")
        permissions["webhooks:manage"] = Permission("webhooks:manage", "webhooks", PermissionAction.MANAGE, description="Manage webhook configurations")
        
        return permissions
    
    def _initialize_system_roles(self) -> Dict[str, Role]:
        """Initialize default system roles"""
        roles = {}
        
        # Super Admin - all permissions
        super_admin = Role(
            name=SystemRole.SUPER_ADMIN.value,
            display_name="Super Administrator",
            description="Full system access with all permissions",
            is_system=True,
            is_assignable=False
        )
        for permission in self._default_permissions.values():
            super_admin.add_permission(permission)
        roles[SystemRole.SUPER_ADMIN.value] = super_admin
        
        # Admin - most permissions except super admin functions
        admin = Role(
            name=SystemRole.ADMIN.value,
            display_name="Administrator",
            description="Administrative access with most permissions",
            is_system=True
        )
        admin_permissions = [
            "users:create", "users:read", "users:update", "users:delete",
            "orgs:create", "orgs:read", "orgs:update", "orgs:delete",
            "roles:read", "roles:assign",
            "sessions:read", "sessions:delete",
            "security:audit", "api:read", "webhooks:read"
        ]
        for perm_name in admin_permissions:
            if perm_name in self._default_permissions:
                admin.add_permission(self._default_permissions[perm_name])
        roles[SystemRole.ADMIN.value] = admin
        
        # Moderator - limited admin functions
        moderator = Role(
            name=SystemRole.MODERATOR.value,
            display_name="Moderator",
            description="Moderate users and content",
            is_system=True
        )
        moderator_permissions = [
            "users:read", "users:update",
            "orgs:read", "sessions:read",
            "security:audit", "api:read"
        ]
        for perm_name in moderator_permissions:
            if perm_name in self._default_permissions:
                moderator.add_permission(self._default_permissions[perm_name])
        roles[SystemRole.MODERATOR.value] = moderator
        
        # User - basic permissions
        user = Role(
            name=SystemRole.USER.value,
            display_name="User",
            description="Standard user permissions",
            is_system=True
        )
        user_permissions = ["users:read", "orgs:read", "api:read"]
        for perm_name in user_permissions:
            if perm_name in self._default_permissions:
                user.add_permission(self._default_permissions[perm_name])
        roles[SystemRole.USER.value] = user
        
        # Guest - minimal permissions
        guest = Role(
            name=SystemRole.GUEST.value,
            display_name="Guest",
            description="Minimal guest access",
            is_system=True
        )
        guest_permissions = ["api:read"]
        for perm_name in guest_permissions:
            if perm_name in self._default_permissions:
                guest.add_permission(self._default_permissions[perm_name])
        roles[SystemRole.GUEST.value] = guest
        
        return roles
    
    # ============= Role Management =============
    
    async def create_role(
        self,
        name: str,
        display_name: str,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        organization_id: Optional[str] = None,
        created_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new custom role"""
        try:
            # Validate role name
            if name in self._system_roles:
                raise ValidationError("Cannot create role with system role name")
            
            # Check if role already exists
            existing_role = await self.get_role(name, organization_id)
            if existing_role:
                raise ValidationError(f"Role '{name}' already exists")
            
            # Create role
            role = Role(
                name=name,
                display_name=display_name,
                description=description,
                organization_id=organization_id
            )
            
            # Add permissions
            if permissions:
                for perm_name in permissions:
                    if perm_name in self._default_permissions:
                        role.add_permission(self._default_permissions[perm_name])
                    else:
                        logger.warning(f"Unknown permission: {perm_name}")
            
            # Store role
            await self._store_role(role)
            
            # Log role creation
            logger.info(f"Role created: {name}", created_by=created_by, organization_id=organization_id)
            
            return {
                "created": True,
                "role": role.to_dict(),
                "message": f"Role '{display_name}' created successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to create role: {str(e)}")
            raise ValidationError("Failed to create role")
    
    async def get_role(self, name: str, organization_id: Optional[str] = None) -> Optional[Role]:
        """Get a role by name"""
        try:
            # Check system roles first
            if name in self._system_roles:
                return self._system_roles[name]
            
            # Check cached custom roles
            cache_key = f"rbac_role:{organization_id or 'global'}:{name}"
            cached_data = await cache_service.get(cache_key)
            
            if cached_data:
                return Role.from_dict(cached_data)
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get role {name}: {str(e)}")
            return None
    
    async def list_roles(
        self,
        organization_id: Optional[str] = None,
        include_system: bool = True,
        assignable_only: bool = False
    ) -> List[Dict[str, Any]]:
        """List all available roles"""
        try:
            roles = []
            
            # Add system roles
            if include_system:
                for role in self._system_roles.values():
                    if not assignable_only or role.is_assignable:
                        roles.append(role.to_dict())
            
            # Add custom roles
            custom_roles = await self._list_custom_roles(organization_id)
            roles.extend(custom_roles)
            
            return roles
        
        except Exception as e:
            logger.error(f"Failed to list roles: {str(e)}")
            return []
    
    async def update_role(
        self,
        name: str,
        updates: Dict[str, Any],
        organization_id: Optional[str] = None,
        updated_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a custom role"""
        try:
            # Get existing role
            role = await self.get_role(name, organization_id)
            if not role:
                raise ValidationError("Role not found")
            
            if role.is_system:
                raise ValidationError("Cannot modify system roles")
            
            # Update role properties
            if "display_name" in updates:
                role.display_name = updates["display_name"]
            if "description" in updates:
                role.description = updates["description"]
            
            # Update permissions
            if "permissions" in updates:
                role.permissions = []
                for perm_name in updates["permissions"]:
                    if perm_name in self._default_permissions:
                        role.add_permission(self._default_permissions[perm_name])
            
            role.updated_at = datetime.utcnow()
            
            # Store updated role
            await self._store_role(role)
            
            logger.info(f"Role updated: {name}", updated_by=updated_by)
            
            return {
                "updated": True,
                "role": role.to_dict(),
                "message": f"Role '{role.display_name}' updated successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to update role: {str(e)}")
            raise ValidationError("Failed to update role")
    
    async def delete_role(
        self,
        name: str,
        organization_id: Optional[str] = None,
        deleted_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Delete a custom role"""
        try:
            # Get role
            role = await self.get_role(name, organization_id)
            if not role:
                raise ValidationError("Role not found")
            
            if role.is_system:
                raise ValidationError("Cannot delete system roles")
            
            # Check if role is assigned to users
            assigned_users = await self._get_users_with_role(name, organization_id)
            if assigned_users:
                raise ValidationError(f"Cannot delete role - assigned to {len(assigned_users)} users")
            
            # Delete role
            await self._delete_role(name, organization_id)
            
            logger.info(f"Role deleted: {name}", deleted_by=deleted_by)
            
            return {
                "deleted": True,
                "message": f"Role '{role.display_name}' deleted successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to delete role: {str(e)}")
            raise ValidationError("Failed to delete role")
    
    # ============= User Role Assignment =============
    
    async def assign_role_to_user(
        self,
        user_id: str,
        role_name: str,
        organization_id: Optional[str] = None,
        assigned_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Assign a role to a user"""
        try:
            # Validate role exists
            role = await self.get_role(role_name, organization_id)
            if not role:
                raise ValidationError("Role not found")
            
            if not role.is_assignable:
                raise ValidationError("Role is not assignable")
            
            # Get current user roles
            user_roles = await self.get_user_roles(user_id, organization_id)
            
            # Check if user already has this role
            if any(r["name"] == role_name for r in user_roles):
                raise ValidationError("User already has this role")
            
            # Add role to user
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            metadata_key = "roles" if not organization_id else f"org_roles_{organization_id}"
            current_metadata = user.private_metadata or {}
            current_roles = current_metadata.get(metadata_key, [])
            
            if role_name not in current_roles:
                current_roles.append(role_name)
                
                await clerk_client.update_user(
                    user_id=user_id,
                    private_metadata={
                        **current_metadata,
                        metadata_key: current_roles,
                        f"{metadata_key}_updated": datetime.utcnow().isoformat()
                    }
                )
            
            # Clear user permissions cache
            await self._clear_user_permissions_cache(user_id)
            
            logger.info(f"Role assigned: {role_name} to user {user_id}", assigned_by=assigned_by)
            
            return {
                "assigned": True,
                "user_id": user_id,
                "role": role_name,
                "message": f"Role '{role.display_name}' assigned successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to assign role: {str(e)}")
            raise ValidationError("Failed to assign role")
    
    async def remove_role_from_user(
        self,
        user_id: str,
        role_name: str,
        organization_id: Optional[str] = None,
        removed_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Remove a role from a user"""
        try:
            # Get user
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            metadata_key = "roles" if not organization_id else f"org_roles_{organization_id}"
            current_metadata = user.private_metadata or {}
            current_roles = current_metadata.get(metadata_key, [])
            
            if role_name not in current_roles:
                raise ValidationError("User does not have this role")
            
            # Remove role
            current_roles.remove(role_name)
            
            await clerk_client.update_user(
                user_id=user_id,
                private_metadata={
                    **current_metadata,
                    metadata_key: current_roles,
                    f"{metadata_key}_updated": datetime.utcnow().isoformat()
                }
            )
            
            # Clear user permissions cache
            await self._clear_user_permissions_cache(user_id)
            
            logger.info(f"Role removed: {role_name} from user {user_id}", removed_by=removed_by)
            
            return {
                "removed": True,
                "user_id": user_id,
                "role": role_name,
                "message": f"Role '{role_name}' removed successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove role: {str(e)}")
            raise ValidationError("Failed to remove role")
    
    async def get_user_roles(
        self,
        user_id: str,
        organization_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all roles assigned to a user"""
        try:
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            metadata_key = "roles" if not organization_id else f"org_roles_{organization_id}"
            user_roles = user.private_metadata.get(metadata_key, []) if user.private_metadata else []
            
            # If no roles assigned, assign default user role
            if not user_roles and not organization_id:
                user_roles = [SystemRole.USER.value]
            
            # Get role details
            roles = []
            for role_name in user_roles:
                role = await self.get_role(role_name, organization_id)
                if role:
                    roles.append(role.to_dict())
            
            return roles
        
        except Exception as e:
            logger.error(f"Failed to get user roles: {str(e)}")
            return []
    
    # ============= Permission Checking =============
    
    async def check_permission(
        self,
        user_id: str,
        permission: str,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> bool:
        """Check if user has a specific permission"""
        try:
            user_permissions = await self.get_user_permissions(user_id, organization_id)
            return permission in user_permissions
        
        except Exception as e:
            logger.error(f"Failed to check permission: {str(e)}")
            return False
    
    async def get_user_permissions(
        self,
        user_id: str,
        organization_id: Optional[str] = None
    ) -> Set[str]:
        """Get all permissions for a user"""
        try:
            # Check cache first
            cache_key = f"rbac_user_permissions:{user_id}:{organization_id or 'global'}"
            cached_permissions = await cache_service.get(cache_key)
            
            if cached_permissions:
                return set(cached_permissions)
            
            # Get user roles
            user_roles = await self.get_user_roles(user_id, organization_id)
            
            # Collect all permissions
            permissions = set()
            for role_data in user_roles:
                for perm_data in role_data.get("permissions", []):
                    permissions.add(perm_data["name"])
            
            # Cache permissions
            await cache_service.set(cache_key, list(permissions), expire=3600)  # 1 hour
            
            return permissions
        
        except Exception as e:
            logger.error(f"Failed to get user permissions: {str(e)}")
            return set()
    
    # ============= Helper Methods =============
    
    async def _store_role(self, role: Role):
        """Store a role in cache"""
        cache_key = f"rbac_role:{role.organization_id or 'global'}:{role.name}"
        await cache_service.set(cache_key, role.to_dict(), expire=86400)  # 24 hours
    
    async def _delete_role(self, name: str, organization_id: Optional[str] = None):
        """Delete a role from cache"""
        cache_key = f"rbac_role:{organization_id or 'global'}:{name}"
        await cache_service.delete(cache_key)
    
    async def _list_custom_roles(self, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List custom roles from cache"""
        # This would typically query a database
        # For now, return empty list as custom roles are stored individually
        return []
    
    async def _get_users_with_role(self, role_name: str, organization_id: Optional[str] = None) -> List[str]:
        """Get list of users with a specific role"""
        # This would typically query the user database
        # For now, return empty list
        return []
    
    async def _clear_user_permissions_cache(self, user_id: str):
        """Clear cached permissions for a user"""
        # Clear both global and organization-specific caches
        await cache_service.delete(f"rbac_user_permissions:{user_id}:global")
        # Note: In a real implementation, you'd clear all org-specific caches too
    
    def get_available_permissions(self) -> List[Dict[str, Any]]:
        """Get all available permissions"""
        return [p.to_dict() for p in self._default_permissions.values()]
    
    def get_system_roles(self) -> List[Dict[str, Any]]:
        """Get all system roles"""
        return [r.to_dict() for r in self._system_roles.values()]


# Singleton instance
rbac_service = RBACService()