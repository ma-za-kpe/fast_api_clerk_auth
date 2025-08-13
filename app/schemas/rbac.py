from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class PermissionScope(str, Enum):
    GLOBAL = "global"
    ORGANIZATION = "organization"
    USER = "user"
    RESOURCE = "resource"


class PermissionAction(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"
    ADMIN = "admin"


class SystemRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"
    GUEST = "guest"


class PermissionSchema(BaseModel):
    name: str
    resource: str
    action: PermissionAction
    scope: PermissionScope = PermissionScope.GLOBAL
    description: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    class Config:
        use_enum_values = True


class RoleSchema(BaseModel):
    name: str
    display_name: str
    description: Optional[str] = None
    permissions: List[PermissionSchema] = []
    is_system: bool = False
    is_assignable: bool = True
    organization_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        use_enum_values = True


class RoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50, regex=r'^[a-zA-Z0-9_-]+$')
    display_name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    permissions: Optional[List[str]] = Field(default=[])
    organization_id: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        # Prevent using system role names
        system_roles = [role.value for role in SystemRole]
        if v.lower() in system_roles:
            raise ValueError('Cannot use system role names')
        return v.lower()

    @validator('permissions')
    def validate_permissions(cls, v):
        if v and len(v) > 50:  # Reasonable limit
            raise ValueError('Too many permissions specified')
        return v


class RoleUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    permissions: Optional[List[str]] = None
    organization_id: Optional[str] = None

    @validator('permissions')
    def validate_permissions(cls, v):
        if v is not None and len(v) > 50:
            raise ValueError('Too many permissions specified')
        return v


class RoleAssignmentRequest(BaseModel):
    role_name: str = Field(..., min_length=1)
    organization_id: Optional[str] = None


class RoleAssignmentResponse(BaseModel):
    assigned: bool
    user_id: str
    role: str
    message: str
    assigned_at: Optional[datetime] = None


class PermissionCheckRequest(BaseModel):
    permission: str = Field(..., min_length=1)
    organization_id: Optional[str] = None
    resource_id: Optional[str] = None


class PermissionCheckResponse(BaseModel):
    user_id: str
    permission: str
    has_permission: bool
    organization_id: Optional[str] = None
    resource_id: Optional[str] = None
    checked_at: datetime


class UserRolesResponse(BaseModel):
    user_id: str
    roles: List[RoleSchema]
    total_roles: int
    organization_id: Optional[str] = None


class UserPermissionsResponse(BaseModel):
    user_id: str
    permissions: List[str]
    total_permissions: int
    organization_id: Optional[str] = None


class RolesListResponse(BaseModel):
    roles: List[RoleSchema]
    total: int
    organization_id: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None


class AvailablePermissionsResponse(BaseModel):
    permissions: List[PermissionSchema]
    grouped_permissions: Dict[str, List[PermissionSchema]]
    total_permissions: int


class SystemRolesResponse(BaseModel):
    system_roles: List[RoleSchema]
    total_roles: int


class RBACDashboardResponse(BaseModel):
    user_id: str
    organization_id: Optional[str] = None
    statistics: Dict[str, int]
    user_roles: List[RoleSchema]
    user_permissions: List[str]
    recent_activity: Dict[str, int]
    recommendations: List[Dict[str, str]]
    rbac_score: float


class BulkRoleAssignmentRequest(BaseModel):
    user_ids: List[str] = Field(..., min_items=1, max_items=100)
    role_name: str = Field(..., min_length=1)
    organization_id: Optional[str] = None

    @validator('user_ids')
    def validate_user_ids(cls, v):
        if len(set(v)) != len(v):
            raise ValueError('Duplicate user IDs not allowed')
        return v


class BulkRoleAssignmentResponse(BaseModel):
    total_attempted: int
    successful: int
    failed: int
    role_name: str
    results: List[Dict[str, Any]]
    message: str


class RoleCreateResponse(BaseModel):
    created: bool
    role: RoleSchema
    message: str


class RoleUpdateResponse(BaseModel):
    updated: bool
    role: RoleSchema
    message: str


class RoleDeleteResponse(BaseModel):
    deleted: bool
    message: str


class ResourcePermission(BaseModel):
    """Permission for a specific resource"""
    resource_type: str
    resource_id: str
    permissions: List[str]
    granted_at: datetime
    granted_by: Optional[str] = None
    expires_at: Optional[datetime] = None


class ConditionalPermission(BaseModel):
    """Permission with conditions"""
    permission: str
    conditions: Dict[str, Any]
    description: Optional[str] = None


class RoleTemplate(BaseModel):
    """Template for creating roles"""
    name: str
    display_name: str
    description: str
    category: str  # e.g., "admin", "user", "custom"
    permissions: List[str]
    is_default: bool = False


class PermissionGroup(BaseModel):
    """Group of related permissions"""
    name: str
    display_name: str
    description: str
    permissions: List[str]
    icon: Optional[str] = None
    color: Optional[str] = None


class RoleInheritance(BaseModel):
    """Role inheritance configuration"""
    child_role: str
    parent_role: str
    organization_id: Optional[str] = None
    created_at: datetime


class AccessAuditEntry(BaseModel):
    """Audit entry for access control"""
    user_id: str
    action: str
    resource: str
    permission_checked: str
    result: bool  # granted or denied
    timestamp: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None