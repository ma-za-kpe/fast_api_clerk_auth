"""
Workspace/Teams Schemas
Pydantic models for workspace API requests and responses
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, validator


class WorkspaceSettingsSchema(BaseModel):
    """Workspace settings schema"""
    allow_guest_access: Optional[bool] = False
    require_2fa: Optional[bool] = False
    allow_public_projects: Optional[bool] = False
    max_members: Optional[int] = Field(100, ge=1, le=10000)
    max_projects: Optional[int] = Field(50, ge=1, le=1000)
    max_storage_gb: Optional[int] = Field(100, ge=1, le=10000)
    allowed_domains: Optional[List[str]] = []
    blocked_domains: Optional[List[str]] = []
    default_member_role: Optional[str] = "member"
    auto_join_domains: Optional[List[str]] = []
    enable_sso: Optional[bool] = False
    sso_provider: Optional[str] = None
    data_retention_days: Optional[int] = Field(365, ge=1, le=3650)
    audit_log_retention_days: Optional[int] = Field(90, ge=1, le=365)
    custom_branding: Optional[Dict[str, Any]] = {}


class WorkspaceFeaturesSchema(BaseModel):
    """Workspace features schema"""
    analytics: Optional[bool] = True
    advanced_permissions: Optional[bool] = True
    custom_roles: Optional[bool] = False
    api_access: Optional[bool] = True
    webhooks: Optional[bool] = True
    integrations: Optional[bool] = True
    bulk_operations: Optional[bool] = True
    export_data: Optional[bool] = True
    custom_fields: Optional[bool] = False
    automation: Optional[bool] = False
    ai_features: Optional[bool] = False


class WorkspaceCreate(BaseModel):
    """Create workspace request"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    settings: Optional[Dict[str, Any]] = None
    features: Optional[Dict[str, Any]] = None
    
    @validator('name')
    def validate_name(cls, v):
        if not v or v.strip() == "":
            raise ValueError("Workspace name cannot be empty")
        return v.strip()


class WorkspaceUpdate(BaseModel):
    """Update workspace request"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    settings: Optional[Dict[str, Any]] = None
    features: Optional[Dict[str, Any]] = None
    
    @validator('name')
    def validate_name(cls, v):
        if v is not None and v.strip() == "":
            raise ValueError("Workspace name cannot be empty")
        return v.strip() if v else v


class WorkspaceResponse(BaseModel):
    """Workspace response"""
    id: str
    name: str
    slug: str
    description: Optional[str]
    owner_id: str
    settings: Dict[str, Any]
    features: Dict[str, Any]
    status: str
    member_count: Optional[int] = None
    user_role: Optional[str] = None
    created_at: str
    updated_at: Optional[str]
    
    class Config:
        orm_mode = True


class WorkspaceMemberResponse(BaseModel):
    """Workspace member response"""
    id: str
    user_id: str
    role: str
    permissions: List[str]
    joined_at: str
    invited_by: Optional[str]
    
    class Config:
        orm_mode = True


class WorkspaceInvitationCreate(BaseModel):
    """Create invitation request"""
    email: EmailStr
    role: str = Field("member", regex="^(owner|admin|member|viewer|guest)$")
    message: Optional[str] = Field(None, max_length=500)


class WorkspaceInvitationResponse(BaseModel):
    """Invitation response"""
    id: str
    workspace_id: str
    email: str
    role: str
    status: str
    expires_at: str
    
    class Config:
        orm_mode = True


class MemberRoleUpdate(BaseModel):
    """Update member role request"""
    role: str = Field(..., regex="^(owner|admin|member|viewer|guest)$")
    permissions: Optional[List[str]] = None


class WorkspaceQuotaResponse(BaseModel):
    """Workspace quota response"""
    members_used: int
    members_limit: int
    projects_used: int
    projects_limit: int
    storage_used_gb: float
    storage_limit_gb: float
    api_calls_used: int
    api_calls_limit: int
    seats_used: int
    seats_limit: int
    
    @property
    def members_percentage(self) -> float:
        return (self.members_used / self.members_limit * 100) if self.members_limit > 0 else 0
    
    @property
    def storage_percentage(self) -> float:
        return (self.storage_used_gb / self.storage_limit_gb * 100) if self.storage_limit_gb > 0 else 0
    
    @property
    def api_calls_percentage(self) -> float:
        return (self.api_calls_used / self.api_calls_limit * 100) if self.api_calls_limit > 0 else 0