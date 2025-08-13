from typing import Optional, Dict, Any, List
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: Optional[str] = Field(None, min_length=1, max_length=50)
    public_metadata: Optional[Dict[str, Any]] = None
    private_metadata: Optional[Dict[str, Any]] = None


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    slug: Optional[str] = Field(None, min_length=1, max_length=50)
    image_url: Optional[str] = None
    public_metadata: Optional[Dict[str, Any]] = None
    private_metadata: Optional[Dict[str, Any]] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: Optional[str] = None
    image_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    members_count: int
    max_allowed_memberships: int
    public_metadata: Dict[str, Any] = Field(default_factory=dict)
    user_role: Optional[str] = None


class OrganizationListResponse(BaseModel):
    organizations: List[OrganizationResponse]
    total: int
    limit: int
    offset: int


class OrganizationMemberResponse(BaseModel):
    user_id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    profile_image_url: Optional[str] = None
    role: str
    joined_at: datetime
    public_metadata: Dict[str, Any] = Field(default_factory=dict)


class OrganizationInviteRequest(BaseModel):
    email: EmailStr
    role: str = Field("member", regex="^(member|admin)$")
    redirect_url: Optional[str] = None
    message: Optional[str] = None


class OrganizationInviteResponse(BaseModel):
    id: str
    email: str
    organization_id: str
    status: str
    created_at: datetime
    expires_at: Optional[datetime] = None


class OrganizationDomainRequest(BaseModel):
    domain: str = Field(..., regex="^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}$")
    verification_method: str = Field("dns", regex="^(dns|email)$")
    auto_join_enabled: bool = True


class OrganizationRoleUpdate(BaseModel):
    role: str = Field(..., regex="^(member|admin|owner)$")


class OrganizationTransferOwnership(BaseModel):
    new_owner_id: str
    confirmation: str = Field(..., description="Type 'TRANSFER' to confirm")