from typing import Optional, Dict, Any, List
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class UserResponse(BaseModel):
    user_id: str
    email: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    profile_image_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    email_verified: bool = False
    phone_verified: bool = False
    two_factor_enabled: bool = False
    public_metadata: Dict[str, Any] = Field(default_factory=dict)


class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    phone_number: Optional[str] = None


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    limit: int
    offset: int


class UserMetadataUpdate(BaseModel):
    public_metadata: Optional[Dict[str, Any]] = None
    private_metadata: Optional[Dict[str, Any]] = None
    unsafe_metadata: Optional[Dict[str, Any]] = None