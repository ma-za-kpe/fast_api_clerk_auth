from typing import Optional, Dict, Any, List
from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime


class SignUpRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    phone_number: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class SignUpResponse(BaseModel):
    user_id: str
    email: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    created_at: datetime
    email_verified: bool = False


class SignInRequest(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    password: str
    remember_me: bool = False
    
    @validator("username")
    def validate_identifier(cls, v, values):
        if not v and not values.get("email"):
            raise ValueError("Either email or username must be provided")
        return v


class DeviceVerificationRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class DeviceTrustRequest(BaseModel):
    duration_days: int = Field(30, ge=1, le=365)


class MFASetupRequest(BaseModel):
    method: str = Field(..., description="MFA method (totp, email, sms)")


class MFAVerifyRequest(BaseModel):
    method: str = Field(..., description="MFA method (totp, email)")
    code: str = Field(..., min_length=6)


class SignInResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    user_id: Optional[str] = None
    message: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    
    @validator("new_password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class EmailVerificationRequest(BaseModel):
    token: Optional[str] = None
    code: Optional[str] = None


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    message: Optional[str] = None


class MFASetupResponse(BaseModel):
    mfa_type: str
    secret: Optional[str] = None
    qr_code: Optional[str] = None
    backup_codes: Optional[List[str]] = None
    message: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    code: str
    mfa_type: str = "totp"