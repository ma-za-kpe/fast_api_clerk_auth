from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class MagicLinkRequest(BaseModel):
    email: EmailStr
    redirect_url: Optional[str] = None


class MagicLinkVerify(BaseModel):
    token: str = Field(..., min_length=1)


class OTPRequest(BaseModel):
    identifier: str = Field(..., description="Email or phone number")
    type: str = Field("email", regex="^(email|sms)$")


class OTPVerify(BaseModel):
    identifier: str = Field(..., description="Email or phone number")
    code: str = Field(..., min_length=6, max_length=6)


class WebAuthnRegisterRequest(BaseModel):
    credential_id: str
    public_key: str
    attestation_object: Optional[str] = None
    client_data_json: Optional[str] = None


class WebAuthnLoginRequest(BaseModel):
    credential_id: str
    authenticator_data: str
    signature: str
    client_data_json: str
    user_handle: Optional[str] = None


class DeviceTrustRequest(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=100)
    user_agent: str
    platform: str
    screen_resolution: Optional[str] = None
    ip_address: Optional[str] = None