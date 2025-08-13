from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Optional, List
from enum import Enum
from datetime import datetime


class SSOProtocol(str, Enum):
    SAML2 = "saml2"
    OIDC = "oidc"


class SAMLBinding(str, Enum):
    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


class SSOProviderBase(BaseModel):
    """Base SSO provider model"""
    name: str = Field(..., description="Provider display name", min_length=1, max_length=100)
    protocol: SSOProtocol = Field(..., description="SSO protocol")
    enabled: bool = Field(default=True, description="Whether provider is enabled")
    domain: Optional[str] = Field(None, description="Email domain for auto-discovery")
    auto_provision: bool = Field(default=True, description="Auto-provision new users")
    organization_id: Optional[str] = Field(None, description="Target organization ID")
    
    @validator('domain')
    def validate_domain(cls, v):
        if v is not None:
            # Basic domain validation
            if not v or '.' not in v or v.startswith('.') or v.endswith('.'):
                raise ValueError('Invalid domain format')
        return v


class SAMLProviderConfig(BaseModel):
    """SAML specific configuration"""
    entity_id: str = Field(..., description="SAML Entity ID")
    sso_url: str = Field(..., description="SAML SSO URL")
    slo_url: Optional[str] = Field(None, description="SAML Single Logout URL")
    x509_cert: str = Field(..., description="X.509 certificate for signature validation")
    binding: SAMLBinding = Field(default=SAMLBinding.HTTP_REDIRECT, description="SAML binding method")
    
    @validator('sso_url', 'slo_url')
    def validate_urls(cls, v):
        if v is not None and not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class OIDCProviderConfig(BaseModel):
    """OIDC specific configuration"""
    issuer: str = Field(..., description="OIDC Issuer URL")
    authorization_endpoint: str = Field(..., description="OIDC Authorization endpoint")
    token_endpoint: str = Field(..., description="OIDC Token endpoint")
    userinfo_endpoint: Optional[str] = Field(None, description="OIDC UserInfo endpoint")
    jwks_uri: Optional[str] = Field(None, description="OIDC JWKS URI")
    client_id: str = Field(..., description="OIDC Client ID")
    client_secret: str = Field(..., description="OIDC Client Secret")
    
    @validator('issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri')
    def validate_urls(cls, v):
        if v is not None and not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class SSOProviderCreate(SSOProviderBase):
    """Create SSO provider request"""
    # SAML specific fields
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    slo_url: Optional[str] = None
    x509_cert: Optional[str] = None
    binding: Optional[SAMLBinding] = None
    
    # OIDC specific fields
    issuer: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    
    # Common settings
    attribute_mapping: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="Attribute mapping from SSO to local attributes"
    )
    role_mapping: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="Role mapping from SSO roles to local roles"
    )
    
    @validator('attribute_mapping', 'role_mapping')
    def validate_mappings(cls, v):
        if v is None:
            return {}
        return v
    
    def validate_protocol_fields(self):
        """Validate protocol-specific required fields"""
        if self.protocol == SSOProtocol.SAML2:
            required_fields = ['entity_id', 'sso_url', 'x509_cert']
            missing = [f for f in required_fields if not getattr(self, f)]
            if missing:
                raise ValueError(f"SAML provider missing required fields: {missing}")
        
        elif self.protocol == SSOProtocol.OIDC:
            required_fields = ['issuer', 'authorization_endpoint', 'token_endpoint', 'client_id', 'client_secret']
            missing = [f for f in required_fields if not getattr(self, f)]
            if missing:
                raise ValueError(f"OIDC provider missing required fields: {missing}")


class SSOProviderUpdate(BaseModel):
    """Update SSO provider request"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    enabled: Optional[bool] = None
    domain: Optional[str] = None
    auto_provision: Optional[bool] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    role_mapping: Optional[Dict[str, str]] = None
    organization_id: Optional[str] = None


class SSOProviderResponse(SSOProviderBase):
    """SSO provider response"""
    id: str = Field(..., description="Provider ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    endpoints: Dict[str, str] = Field(..., description="Provider endpoints")
    
    class Config:
        from_attributes = True


class SSOProviderList(BaseModel):
    """List of SSO providers"""
    providers: List[SSOProviderResponse]
    total: int


class SAMLLoginRequest(BaseModel):
    """SAML login initiation request"""
    relay_state: Optional[str] = Field(None, description="RelayState parameter")
    organization_id: Optional[str] = Field(None, description="Target organization ID")


class OIDCLoginRequest(BaseModel):
    """OIDC login initiation request"""
    redirect_uri: Optional[str] = Field(None, description="Custom redirect URI")
    organization_id: Optional[str] = Field(None, description="Target organization ID")
    scopes: Optional[List[str]] = Field(
        default=["openid", "email", "profile"],
        description="OIDC scopes to request"
    )
    
    @validator('scopes')
    def validate_scopes(cls, v):
        if v and 'openid' not in v:
            v.insert(0, 'openid')
        return v


class SSODiscoveryResponse(BaseModel):
    """SSO discovery response"""
    sso_available: bool = Field(..., description="Whether SSO is available for domain")
    provider_id: Optional[str] = Field(None, description="Provider ID if available")
    provider_name: Optional[str] = Field(None, description="Provider name if available")
    protocol: Optional[SSOProtocol] = Field(None, description="SSO protocol if available")
    login_url: Optional[str] = Field(None, description="Login URL if available")


class SSOAuthenticationResult(BaseModel):
    """SSO authentication result"""
    success: bool = Field(..., description="Whether authentication was successful")
    user: Dict[str, Any] = Field(..., description="User information")
    provider_id: str = Field(..., description="Provider ID")
    tokens: Optional[Dict[str, Any]] = Field(None, description="OAuth tokens (OIDC only)")
    relay_state: Optional[str] = Field(None, description="RelayState (SAML only)")


class SSOTestResult(BaseModel):
    """SSO provider test result"""
    provider_id: str = Field(..., description="Provider ID")
    protocol: SSOProtocol = Field(..., description="SSO protocol")
    enabled: bool = Field(..., description="Whether provider is enabled")
    configuration_valid: bool = Field(..., description="Whether configuration is valid")
    endpoints: Dict[str, str] = Field(..., description="Provider endpoints")
    warnings: List[str] = Field(default_factory=list, description="Configuration warnings")
    errors: List[str] = Field(default_factory=list, description="Configuration errors")


class SSOAnalytics(BaseModel):
    """SSO usage analytics"""
    period_days: int = Field(..., description="Analytics period in days")
    total_sso_logins: int = Field(..., description="Total SSO login attempts")
    successful_logins: int = Field(..., description="Successful SSO logins")
    failed_logins: int = Field(..., description="Failed SSO logins")
    success_rate: float = Field(..., description="Success rate percentage")
    providers_used: Dict[str, int] = Field(..., description="Usage count by provider")
    top_domains: Dict[str, int] = Field(..., description="Top domains using SSO")
    users_provisioned: int = Field(..., description="New users provisioned via SSO")
    generated_at: datetime = Field(..., description="Analytics generation timestamp")


class AttributeMapping(BaseModel):
    """SSO attribute mapping configuration"""
    email: str = Field(default="email", description="Email attribute mapping")
    first_name: str = Field(default="given_name", description="First name attribute mapping")
    last_name: str = Field(default="family_name", description="Last name attribute mapping")
    display_name: str = Field(default="name", description="Display name attribute mapping")
    groups: Optional[str] = Field(None, description="Groups attribute mapping")
    department: Optional[str] = Field(None, description="Department attribute mapping")
    job_title: Optional[str] = Field(None, description="Job title attribute mapping")
    phone: Optional[str] = Field(None, description="Phone number attribute mapping")
    
    def to_mapping_dict(self) -> Dict[str, str]:
        """Convert to dictionary format for storage"""
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "display_name": self.display_name,
            "groups": self.groups,
            "department": self.department,
            "job_title": self.job_title,
            "phone": self.phone
        }


class RoleMapping(BaseModel):
    """SSO role mapping configuration"""
    admin_roles: List[str] = Field(default_factory=list, description="SSO roles that map to admin")
    member_roles: List[str] = Field(default_factory=list, description="SSO roles that map to member")
    viewer_roles: List[str] = Field(default_factory=list, description="SSO roles that map to viewer")
    custom_mappings: Dict[str, str] = Field(default_factory=dict, description="Custom role mappings")
    
    def to_mapping_dict(self) -> Dict[str, str]:
        """Convert to dictionary format for storage"""
        mapping = {}
        
        # Add standard role mappings
        for role in self.admin_roles:
            mapping[role] = "admin"
        for role in self.member_roles:
            mapping[role] = "member"
        for role in self.viewer_roles:
            mapping[role] = "viewer"
        
        # Add custom mappings
        mapping.update(self.custom_mappings)
        
        return mapping


class SSOProviderStatus(BaseModel):
    """SSO provider status"""
    provider_id: str = Field(..., description="Provider ID")
    name: str = Field(..., description="Provider name")
    protocol: SSOProtocol = Field(..., description="SSO protocol")
    enabled: bool = Field(..., description="Whether provider is enabled")
    domain: Optional[str] = Field(None, description="Associated domain")
    last_used: Optional[datetime] = Field(None, description="Last usage timestamp")
    total_users: int = Field(default=0, description="Total users from this provider")
    active_users: int = Field(default=0, description="Active users from this provider")
    success_rate_30d: float = Field(default=0.0, description="30-day success rate")


class SSODashboard(BaseModel):
    """SSO management dashboard data"""
    total_providers: int = Field(..., description="Total configured providers")
    enabled_providers: int = Field(..., description="Enabled providers")
    total_sso_users: int = Field(..., description="Total SSO users")
    sso_logins_today: int = Field(..., description="SSO logins today")
    sso_logins_30d: int = Field(..., description="SSO logins in last 30 days")
    providers: List[SSOProviderStatus] = Field(..., description="Provider status list")
    recent_activity: List[Dict[str, Any]] = Field(..., description="Recent SSO activity")
    top_domains: List[Dict[str, Any]] = Field(..., description="Top domains using SSO")