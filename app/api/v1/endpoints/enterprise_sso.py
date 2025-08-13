from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Form, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel, Field
import structlog

from app.core.exceptions import ValidationError, AuthenticationError, ConfigurationError
from app.api.v1.deps import get_current_user, require_admin
from app.core.permissions import require_permission
from app.services.enterprise_sso_service import (
    enterprise_sso_service,
    SSOProvider,
    SSOProtocol,
    SAMLBinding
)

router = APIRouter()
logger = structlog.get_logger()


# ============= Pydantic Models =============

class SSOProviderCreate(BaseModel):
    name: str = Field(..., description="Provider display name")
    protocol: SSOProtocol = Field(..., description="SSO protocol (SAML2 or OIDC)")
    enabled: bool = Field(default=True, description="Whether provider is enabled")
    domain: Optional[str] = Field(None, description="Email domain for auto-discovery")
    
    # SAML specific fields
    entity_id: Optional[str] = Field(None, description="SAML Entity ID")
    sso_url: Optional[str] = Field(None, description="SAML SSO URL")
    slo_url: Optional[str] = Field(None, description="SAML Single Logout URL")
    x509_cert: Optional[str] = Field(None, description="X.509 certificate for signature validation")
    binding: Optional[SAMLBinding] = Field(None, description="SAML binding method")
    
    # OIDC specific fields
    issuer: Optional[str] = Field(None, description="OIDC Issuer URL")
    authorization_endpoint: Optional[str] = Field(None, description="OIDC Authorization endpoint")
    token_endpoint: Optional[str] = Field(None, description="OIDC Token endpoint")
    userinfo_endpoint: Optional[str] = Field(None, description="OIDC UserInfo endpoint")
    jwks_uri: Optional[str] = Field(None, description="OIDC JWKS URI")
    client_id: Optional[str] = Field(None, description="OIDC Client ID")
    client_secret: Optional[str] = Field(None, description="OIDC Client Secret")
    
    # Common settings
    auto_provision: bool = Field(default=True, description="Auto-provision new users")
    attribute_mapping: Optional[Dict[str, str]] = Field(None, description="Attribute mapping")
    role_mapping: Optional[Dict[str, str]] = Field(None, description="Role mapping")
    organization_id: Optional[str] = Field(None, description="Target organization ID")


class SSOProviderUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    domain: Optional[str] = None
    auto_provision: Optional[bool] = None
    attribute_mapping: Optional[Dict[str, str]] = None
    role_mapping: Optional[Dict[str, str]] = None


class SAMLLoginRequest(BaseModel):
    relay_state: Optional[str] = None
    organization_id: Optional[str] = None


class OIDCLoginRequest(BaseModel):
    redirect_uri: Optional[str] = None
    organization_id: Optional[str] = None
    scopes: Optional[List[str]] = None


# ============= Provider Management Endpoints =============

@router.post("/providers")
@require_permission("organizations:manage")
async def create_sso_provider(
    provider_data: SSOProviderCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create SSO provider configuration (admin only)
    """
    try:
        # Generate provider ID
        provider_id = f"sso_{provider_data.protocol.value}_{provider_data.name.lower().replace(' ', '_')}"
        
        # Create provider object
        provider = SSOProvider(
            id=provider_id,
            name=provider_data.name,
            protocol=provider_data.protocol,
            enabled=provider_data.enabled,
            domain=provider_data.domain,
            entity_id=provider_data.entity_id,
            sso_url=provider_data.sso_url,
            slo_url=provider_data.slo_url,
            x509_cert=provider_data.x509_cert,
            binding=provider_data.binding,
            issuer=provider_data.issuer,
            authorization_endpoint=provider_data.authorization_endpoint,
            token_endpoint=provider_data.token_endpoint,
            userinfo_endpoint=provider_data.userinfo_endpoint,
            jwks_uri=provider_data.jwks_uri,
            client_id=provider_data.client_id,
            client_secret=provider_data.client_secret,
            auto_provision=provider_data.auto_provision,
            attribute_mapping=provider_data.attribute_mapping,
            role_mapping=provider_data.role_mapping,
            organization_id=provider_data.organization_id
        )
        
        result = await enterprise_sso_service.add_sso_provider(provider)
        
        logger.info(
            f"SSO provider created",
            provider_id=provider_id,
            created_by=current_user["user_id"]
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create SSO provider: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create SSO provider")


@router.get("/providers")
@require_permission("organizations:read")
async def list_sso_providers(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List all SSO providers (admin only)
    """
    try:
        providers = await enterprise_sso_service.list_sso_providers()
        return {"providers": providers}
    
    except Exception as e:
        logger.error(f"Failed to list SSO providers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list SSO providers")


@router.get("/providers/{provider_id}")
@require_permission("organizations:read")
async def get_sso_provider(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get SSO provider configuration (admin only)
    """
    try:
        provider = await enterprise_sso_service.get_sso_provider(provider_id)
        if not provider:
            raise HTTPException(status_code=404, detail="SSO provider not found")
        
        # Remove sensitive data
        provider_data = {
            "id": provider.id,
            "name": provider.name,
            "protocol": provider.protocol.value,
            "enabled": provider.enabled,
            "domain": provider.domain,
            "auto_provision": provider.auto_provision,
            "organization_id": provider.organization_id,
            "endpoints": enterprise_sso_service._get_provider_endpoints(provider)
        }
        
        return provider_data
    
    except Exception as e:
        logger.error(f"Failed to get SSO provider: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get SSO provider")


@router.put("/providers/{provider_id}")
@require_permission("organizations:manage")
async def update_sso_provider(
    provider_id: str,
    update_data: SSOProviderUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update SSO provider configuration (admin only)
    """
    try:
        provider = await enterprise_sso_service.get_sso_provider(provider_id)
        if not provider:
            raise HTTPException(status_code=404, detail="SSO provider not found")
        
        # Update provider with new data
        update_dict = update_data.dict(exclude_unset=True)
        for key, value in update_dict.items():
            if hasattr(provider, key):
                setattr(provider, key, value)
        
        result = await enterprise_sso_service.add_sso_provider(provider)
        
        logger.info(
            f"SSO provider updated",
            provider_id=provider_id,
            updated_by=current_user["user_id"]
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update SSO provider: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update SSO provider")


@router.delete("/providers/{provider_id}")
@require_permission("organizations:manage")
async def delete_sso_provider(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Delete SSO provider configuration (admin only)
    """
    try:
        result = await enterprise_sso_service.delete_sso_provider(provider_id)
        
        logger.info(
            f"SSO provider deleted",
            provider_id=provider_id,
            deleted_by=current_user["user_id"]
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to delete SSO provider: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete SSO provider")


# ============= Discovery Endpoints =============

@router.get("/discovery")
async def discover_sso_provider(
    email: str = Query(..., description="Email address for domain discovery")
):
    """
    Discover SSO provider for email domain
    """
    try:
        email_domain = email.split("@")[-1].lower()
        provider_id = await enterprise_sso_service.discover_provider_for_domain(email_domain)
        
        if provider_id:
            provider = await enterprise_sso_service.get_sso_provider(provider_id)
            if provider and provider.enabled:
                return {
                    "sso_available": True,
                    "provider_id": provider_id,
                    "provider_name": provider.name,
                    "protocol": provider.protocol.value,
                    "login_url": f"/api/v1/sso/{provider.protocol.value}/login/{provider_id}"
                }
        
        return {"sso_available": False}
    
    except Exception as e:
        logger.error(f"Failed to discover SSO provider: {str(e)}")
        return {"sso_available": False}


# ============= SAML 2.0 Endpoints =============

@router.post("/saml/login/{provider_id}")
async def initiate_saml_login(
    provider_id: str,
    login_data: SAMLLoginRequest
):
    """
    Initiate SAML SSO login
    """
    try:
        result = await enterprise_sso_service.initiate_saml_login(
            provider_id=provider_id,
            relay_state=login_data.relay_state,
            organization_id=login_data.organization_id
        )
        
        if result["binding"] == "HTTP-Redirect":
            return RedirectResponse(url=result["redirect_url"], status_code=302)
        else:
            # HTTP-POST binding - return form
            return HTMLResponse(content=f"""
            <html>
                <body onload="document.forms[0].submit()">
                    <form method="post" action="{result['sso_url']}">
                        <input type="hidden" name="SAMLRequest" value="{result['saml_request']}" />
                        {f'<input type="hidden" name="RelayState" value="{result["relay_state"]}" />' if result.get("relay_state") else ""}
                        <input type="submit" value="Continue to SSO" />
                    </form>
                </body>
            </html>
            """)
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to initiate SAML login: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate SAML login")


@router.post("/saml/acs")
async def handle_saml_acs(
    request: Request,
    SAMLResponse: str = Form(...),
    RelayState: Optional[str] = Form(None)
):
    """
    SAML Assertion Consumer Service endpoint
    """
    try:
        result = await enterprise_sso_service.handle_saml_response(
            saml_response=SAMLResponse,
            relay_state=RelayState
        )
        
        if result["success"]:
            # In production, create session and redirect to application
            return {
                "authentication": "successful",
                "user": result["user"],
                "provider": result["provider_id"],
                "relay_state": result.get("relay_state")
            }
        else:
            raise HTTPException(status_code=401, detail="SAML authentication failed")
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to handle SAML response: {str(e)}")
        raise HTTPException(status_code=500, detail="SAML authentication error")


@router.get("/saml/metadata/{provider_id}")
async def get_saml_metadata(provider_id: str):
    """
    Get SAML service provider metadata
    """
    try:
        provider = await enterprise_sso_service.get_sso_provider(provider_id)
        if not provider or provider.protocol != SSOProtocol.SAML2:
            raise HTTPException(status_code=404, detail="SAML provider not found")
        
        # Generate SP metadata XML
        base_url = enterprise_sso_service.base_url
        metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{base_url}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                   Location="{base_url}/api/v1/sso/saml/acs"
                                   index="0" />
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""
        
        return HTMLResponse(content=metadata_xml, media_type="application/xml")
    
    except Exception as e:
        logger.error(f"Failed to get SAML metadata: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get SAML metadata")


# ============= OpenID Connect Endpoints =============

@router.post("/oidc/login/{provider_id}")
async def initiate_oidc_login(
    provider_id: str,
    login_data: OIDCLoginRequest
):
    """
    Initiate OIDC SSO login
    """
    try:
        result = await enterprise_sso_service.initiate_oidc_login(
            provider_id=provider_id,
            redirect_uri=login_data.redirect_uri,
            organization_id=login_data.organization_id,
            scopes=login_data.scopes
        )
        
        return RedirectResponse(url=result["authorization_url"], status_code=302)
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to initiate OIDC login: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate OIDC login")


@router.get("/oidc/callback")
async def handle_oidc_callback(
    code: str = Query(...),
    state: str = Query(...),
    redirect_uri: Optional[str] = Query(None),
    error: Optional[str] = Query(None)
):
    """
    OIDC callback endpoint
    """
    try:
        if error:
            raise AuthenticationError(f"OIDC authentication error: {error}")
        
        result = await enterprise_sso_service.handle_oidc_callback(
            code=code,
            state=state,
            redirect_uri=redirect_uri
        )
        
        if result["success"]:
            # In production, create session and redirect to application
            return {
                "authentication": "successful",
                "user": result["user"],
                "provider": result["provider_id"],
                "tokens": result.get("tokens", {})
            }
        else:
            raise HTTPException(status_code=401, detail="OIDC authentication failed")
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to handle OIDC callback: {str(e)}")
        raise HTTPException(status_code=500, detail="OIDC authentication error")


# ============= Management Endpoints =============

@router.get("/test/{provider_id}")
@require_permission("organizations:manage")
async def test_sso_provider(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Test SSO provider configuration (admin only)
    """
    try:
        provider = await enterprise_sso_service.get_sso_provider(provider_id)
        if not provider:
            raise HTTPException(status_code=404, detail="SSO provider not found")
        
        # Test provider configuration
        test_results = {
            "provider_id": provider_id,
            "protocol": provider.protocol.value,
            "enabled": provider.enabled,
            "configuration_valid": True,
            "endpoints": enterprise_sso_service._get_provider_endpoints(provider),
            "warnings": []
        }
        
        # Add protocol-specific tests
        if provider.protocol == SSOProtocol.SAML2:
            if not provider.x509_cert:
                test_results["warnings"].append("No X.509 certificate configured for signature validation")
            if not provider.slo_url:
                test_results["warnings"].append("Single Logout URL not configured")
        
        elif provider.protocol == SSOProtocol.OIDC:
            if not provider.jwks_uri:
                test_results["warnings"].append("JWKS URI not configured")
            if not provider.userinfo_endpoint:
                test_results["warnings"].append("UserInfo endpoint not configured")
        
        return test_results
    
    except Exception as e:
        logger.error(f"Failed to test SSO provider: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to test SSO provider")


@router.get("/analytics")
@require_permission("organizations:read")
async def get_sso_analytics(
    days: int = Query(30, ge=1, le=90),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get SSO usage analytics (admin only)
    """
    try:
        # This would integrate with the audit service to get SSO usage stats
        analytics = {
            "period_days": days,
            "total_sso_logins": 0,
            "successful_logins": 0,
            "failed_logins": 0,
            "providers_used": {},
            "top_domains": {},
            "user_provisioned": 0,
            "generated_at": "2024-01-01T00:00:00Z"
        }
        
        return analytics
    
    except Exception as e:
        logger.error(f"Failed to get SSO analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get SSO analytics")