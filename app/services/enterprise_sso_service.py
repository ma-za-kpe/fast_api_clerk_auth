from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
import structlog
import base64
import secrets
import urllib.parse
from xml.etree import ElementTree as ET
import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthenticationError, ConfigurationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class SSOProtocol(Enum):
    SAML2 = "saml2"
    OIDC = "oidc"


class SAMLBinding(Enum):
    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


@dataclass
class SSOProvider:
    """SSO Provider configuration"""
    id: str
    name: str
    protocol: SSOProtocol
    enabled: bool
    domain: Optional[str] = None
    
    # SAML specific
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    slo_url: Optional[str] = None
    x509_cert: Optional[str] = None
    binding: Optional[SAMLBinding] = None
    
    # OIDC specific
    issuer: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    
    # Common settings
    auto_provision: bool = True
    attribute_mapping: Optional[Dict[str, str]] = None
    role_mapping: Optional[Dict[str, str]] = None
    organization_id: Optional[str] = None


class EnterpriseSSOService:
    """
    Enterprise SSO service supporting SAML 2.0 and OpenID Connect
    """
    
    def __init__(self):
        self.base_url = getattr(settings, 'BASE_URL', 'http://localhost:8000')
        self.sso_providers: Dict[str, SSOProvider] = {}
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    # ============= Provider Management =============
    
    async def add_sso_provider(self, provider: SSOProvider) -> Dict[str, Any]:
        """
        Add or update SSO provider configuration
        """
        try:
            # Validate provider configuration
            validation_result = await self._validate_provider_config(provider)
            if not validation_result["valid"]:
                raise ValidationError(f"Invalid provider configuration: {validation_result['errors']}")
            
            # Store provider configuration
            provider_key = f"sso_provider:{provider.id}"
            provider_data = {
                "id": provider.id,
                "name": provider.name,
                "protocol": provider.protocol.value,
                "enabled": provider.enabled,
                "domain": provider.domain,
                "entity_id": provider.entity_id,
                "sso_url": provider.sso_url,
                "slo_url": provider.slo_url,
                "x509_cert": provider.x509_cert,
                "binding": provider.binding.value if provider.binding else None,
                "issuer": provider.issuer,
                "authorization_endpoint": provider.authorization_endpoint,
                "token_endpoint": provider.token_endpoint,
                "userinfo_endpoint": provider.userinfo_endpoint,
                "jwks_uri": provider.jwks_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "auto_provision": provider.auto_provision,
                "attribute_mapping": provider.attribute_mapping or {},
                "role_mapping": provider.role_mapping or {},
                "organization_id": provider.organization_id,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            await cache_service.set(provider_key, provider_data)
            
            # Cache provider in memory
            self.sso_providers[provider.id] = provider
            
            # If domain is specified, create domain mapping
            if provider.domain:
                domain_key = f"sso_domain:{provider.domain}"
                await cache_service.set(domain_key, provider.id)
            
            logger.info(
                f"SSO provider configured",
                provider_id=provider.id,
                protocol=provider.protocol.value,
                domain=provider.domain
            )
            
            return {
                "provider_id": provider.id,
                "configured": True,
                "endpoints": self._get_provider_endpoints(provider)
            }
        
        except Exception as e:
            logger.error(f"Failed to add SSO provider: {str(e)}")
            raise ValidationError("Failed to configure SSO provider")
    
    async def get_sso_provider(self, provider_id: str) -> Optional[SSOProvider]:
        """
        Get SSO provider configuration
        """
        try:
            # Check memory cache first
            if provider_id in self.sso_providers:
                return self.sso_providers[provider_id]
            
            # Load from cache
            provider_key = f"sso_provider:{provider_id}"
            provider_data = await cache_service.get(provider_key)
            
            if not provider_data:
                return None
            
            # Convert to SSOProvider object
            provider = SSOProvider(
                id=provider_data["id"],
                name=provider_data["name"],
                protocol=SSOProtocol(provider_data["protocol"]),
                enabled=provider_data["enabled"],
                domain=provider_data.get("domain"),
                entity_id=provider_data.get("entity_id"),
                sso_url=provider_data.get("sso_url"),
                slo_url=provider_data.get("slo_url"),
                x509_cert=provider_data.get("x509_cert"),
                binding=SAMLBinding(provider_data["binding"]) if provider_data.get("binding") else None,
                issuer=provider_data.get("issuer"),
                authorization_endpoint=provider_data.get("authorization_endpoint"),
                token_endpoint=provider_data.get("token_endpoint"),
                userinfo_endpoint=provider_data.get("userinfo_endpoint"),
                jwks_uri=provider_data.get("jwks_uri"),
                client_id=provider_data.get("client_id"),
                client_secret=provider_data.get("client_secret"),
                auto_provision=provider_data.get("auto_provision", True),
                attribute_mapping=provider_data.get("attribute_mapping", {}),
                role_mapping=provider_data.get("role_mapping", {}),
                organization_id=provider_data.get("organization_id")
            )
            
            # Cache in memory
            self.sso_providers[provider_id] = provider
            
            return provider
        
        except Exception as e:
            logger.error(f"Failed to get SSO provider: {str(e)}")
            return None
    
    async def discover_provider_for_domain(self, email_domain: str) -> Optional[str]:
        """
        Discover SSO provider for email domain
        """
        try:
            domain_key = f"sso_domain:{email_domain}"
            provider_id = await cache_service.get(domain_key)
            return provider_id
        
        except Exception as e:
            logger.error(f"Failed to discover provider for domain: {str(e)}")
            return None
    
    # ============= SAML 2.0 Implementation =============
    
    async def initiate_saml_login(
        self,
        provider_id: str,
        relay_state: Optional[str] = None,
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Initiate SAML SSO login flow
        """
        try:
            provider = await self.get_sso_provider(provider_id)
            if not provider or provider.protocol != SSOProtocol.SAML2:
                raise ValidationError("Invalid SAML provider")
            
            if not provider.enabled:
                raise ValidationError("SSO provider is disabled")
            
            # Generate SAML Request ID
            request_id = self._generate_request_id()
            
            # Generate SAML AuthnRequest
            authn_request = self._generate_saml_authn_request(
                provider=provider,
                request_id=request_id,
                relay_state=relay_state
            )
            
            # Store request state
            state_key = f"saml_state:{request_id}"
            state_data = {
                "provider_id": provider_id,
                "request_id": request_id,
                "relay_state": relay_state,
                "organization_id": organization_id,
                "created_at": datetime.utcnow().isoformat()
            }
            await cache_service.set(state_key, state_data, expire=600)  # 10 minutes
            
            # Encode request
            if provider.binding == SAMLBinding.HTTP_POST:
                # HTTP POST binding
                saml_request_encoded = base64.b64encode(authn_request.encode()).decode()
                
                return {
                    "binding": "HTTP-POST",
                    "sso_url": provider.sso_url,
                    "saml_request": saml_request_encoded,
                    "relay_state": relay_state,
                    "request_id": request_id
                }
            else:
                # HTTP Redirect binding (default)
                saml_request_encoded = base64.b64encode(authn_request.encode()).decode()
                saml_request_encoded = urllib.parse.quote(saml_request_encoded)
                
                redirect_url = f"{provider.sso_url}?SAMLRequest={saml_request_encoded}"
                if relay_state:
                    redirect_url += f"&RelayState={urllib.parse.quote(relay_state)}"
                
                return {
                    "binding": "HTTP-Redirect",
                    "redirect_url": redirect_url,
                    "request_id": request_id
                }
        
        except Exception as e:
            logger.error(f"Failed to initiate SAML login: {str(e)}")
            raise ValidationError("Failed to initiate SSO login")
    
    async def handle_saml_response(
        self,
        saml_response: str,
        relay_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Handle SAML Response from IdP
        """
        try:
            # Decode SAML response
            try:
                saml_response_decoded = base64.b64decode(saml_response).decode()
            except Exception:
                raise ValidationError("Invalid SAML response encoding")
            
            # Parse SAML response
            response_data = self._parse_saml_response(saml_response_decoded)
            
            # Validate response
            validation_result = await self._validate_saml_response(response_data)
            if not validation_result["valid"]:
                raise AuthenticationError(f"SAML response validation failed: {validation_result['error']}")
            
            # Get provider
            provider = await self.get_sso_provider(validation_result["provider_id"])
            if not provider:
                raise ValidationError("SSO provider not found")
            
            # Extract user attributes
            user_attributes = self._extract_saml_attributes(
                response_data,
                provider.attribute_mapping
            )
            
            # Provision or authenticate user
            user_result = await self._provision_sso_user(
                provider=provider,
                attributes=user_attributes,
                protocol="saml"
            )
            
            logger.info(
                f"SAML authentication successful",
                provider_id=provider.id,
                user_id=user_result.get("user_id")
            )
            
            return {
                "success": True,
                "user": user_result,
                "provider_id": provider.id,
                "relay_state": relay_state
            }
        
        except Exception as e:
            logger.error(f"Failed to handle SAML response: {str(e)}")
            raise AuthenticationError("SAML authentication failed")
    
    # ============= OpenID Connect Implementation =============
    
    async def initiate_oidc_login(
        self,
        provider_id: str,
        redirect_uri: Optional[str] = None,
        organization_id: Optional[str] = None,
        scopes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Initiate OIDC SSO login flow
        """
        try:
            provider = await self.get_sso_provider(provider_id)
            if not provider or provider.protocol != SSOProtocol.OIDC:
                raise ValidationError("Invalid OIDC provider")
            
            if not provider.enabled:
                raise ValidationError("SSO provider is disabled")
            
            # Generate state and nonce
            state = self._generate_request_id()
            nonce = self._generate_request_id()
            
            # Default scopes
            if not scopes:
                scopes = ["openid", "email", "profile"]
            
            # Store request state
            state_key = f"oidc_state:{state}"
            state_data = {
                "provider_id": provider_id,
                "nonce": nonce,
                "redirect_uri": redirect_uri,
                "organization_id": organization_id,
                "created_at": datetime.utcnow().isoformat()
            }
            await cache_service.set(state_key, state_data, expire=600)  # 10 minutes
            
            # Build authorization URL
            params = {
                "response_type": "code",
                "client_id": provider.client_id,
                "redirect_uri": redirect_uri or f"{self.base_url}/api/v1/sso/oidc/callback",
                "scope": " ".join(scopes),
                "state": state,
                "nonce": nonce
            }
            
            auth_url = provider.authorization_endpoint + "?" + urllib.parse.urlencode(params)
            
            return {
                "authorization_url": auth_url,
                "state": state,
                "nonce": nonce
            }
        
        except Exception as e:
            logger.error(f"Failed to initiate OIDC login: {str(e)}")
            raise ValidationError("Failed to initiate OIDC login")
    
    async def handle_oidc_callback(
        self,
        code: str,
        state: str,
        redirect_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Handle OIDC authorization code callback
        """
        try:
            # Validate state
            state_key = f"oidc_state:{state}"
            state_data = await cache_service.get(state_key)
            if not state_data:
                raise AuthenticationError("Invalid or expired state")
            
            # Clear state
            await cache_service.delete(state_key)
            
            # Get provider
            provider = await self.get_sso_provider(state_data["provider_id"])
            if not provider:
                raise ValidationError("SSO provider not found")
            
            # Exchange code for tokens
            token_data = await self._exchange_oidc_code(
                provider=provider,
                code=code,
                redirect_uri=redirect_uri or f"{self.base_url}/api/v1/sso/oidc/callback"
            )
            
            # Validate ID token
            user_info = await self._validate_oidc_token(
                provider=provider,
                id_token=token_data["id_token"],
                nonce=state_data["nonce"]
            )
            
            # Get additional user info if needed
            if token_data.get("access_token") and provider.userinfo_endpoint:
                additional_info = await self._get_oidc_userinfo(
                    provider=provider,
                    access_token=token_data["access_token"]
                )
                user_info.update(additional_info)
            
            # Provision or authenticate user
            user_result = await self._provision_sso_user(
                provider=provider,
                attributes=user_info,
                protocol="oidc"
            )
            
            logger.info(
                f"OIDC authentication successful",
                provider_id=provider.id,
                user_id=user_result.get("user_id")
            )
            
            return {
                "success": True,
                "user": user_result,
                "provider_id": provider.id,
                "tokens": token_data
            }
        
        except Exception as e:
            logger.error(f"Failed to handle OIDC callback: {str(e)}")
            raise AuthenticationError("OIDC authentication failed")
    
    # ============= User Provisioning =============
    
    async def _provision_sso_user(
        self,
        provider: SSOProvider,
        attributes: Dict[str, Any],
        protocol: str
    ) -> Dict[str, Any]:
        """
        Provision or authenticate SSO user
        """
        try:
            # Map attributes using provider mapping
            mapped_attributes = self._map_user_attributes(attributes, provider.attribute_mapping)
            
            email = mapped_attributes.get("email")
            if not email:
                raise ValidationError("Email attribute is required")
            
            # Check if user exists
            clerk_client = await self._get_clerk_client()
            existing_user = None
            
            try:
                users = await clerk_client.list_users(email_address=[email])
                existing_user = users[0] if users else None
            except Exception:
                pass
            
            if existing_user:
                # Update existing user
                user_data = {
                    "public_metadata": {
                        **existing_user.public_metadata,
                        "sso_provider": provider.id,
                        "sso_protocol": protocol,
                        "last_sso_login": datetime.utcnow().isoformat()
                    }
                }
                
                # Update organization membership if specified
                if provider.organization_id:
                    user_data["public_metadata"]["sso_organization"] = provider.organization_id
                
                user = await clerk_client.update_user(existing_user.id, **user_data)
                
                return {
                    "user_id": user.id,
                    "email": email,
                    "existing_user": True,
                    "organization_id": provider.organization_id
                }
            
            elif provider.auto_provision:
                # Create new user
                user_data = {
                    "email_address": [email],
                    "first_name": mapped_attributes.get("first_name"),
                    "last_name": mapped_attributes.get("last_name"),
                    "public_metadata": {
                        "sso_provider": provider.id,
                        "sso_protocol": protocol,
                        "provisioned_via_sso": True,
                        "created_via_sso": datetime.utcnow().isoformat()
                    },
                    "skip_password_checks": True,
                    "skip_password_requirement": True
                }
                
                # Add organization metadata
                if provider.organization_id:
                    user_data["public_metadata"]["sso_organization"] = provider.organization_id
                
                user = await clerk_client.create_user(**user_data)
                
                # Add to organization if specified
                if provider.organization_id:
                    try:
                        await clerk_client.create_organization_membership(
                            organization_id=provider.organization_id,
                            user_id=user.id,
                            role="basic_member"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to add SSO user to organization: {str(e)}")
                
                logger.info(f"SSO user provisioned", user_id=user.id, provider_id=provider.id)
                
                return {
                    "user_id": user.id,
                    "email": email,
                    "provisioned": True,
                    "organization_id": provider.organization_id
                }
            
            else:
                raise AuthenticationError("User not found and auto-provisioning is disabled")
        
        except Exception as e:
            logger.error(f"Failed to provision SSO user: {str(e)}")
            raise ValidationError("Failed to provision user")
    
    # ============= Helper Methods =============
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return secrets.token_urlsafe(32)
    
    def _get_provider_endpoints(self, provider: SSOProvider) -> Dict[str, str]:
        """Get provider endpoint URLs"""
        endpoints = {}
        
        if provider.protocol == SSOProtocol.SAML2:
            endpoints.update({
                "sso_url": f"{self.base_url}/api/v1/sso/saml/login/{provider.id}",
                "acs_url": f"{self.base_url}/api/v1/sso/saml/acs",
                "metadata_url": f"{self.base_url}/api/v1/sso/saml/metadata/{provider.id}"
            })
        elif provider.protocol == SSOProtocol.OIDC:
            endpoints.update({
                "authorization_url": f"{self.base_url}/api/v1/sso/oidc/login/{provider.id}",
                "callback_url": f"{self.base_url}/api/v1/sso/oidc/callback",
                "redirect_uri": f"{self.base_url}/api/v1/sso/oidc/callback"
            })
        
        return endpoints
    
    async def _validate_provider_config(self, provider: SSOProvider) -> Dict[str, Any]:
        """Validate SSO provider configuration"""
        errors = []
        
        if provider.protocol == SSOProtocol.SAML2:
            if not provider.entity_id:
                errors.append("SAML entity_id is required")
            if not provider.sso_url:
                errors.append("SAML SSO URL is required")
            if not provider.x509_cert:
                errors.append("SAML X.509 certificate is required")
        
        elif provider.protocol == SSOProtocol.OIDC:
            if not provider.issuer:
                errors.append("OIDC issuer is required")
            if not provider.client_id:
                errors.append("OIDC client_id is required")
            if not provider.client_secret:
                errors.append("OIDC client_secret is required")
            if not provider.authorization_endpoint:
                errors.append("OIDC authorization_endpoint is required")
            if not provider.token_endpoint:
                errors.append("OIDC token_endpoint is required")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def _generate_saml_authn_request(
        self,
        provider: SSOProvider,
        request_id: str,
        relay_state: Optional[str] = None
    ) -> str:
        """Generate SAML AuthnRequest XML"""
        # This is a simplified SAML request - in production you'd use a proper SAML library
        acs_url = f"{self.base_url}/api/v1/sso/saml/acs"
        issue_instant = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        
        authn_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{request_id}"
                    Version="2.0"
                    IssueInstant="{issue_instant}"
                    Destination="{provider.sso_url}"
                    AssertionConsumerServiceURL="{acs_url}">
    <saml:Issuer>{self.base_url}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""
        
        return authn_request
    
    def _parse_saml_response(self, saml_response: str) -> Dict[str, Any]:
        """Parse SAML Response XML (simplified)"""
        # In production, use a proper SAML library like python3-saml
        try:
            root = ET.fromstring(saml_response)
            
            # Extract basic response data
            response_data = {
                "response_id": root.get("ID"),
                "issue_instant": root.get("IssueInstant"),
                "destination": root.get("Destination"),
                "attributes": {},
                "name_id": None,
                "status": "success"  # Simplified - should check StatusCode
            }
            
            # Extract NameID and attributes (simplified)
            # This would need proper namespace handling in production
            
            return response_data
        
        except Exception as e:
            logger.error(f"Failed to parse SAML response: {str(e)}")
            raise ValidationError("Invalid SAML response format")
    
    async def _validate_saml_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SAML response (simplified)"""
        # In production, implement proper signature validation, timestamp checks, etc.
        return {
            "valid": True,
            "provider_id": "default",  # Should be extracted from response
            "error": None
        }
    
    def _extract_saml_attributes(
        self,
        response_data: Dict[str, Any],
        attribute_mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """Extract user attributes from SAML response"""
        # Simplified - in production, properly parse SAML attributes
        return {
            "email": "user@example.com",  # Extract from SAML response
            "first_name": "John",
            "last_name": "Doe"
        }
    
    async def _exchange_oidc_code(
        self,
        provider: SSOProvider,
        code: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """Exchange OIDC authorization code for tokens"""
        # Simplified - in production, make actual HTTP request to token endpoint
        return {
            "access_token": "fake_access_token",
            "id_token": "fake_id_token",
            "refresh_token": "fake_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
    
    async def _validate_oidc_token(
        self,
        provider: SSOProvider,
        id_token: str,
        nonce: str
    ) -> Dict[str, Any]:
        """Validate OIDC ID token"""
        # Simplified - in production, validate JWT signature and claims
        return {
            "sub": "user123",
            "email": "user@example.com",
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe"
        }
    
    async def _get_oidc_userinfo(
        self,
        provider: SSOProvider,
        access_token: str
    ) -> Dict[str, Any]:
        """Get additional user info from OIDC userinfo endpoint"""
        # Simplified - in production, make HTTP request to userinfo endpoint
        return {}
    
    def _map_user_attributes(
        self,
        attributes: Dict[str, Any],
        mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """Map SSO attributes to user attributes"""
        mapped = {}
        
        # Default mappings
        default_mapping = {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
            "name": "name"
        }
        
        # Combine default and custom mappings
        combined_mapping = {**default_mapping, **mapping}
        
        for local_attr, sso_attr in combined_mapping.items():
            if sso_attr in attributes:
                mapped[local_attr] = attributes[sso_attr]
        
        return mapped
    
    # ============= Management Methods =============
    
    async def list_sso_providers(self) -> List[Dict[str, Any]]:
        """List all configured SSO providers"""
        try:
            # Get all provider keys
            pattern = "sso_provider:*"
            provider_keys = await cache_service.get_pattern(pattern)
            
            providers = []
            for key in provider_keys:
                provider_data = await cache_service.get(key)
                if provider_data:
                    # Remove sensitive data
                    safe_data = {k: v for k, v in provider_data.items() 
                                if k not in ["client_secret", "x509_cert"]}
                    providers.append(safe_data)
            
            return providers
        
        except Exception as e:
            logger.error(f"Failed to list SSO providers: {str(e)}")
            return []
    
    async def delete_sso_provider(self, provider_id: str) -> Dict[str, Any]:
        """Delete SSO provider configuration"""
        try:
            provider = await self.get_sso_provider(provider_id)
            if not provider:
                raise ValidationError("SSO provider not found")
            
            # Delete provider configuration
            provider_key = f"sso_provider:{provider_id}"
            await cache_service.delete(provider_key)
            
            # Delete domain mapping if exists
            if provider.domain:
                domain_key = f"sso_domain:{provider.domain}"
                await cache_service.delete(domain_key)
            
            # Remove from memory cache
            if provider_id in self.sso_providers:
                del self.sso_providers[provider_id]
            
            logger.info(f"SSO provider deleted", provider_id=provider_id)
            
            return {"deleted": True, "provider_id": provider_id}
        
        except Exception as e:
            logger.error(f"Failed to delete SSO provider: {str(e)}")
            raise ValidationError("Failed to delete SSO provider")


# Singleton instance
enterprise_sso_service = EnterpriseSSOService()