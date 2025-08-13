"""
JWKS Cache Service
Caches and manages JSON Web Key Sets for efficient token validation
"""

import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from jose import jwk, jwt
from jose.exceptions import JWTError
import asyncio
from urllib.parse import urlparse

from app.core.config import settings
from app.core.cache import cache_service
from app.core.exceptions import AuthenticationError


class JWKSCacheService:
    """Service for caching and managing JWKS"""
    
    def __init__(self):
        self.cache_ttl = 3600  # 1 hour default
        self.max_cache_ttl = 86400  # 24 hours max
        self.min_cache_ttl = 300  # 5 minutes min
        self.refresh_threshold = 0.8  # Refresh when 80% of TTL expired
        
        # JWKS endpoints
        self.jwks_urls = {
            "clerk": f"https://api.clerk.dev/v1/jwks",
            "auth0": None,
            "okta": None,
            "cognito": None
        }
        
        # Cache key prefixes
        self.cache_prefix = "jwks"
        self.key_cache_prefix = "jwk"
        
        # HTTP client
        self.http_client = httpx.AsyncClient(
            timeout=10.0,
            headers={"User-Agent": "FastAPI-JWKS-Cache/1.0"}
        )
        
        # Background refresh task
        self.refresh_task = None
        self.refresh_interval = 300  # Check every 5 minutes
    
    async def initialize(self):
        """Initialize JWKS cache service"""
        # Load initial JWKS
        for provider in self.jwks_urls:
            if self.jwks_urls[provider]:
                await self.get_jwks(provider)
        
        # Start background refresh task
        if not self.refresh_task:
            self.refresh_task = asyncio.create_task(self._background_refresh())
    
    async def shutdown(self):
        """Shutdown JWKS cache service"""
        if self.refresh_task:
            self.refresh_task.cancel()
            try:
                await self.refresh_task
            except asyncio.CancelledError:
                pass
        
        await self.http_client.aclose()
    
    async def get_jwks(
        self,
        provider: str = "clerk",
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Get JWKS for a provider
        
        Args:
            provider: Provider name (clerk, auth0, okta, etc.)
            force_refresh: Force refresh from source
        """
        cache_key = f"{self.cache_prefix}:{provider}"
        
        # Check cache unless force refresh
        if not force_refresh:
            cached = await cache_service.get(cache_key)
            if cached:
                # Check if needs proactive refresh
                cache_age = cached.get("cached_at", 0)
                cache_ttl = cached.get("ttl", self.cache_ttl)
                
                if self._should_refresh(cache_age, cache_ttl):
                    # Trigger async refresh but return cached
                    asyncio.create_task(self._refresh_jwks(provider))
                
                return cached.get("keys", {})
        
        # Fetch from source
        return await self._refresh_jwks(provider)
    
    async def get_key(
        self,
        kid: str,
        provider: str = "clerk"
    ) -> Optional[Dict[str, Any]]:
        """
        Get specific key by ID
        
        Args:
            kid: Key ID
            provider: Provider name
        """
        # Check specific key cache
        key_cache = f"{self.key_cache_prefix}:{provider}:{kid}"
        cached_key = await cache_service.get(key_cache)
        if cached_key:
            return cached_key
        
        # Get JWKS and find key
        jwks = await self.get_jwks(provider)
        keys = jwks.get("keys", [])
        
        for key in keys:
            if key.get("kid") == kid:
                # Cache individual key
                await cache_service.set(
                    key_cache,
                    key,
                    ttl=self.cache_ttl
                )
                return key
        
        return None
    
    async def validate_token(
        self,
        token: str,
        provider: str = "clerk",
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate JWT token using cached JWKS
        
        Args:
            token: JWT token to validate
            provider: Provider name
            audience: Expected audience
            issuer: Expected issuer
        """
        try:
            # Decode header to get kid
            unverified = jwt.get_unverified_header(token)
            kid = unverified.get("kid")
            
            if not kid:
                raise AuthenticationError("Token missing key ID")
            
            # Get key from cache
            key = await self.get_key(kid, provider)
            if not key:
                # Try refreshing JWKS
                await self.get_jwks(provider, force_refresh=True)
                key = await self.get_key(kid, provider)
                
                if not key:
                    raise AuthenticationError(f"Key {kid} not found in JWKS")
            
            # Convert JWK to public key
            public_key = jwk.construct(key)
            
            # Validate token
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": audience is not None,
                "verify_iss": issuer is not None
            }
            
            claims = jwt.decode(
                token,
                public_key,
                algorithms=[key.get("alg", "RS256")],
                audience=audience,
                issuer=issuer,
                options=options
            )
            
            # Cache validated token claims briefly
            token_cache_key = f"validated_token:{self._hash_token(token)}"
            await cache_service.set(
                token_cache_key,
                claims,
                ttl=60  # 1 minute cache
            )
            
            return claims
            
        except JWTError as e:
            raise AuthenticationError(f"Token validation failed: {str(e)}")
    
    async def get_public_key(
        self,
        kid: str,
        provider: str = "clerk",
        format: str = "pem"
    ) -> Optional[str]:
        """
        Get public key in specified format
        
        Args:
            kid: Key ID
            provider: Provider name
            format: Output format (pem, der, jwk)
        """
        key = await self.get_key(kid, provider)
        if not key:
            return None
        
        if format == "jwk":
            return json.dumps(key)
        
        # Convert to cryptography key
        public_key = jwk.construct(key)
        
        if format == "pem":
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        elif format == "der":
            return public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        
        return None
    
    async def rotate_cache(self, provider: str = "clerk"):
        """Force rotate JWKS cache for a provider"""
        # Clear all related caches
        await cache_service.delete(f"{self.cache_prefix}:{provider}")
        
        # Clear individual key caches
        pattern = f"{self.key_cache_prefix}:{provider}:*"
        await cache_service.delete_pattern(pattern)
        
        # Refresh from source
        await self.get_jwks(provider, force_refresh=True)
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {}
        
        for provider in self.jwks_urls:
            if not self.jwks_urls[provider]:
                continue
            
            cache_key = f"{self.cache_prefix}:{provider}"
            cached = await cache_service.get(cache_key)
            
            if cached:
                cache_age = time.time() - cached.get("cached_at", 0)
                cache_ttl = cached.get("ttl", self.cache_ttl)
                
                stats[provider] = {
                    "cached": True,
                    "age_seconds": int(cache_age),
                    "ttl_seconds": cache_ttl,
                    "keys_count": len(cached.get("keys", {}).get("keys", [])),
                    "expires_in": int(cache_ttl - cache_age),
                    "needs_refresh": self._should_refresh(
                        cached.get("cached_at", 0),
                        cache_ttl
                    )
                }
            else:
                stats[provider] = {
                    "cached": False
                }
        
        return stats
    
    async def warm_cache(self):
        """Warm up cache by pre-loading all JWKS"""
        tasks = []
        for provider in self.jwks_urls:
            if self.jwks_urls[provider]:
                tasks.append(self.get_jwks(provider, force_refresh=True))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _refresh_jwks(self, provider: str) -> Dict[str, Any]:
        """Refresh JWKS from source"""
        url = self.jwks_urls.get(provider)
        if not url:
            # Try to construct URL based on provider settings
            url = self._get_provider_jwks_url(provider)
            if not url:
                raise ValueError(f"No JWKS URL configured for provider: {provider}")
        
        try:
            response = await self.http_client.get(url)
            response.raise_for_status()
            
            jwks = response.json()
            
            # Determine cache TTL from response headers
            cache_ttl = self._get_cache_ttl_from_headers(response.headers)
            
            # Store in cache
            cache_data = {
                "keys": jwks,
                "cached_at": time.time(),
                "ttl": cache_ttl,
                "provider": provider,
                "url": url
            }
            
            cache_key = f"{self.cache_prefix}:{provider}"
            await cache_service.set(
                cache_key,
                cache_data,
                ttl=cache_ttl
            )
            
            # Clear old individual key caches
            pattern = f"{self.key_cache_prefix}:{provider}:*"
            await cache_service.delete_pattern(pattern)
            
            return jwks
            
        except httpx.HTTPError as e:
            # On error, try to return cached version if available
            cache_key = f"{self.cache_prefix}:{provider}"
            cached = await cache_service.get(cache_key)
            if cached:
                return cached.get("keys", {})
            
            raise AuthenticationError(f"Failed to fetch JWKS: {str(e)}")
    
    async def _background_refresh(self):
        """Background task to refresh JWKS proactively"""
        while True:
            try:
                await asyncio.sleep(self.refresh_interval)
                
                # Check each provider
                for provider in self.jwks_urls:
                    if not self.jwks_urls[provider]:
                        continue
                    
                    cache_key = f"{self.cache_prefix}:{provider}"
                    cached = await cache_service.get(cache_key)
                    
                    if cached:
                        cache_age = cached.get("cached_at", 0)
                        cache_ttl = cached.get("ttl", self.cache_ttl)
                        
                        if self._should_refresh(cache_age, cache_ttl):
                            await self._refresh_jwks(provider)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                print(f"JWKS background refresh error: {e}")
    
    def _should_refresh(self, cached_at: float, ttl: int) -> bool:
        """Check if cache should be refreshed"""
        age = time.time() - cached_at
        return age > (ttl * self.refresh_threshold)
    
    def _get_cache_ttl_from_headers(self, headers: Dict) -> int:
        """Extract cache TTL from HTTP headers"""
        # Check Cache-Control header
        cache_control = headers.get("cache-control", "")
        if "max-age=" in cache_control:
            try:
                max_age = int(cache_control.split("max-age=")[1].split(",")[0])
                return min(max(max_age, self.min_cache_ttl), self.max_cache_ttl)
            except:
                pass
        
        # Check Expires header
        expires = headers.get("expires")
        if expires:
            try:
                from email.utils import parsedate_to_datetime
                expires_dt = parsedate_to_datetime(expires)
                ttl = int((expires_dt - datetime.utcnow()).total_seconds())
                return min(max(ttl, self.min_cache_ttl), self.max_cache_ttl)
            except:
                pass
        
        # Default TTL
        return self.cache_ttl
    
    def _get_provider_jwks_url(self, provider: str) -> Optional[str]:
        """Get JWKS URL for provider based on configuration"""
        if provider == "clerk":
            # Clerk JWKS URL pattern
            if hasattr(settings, 'CLERK_FRONTEND_API'):
                domain = urlparse(settings.CLERK_FRONTEND_API).netloc
                return f"https://{domain}/.well-known/jwks.json"
        elif provider == "auth0":
            if hasattr(settings, 'AUTH0_DOMAIN'):
                return f"https://{settings.AUTH0_DOMAIN}/.well-known/jwks.json"
        elif provider == "okta":
            if hasattr(settings, 'OKTA_DOMAIN'):
                return f"https://{settings.OKTA_DOMAIN}/oauth2/default/v1/keys"
        elif provider == "cognito":
            if hasattr(settings, 'COGNITO_REGION') and hasattr(settings, 'COGNITO_USER_POOL_ID'):
                return f"https://cognito-idp.{settings.COGNITO_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        
        return None
    
    def _hash_token(self, token: str) -> str:
        """Hash token for caching"""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()[:16]


# Create singleton instance
jwks_cache_service = JWKSCacheService()