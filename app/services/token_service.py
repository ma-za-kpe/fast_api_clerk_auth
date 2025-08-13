from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
import secrets
import hashlib
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
import structlog

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ValidationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class TokenService:
    """
    Enhanced token management service with refresh token rotation
    """
    
    def __init__(self):
        self.access_token_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES if hasattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES') else 15
        self.refresh_token_expire = settings.REFRESH_TOKEN_EXPIRE_DAYS if hasattr(settings, 'REFRESH_TOKEN_EXPIRE_DAYS') else 7
        self.refresh_token_rotation_enabled = True
        self.refresh_token_reuse_window = 10  # seconds to allow reuse after rotation
        self.max_refresh_chain_length = 10  # maximum times a token can be refreshed
        self.algorithm = "HS256"
        self.secret_key = settings.SECRET_KEY if hasattr(settings, 'SECRET_KEY') else "your-secret-key"
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def create_token_pair(
        self,
        user_id: str,
        session_id: str,
        device_id: Optional[str] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create access and refresh token pair with rotation support
        """
        try:
            # Generate token family ID (for tracking refresh chains)
            family_id = secrets.token_urlsafe(32)
            
            # Create access token
            access_token, access_jti = self._create_access_token(
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                family_id=family_id,
                additional_claims=additional_claims
            )
            
            # Create refresh token
            refresh_token, refresh_jti = self._create_refresh_token(
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                family_id=family_id,
                chain_count=0
            )
            
            # Store refresh token metadata for rotation tracking
            await self._store_refresh_token_metadata(
                refresh_jti=refresh_jti,
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                family_id=family_id,
                chain_count=0,
                parent_jti=None
            )
            
            # Store token family information
            await self._store_token_family(
                family_id=family_id,
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                refresh_jti=refresh_jti
            )
            
            logger.info(
                f"Token pair created for user {user_id}",
                session_id=session_id,
                family_id=family_id
            )
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": self.access_token_expire * 60,
                "refresh_expires_in": self.refresh_token_expire * 24 * 3600,
                "family_id": family_id
            }
        
        except Exception as e:
            logger.error(f"Failed to create token pair: {str(e)}")
            raise ValidationError("Failed to create authentication tokens")
    
    async def rotate_refresh_token(
        self,
        refresh_token: str,
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rotate refresh token - invalidate old one and issue new pair
        """
        try:
            # Decode and validate refresh token
            payload = self._decode_token(refresh_token)
            
            if payload.get("type") != "refresh":
                raise AuthenticationError("Invalid token type")
            
            refresh_jti = payload.get("jti")
            user_id = payload.get("sub")
            session_id = payload.get("session_id")
            family_id = payload.get("family_id")
            chain_count = payload.get("chain_count", 0)
            
            # Check if token has been revoked (possible token reuse attack)
            if await self._is_token_revoked(refresh_jti):
                # Token reuse detected - revoke entire family
                await self._revoke_token_family(family_id)
                logger.warning(
                    f"Refresh token reuse detected - revoking family",
                    user_id=user_id,
                    family_id=family_id
                )
                raise AuthenticationError("Token has been revoked - possible security breach")
            
            # Check if we're within reuse window (for race conditions)
            metadata = await self._get_refresh_token_metadata(refresh_jti)
            if metadata and metadata.get("rotated"):
                rotated_at = datetime.fromisoformat(metadata["rotated_at"])
                if (datetime.utcnow() - rotated_at).total_seconds() < self.refresh_token_reuse_window:
                    # Within grace period - return the new tokens
                    new_tokens = metadata.get("new_tokens")
                    if new_tokens:
                        return new_tokens
                
                # Outside grace period - security breach
                await self._revoke_token_family(family_id)
                raise AuthenticationError("Token already rotated - possible security breach")
            
            # Check maximum refresh chain length
            if chain_count >= self.max_refresh_chain_length:
                raise AuthenticationError("Maximum refresh limit reached - please login again")
            
            # Validate session is still active
            if not await self._validate_session(session_id):
                raise AuthenticationError("Session is no longer valid")
            
            # Create new token pair
            new_access_token, new_access_jti = self._create_access_token(
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                family_id=family_id
            )
            
            new_refresh_token, new_refresh_jti = self._create_refresh_token(
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                family_id=family_id,
                chain_count=chain_count + 1
            )
            
            # Store new refresh token metadata
            await self._store_refresh_token_metadata(
                refresh_jti=new_refresh_jti,
                user_id=user_id,
                session_id=session_id,
                device_id=device_id,
                family_id=family_id,
                chain_count=chain_count + 1,
                parent_jti=refresh_jti
            )
            
            # Mark old token as rotated (with grace period)
            await self._mark_token_rotated(
                refresh_jti,
                {
                    "access_token": new_access_token,
                    "refresh_token": new_refresh_token,
                    "token_type": "Bearer",
                    "expires_in": self.access_token_expire * 60
                }
            )
            
            # Update token family
            await self._update_token_family(family_id, new_refresh_jti)
            
            logger.info(
                f"Refresh token rotated for user {user_id}",
                family_id=family_id,
                chain_count=chain_count + 1
            )
            
            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": self.access_token_expire * 60,
                "refresh_expires_in": self.refresh_token_expire * 24 * 3600,
                "rotation_count": chain_count + 1
            }
        
        except (AuthenticationError, ExpiredSignatureError):
            raise
        except Exception as e:
            logger.error(f"Failed to rotate refresh token: {str(e)}")
            raise AuthenticationError("Failed to refresh authentication")
    
    async def revoke_token(self, token: str, token_type: str = "access") -> bool:
        """
        Revoke a specific token
        """
        try:
            payload = self._decode_token(token, verify_exp=False)
            jti = payload.get("jti")
            
            if not jti:
                return False
            
            # Add to revocation list
            revoke_key = f"revoked_token:{jti}"
            exp = payload.get("exp")
            
            if exp:
                # Set expiry to match token expiry
                ttl = exp - int(datetime.utcnow().timestamp())
                if ttl > 0:
                    await cache_service.set(revoke_key, True, expire=ttl)
            else:
                # Default to 7 days
                await cache_service.set(revoke_key, True, expire=7 * 24 * 3600)
            
            # If it's a refresh token, also revoke the family
            if token_type == "refresh" and payload.get("family_id"):
                await self._revoke_token_family(payload["family_id"])
            
            logger.info(f"Token revoked", jti=jti, token_type=token_type)
            return True
        
        except Exception as e:
            logger.error(f"Failed to revoke token: {str(e)}")
            return False
    
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user
        """
        try:
            # Get all token families for user
            families_key = f"user_token_families:{user_id}"
            families = await cache_service.get_set_members(families_key)
            
            count = 0
            for family_id in families:
                if await self._revoke_token_family(family_id):
                    count += 1
            
            # Clear user families set
            await cache_service.delete(families_key)
            
            logger.info(f"Revoked all tokens for user {user_id}", count=count)
            return count
        
        except Exception as e:
            logger.error(f"Failed to revoke user tokens: {str(e)}")
            return 0
    
    async def validate_access_token(self, token: str) -> Dict[str, Any]:
        """
        Validate access token and return claims
        """
        try:
            payload = self._decode_token(token)
            
            if payload.get("type") != "access":
                raise AuthenticationError("Invalid token type")
            
            # Check if token is revoked
            jti = payload.get("jti")
            if await self._is_token_revoked(jti):
                raise AuthenticationError("Token has been revoked")
            
            # Check if token family is valid
            family_id = payload.get("family_id")
            if family_id and not await self._is_family_valid(family_id):
                raise AuthenticationError("Token family has been revoked")
            
            return {
                "user_id": payload.get("sub"),
                "session_id": payload.get("session_id"),
                "device_id": payload.get("device_id"),
                "family_id": family_id,
                "claims": payload
            }
        
        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to validate access token: {str(e)}")
            raise AuthenticationError("Token validation failed")
    
    # ============= Helper Methods =============
    
    def _create_access_token(
        self,
        user_id: str,
        session_id: str,
        device_id: Optional[str],
        family_id: str,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str]:
        """Create access token"""
        jti = secrets.token_urlsafe(32)
        
        payload = {
            "sub": user_id,
            "type": "access",
            "jti": jti,
            "session_id": session_id,
            "device_id": device_id,
            "family_id": family_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=self.access_token_expire)
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token, jti
    
    def _create_refresh_token(
        self,
        user_id: str,
        session_id: str,
        device_id: Optional[str],
        family_id: str,
        chain_count: int
    ) -> Tuple[str, str]:
        """Create refresh token"""
        jti = secrets.token_urlsafe(32)
        
        payload = {
            "sub": user_id,
            "type": "refresh",
            "jti": jti,
            "session_id": session_id,
            "device_id": device_id,
            "family_id": family_id,
            "chain_count": chain_count,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=self.refresh_token_expire)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token, jti
    
    def _decode_token(self, token: str, verify_exp: bool = True) -> Dict[str, Any]:
        """Decode and validate JWT token"""
        return jwt.decode(
            token,
            self.secret_key,
            algorithms=[self.algorithm],
            options={"verify_exp": verify_exp}
        )
    
    async def _store_refresh_token_metadata(
        self,
        refresh_jti: str,
        user_id: str,
        session_id: str,
        device_id: Optional[str],
        family_id: str,
        chain_count: int,
        parent_jti: Optional[str]
    ):
        """Store refresh token metadata for tracking"""
        metadata = {
            "jti": refresh_jti,
            "user_id": user_id,
            "session_id": session_id,
            "device_id": device_id,
            "family_id": family_id,
            "chain_count": chain_count,
            "parent_jti": parent_jti,
            "created_at": datetime.utcnow().isoformat(),
            "rotated": False
        }
        
        key = f"refresh_token:{refresh_jti}"
        expire = self.refresh_token_expire * 24 * 3600
        await cache_service.set(key, metadata, expire=expire)
        
        # Add to user's token families
        families_key = f"user_token_families:{user_id}"
        await cache_service.add_to_set(families_key, family_id)
    
    async def _get_refresh_token_metadata(self, refresh_jti: str) -> Optional[Dict[str, Any]]:
        """Get refresh token metadata"""
        key = f"refresh_token:{refresh_jti}"
        return await cache_service.get(key)
    
    async def _mark_token_rotated(self, refresh_jti: str, new_tokens: Dict[str, Any]):
        """Mark token as rotated with grace period"""
        metadata = await self._get_refresh_token_metadata(refresh_jti)
        if metadata:
            metadata["rotated"] = True
            metadata["rotated_at"] = datetime.utcnow().isoformat()
            metadata["new_tokens"] = new_tokens
            
            key = f"refresh_token:{refresh_jti}"
            # Keep for grace period + buffer
            expire = self.refresh_token_reuse_window + 60
            await cache_service.set(key, metadata, expire=expire)
    
    async def _store_token_family(
        self,
        family_id: str,
        user_id: str,
        session_id: str,
        device_id: Optional[str],
        refresh_jti: str
    ):
        """Store token family information"""
        family_data = {
            "family_id": family_id,
            "user_id": user_id,
            "session_id": session_id,
            "device_id": device_id,
            "current_refresh_jti": refresh_jti,
            "created_at": datetime.utcnow().isoformat(),
            "valid": True
        }
        
        key = f"token_family:{family_id}"
        expire = self.refresh_token_expire * 24 * 3600
        await cache_service.set(key, family_data, expire=expire)
    
    async def _update_token_family(self, family_id: str, new_refresh_jti: str):
        """Update token family with new refresh token"""
        key = f"token_family:{family_id}"
        family_data = await cache_service.get(key)
        
        if family_data:
            family_data["current_refresh_jti"] = new_refresh_jti
            family_data["updated_at"] = datetime.utcnow().isoformat()
            
            expire = self.refresh_token_expire * 24 * 3600
            await cache_service.set(key, family_data, expire=expire)
    
    async def _revoke_token_family(self, family_id: str) -> bool:
        """Revoke entire token family"""
        try:
            key = f"token_family:{family_id}"
            family_data = await cache_service.get(key)
            
            if family_data:
                family_data["valid"] = False
                family_data["revoked_at"] = datetime.utcnow().isoformat()
                
                # Keep for audit
                await cache_service.set(key, family_data, expire=7 * 24 * 3600)
                
                logger.info(f"Token family revoked", family_id=family_id)
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to revoke token family: {str(e)}")
            return False
    
    async def _is_token_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        if not jti:
            return False
        
        revoke_key = f"revoked_token:{jti}"
        return await cache_service.exists(revoke_key)
    
    async def _is_family_valid(self, family_id: str) -> bool:
        """Check if token family is valid"""
        if not family_id:
            return True
        
        key = f"token_family:{family_id}"
        family_data = await cache_service.get(key)
        
        return family_data and family_data.get("valid", False)
    
    async def _validate_session(self, session_id: str) -> bool:
        """Validate session is still active"""
        session_key = f"session:{session_id}"
        session_data = await cache_service.get(session_key)
        return session_data is not None
    
    async def get_token_analytics(self, user_id: str) -> Dict[str, Any]:
        """Get token analytics for a user"""
        try:
            families_key = f"user_token_families:{user_id}"
            families = await cache_service.get_set_members(families_key)
            
            active_families = 0
            total_refresh_count = 0
            
            for family_id in families:
                key = f"token_family:{family_id}"
                family_data = await cache_service.get(key)
                
                if family_data and family_data.get("valid"):
                    active_families += 1
                    
                    # Get current refresh token metadata
                    refresh_jti = family_data.get("current_refresh_jti")
                    if refresh_jti:
                        metadata = await self._get_refresh_token_metadata(refresh_jti)
                        if metadata:
                            total_refresh_count += metadata.get("chain_count", 0)
            
            return {
                "total_families": len(families),
                "active_families": active_families,
                "total_refresh_count": total_refresh_count,
                "max_refresh_chain": self.max_refresh_chain_length,
                "rotation_enabled": self.refresh_token_rotation_enabled
            }
        
        except Exception as e:
            logger.error(f"Failed to get token analytics: {str(e)}")
            return {}


# Singleton instance
token_service = TokenService()