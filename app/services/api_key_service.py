from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import secrets
import hashlib
import structlog
from enum import Enum

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthenticationError, AuthorizationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class APIKeyScope(Enum):
    """API Key permission scopes"""
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    READ_ORGANIZATIONS = "read:organizations"
    WRITE_ORGANIZATIONS = "write:organizations"
    READ_SESSIONS = "read:sessions"
    WRITE_SESSIONS = "write:sessions"
    READ_WEBHOOKS = "read:webhooks"
    WRITE_WEBHOOKS = "write:webhooks"
    ADMIN = "admin:all"
    
    @classmethod
    def get_all_scopes(cls) -> List[str]:
        """Get all available scopes"""
        return [scope.value for scope in cls]
    
    @classmethod
    def get_read_scopes(cls) -> List[str]:
        """Get all read-only scopes"""
        return [scope.value for scope in cls if scope.value.startswith("read:")]
    
    @classmethod
    def get_write_scopes(cls) -> List[str]:
        """Get all write scopes"""
        return [scope.value for scope in cls if scope.value.startswith("write:")]


class APIKeyService:
    """
    API Key management service with rotation and scoped permissions
    """
    
    def __init__(self):
        self.key_prefix_public = "pk_"  # Publishable key prefix
        self.key_prefix_secret = "sk_"  # Secret key prefix
        self.key_length = 32
        self.max_keys_per_user = 10
        self.default_expiry_days = 90
        self.rotation_grace_period_hours = 24
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def create_api_key(
        self,
        user_id: str,
        name: str,
        key_type: str = "secret",
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None,
        allowed_ips: Optional[List[str]] = None,
        allowed_origins: Optional[List[str]] = None,
        rate_limit: Optional[int] = None  # requests per minute
    ) -> Dict[str, Any]:
        """
        Create a new API key with specified permissions
        """
        try:
            # Validate key type
            if key_type not in ["publishable", "secret"]:
                raise ValidationError("Invalid key type. Must be 'publishable' or 'secret'")
            
            # Check user's key limit
            user_keys = await self.get_user_api_keys(user_id)
            if len(user_keys) >= self.max_keys_per_user:
                raise ValidationError(f"Maximum of {self.max_keys_per_user} API keys allowed per user")
            
            # Validate scopes
            if scopes:
                invalid_scopes = set(scopes) - set(APIKeyScope.get_all_scopes())
                if invalid_scopes:
                    raise ValidationError(f"Invalid scopes: {', '.join(invalid_scopes)}")
            else:
                # Default scopes based on key type
                scopes = APIKeyScope.get_read_scopes() if key_type == "publishable" else []
            
            # Generate API key
            prefix = self.key_prefix_public if key_type == "publishable" else self.key_prefix_secret
            key_id = secrets.token_urlsafe(16)
            key_secret = secrets.token_urlsafe(self.key_length)
            api_key = f"{prefix}{key_secret}"
            
            # Hash the key for storage
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Calculate expiry
            expiry_days = expires_in_days or self.default_expiry_days
            expires_at = datetime.utcnow() + timedelta(days=expiry_days)
            
            # Create key metadata
            key_data = {
                "key_id": key_id,
                "user_id": user_id,
                "name": name,
                "type": key_type,
                "key_hash": key_hash,
                "key_prefix": api_key[:8] + "...",  # Store prefix for identification
                "scopes": scopes,
                "allowed_ips": allowed_ips or [],
                "allowed_origins": allowed_origins or [],
                "rate_limit": rate_limit or (1000 if key_type == "publishable" else 100),
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at.isoformat(),
                "last_used_at": None,
                "usage_count": 0,
                "active": True,
                "rotated": False
            }
            
            # Store key data
            storage_key = f"api_key:{key_id}"
            await cache_service.set(storage_key, key_data)
            
            # Add to user's key list
            user_keys_key = f"user_api_keys:{user_id}"
            await cache_service.add_to_set(user_keys_key, key_id)
            
            # Store key hash for quick lookup
            hash_key = f"api_key_hash:{key_hash}"
            await cache_service.set(hash_key, key_id, expire=expiry_days * 86400)
            
            logger.info(
                f"API key created for user {user_id}",
                key_id=key_id,
                key_type=key_type,
                scopes_count=len(scopes)
            )
            
            return {
                "key_id": key_id,
                "api_key": api_key,  # Only returned on creation
                "name": name,
                "type": key_type,
                "scopes": scopes,
                "expires_at": expires_at.isoformat(),
                "rate_limit": key_data["rate_limit"],
                "message": "Store this API key securely. It will not be shown again."
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to create API key: {str(e)}")
            raise ValidationError("Failed to create API key")
    
    async def rotate_api_key(
        self,
        user_id: str,
        key_id: str,
        immediate: bool = False
    ) -> Dict[str, Any]:
        """
        Rotate an API key with optional grace period
        """
        try:
            # Get existing key data
            storage_key = f"api_key:{key_id}"
            key_data = await cache_service.get(storage_key)
            
            if not key_data:
                raise ValidationError("API key not found")
            
            if key_data["user_id"] != user_id:
                raise AuthorizationError("Unauthorized to rotate this key")
            
            if key_data.get("rotated"):
                raise ValidationError("Key has already been rotated")
            
            # Generate new key
            new_key_result = await self.create_api_key(
                user_id=user_id,
                name=f"{key_data['name']} (Rotated)",
                key_type=key_data["type"],
                scopes=key_data["scopes"],
                expires_in_days=None,  # Use same expiry as original
                allowed_ips=key_data.get("allowed_ips"),
                allowed_origins=key_data.get("allowed_origins"),
                rate_limit=key_data.get("rate_limit")
            )
            
            # Mark old key as rotated
            key_data["rotated"] = True
            key_data["rotated_at"] = datetime.utcnow().isoformat()
            key_data["replacement_key_id"] = new_key_result["key_id"]
            
            if immediate:
                # Revoke immediately
                key_data["active"] = False
                key_data["revoked_at"] = datetime.utcnow().isoformat()
            else:
                # Set grace period expiry
                grace_expires = datetime.utcnow() + timedelta(hours=self.rotation_grace_period_hours)
                key_data["grace_period_expires"] = grace_expires.isoformat()
            
            # Update old key data
            await cache_service.set(storage_key, key_data)
            
            logger.info(
                f"API key rotated for user {user_id}",
                old_key_id=key_id,
                new_key_id=new_key_result["key_id"],
                immediate=immediate
            )
            
            return {
                "old_key_id": key_id,
                "new_key_id": new_key_result["key_id"],
                "new_api_key": new_key_result["api_key"],
                "grace_period_hours": 0 if immediate else self.rotation_grace_period_hours,
                "message": "API key rotated successfully. Update your applications with the new key."
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to rotate API key: {str(e)}")
            raise ValidationError("Failed to rotate API key")
    
    async def validate_api_key(
        self,
        api_key: str,
        required_scopes: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        origin: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate an API key and check permissions
        Returns (is_valid, key_data)
        """
        try:
            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Look up key by hash
            hash_key = f"api_key_hash:{key_hash}"
            key_id = await cache_service.get(hash_key)
            
            if not key_id:
                return False, None
            
            # Get key data
            storage_key = f"api_key:{key_id}"
            key_data = await cache_service.get(storage_key)
            
            if not key_data:
                return False, None
            
            # Check if key is active
            if not key_data.get("active"):
                logger.warning(f"Inactive API key used", key_id=key_id)
                return False, None
            
            # Check if key is expired
            expires_at = datetime.fromisoformat(key_data["expires_at"])
            if datetime.utcnow() > expires_at:
                logger.warning(f"Expired API key used", key_id=key_id)
                return False, None
            
            # Check if in grace period after rotation
            if key_data.get("rotated") and key_data.get("grace_period_expires"):
                grace_expires = datetime.fromisoformat(key_data["grace_period_expires"])
                if datetime.utcnow() > grace_expires:
                    key_data["active"] = False
                    await cache_service.set(storage_key, key_data)
                    logger.warning(f"API key grace period expired", key_id=key_id)
                    return False, None
            
            # Check IP restrictions
            if key_data.get("allowed_ips") and ip_address:
                if ip_address not in key_data["allowed_ips"]:
                    logger.warning(
                        f"API key used from unauthorized IP",
                        key_id=key_id,
                        ip_address=ip_address
                    )
                    return False, None
            
            # Check origin restrictions
            if key_data.get("allowed_origins") and origin:
                if not any(origin.startswith(allowed) for allowed in key_data["allowed_origins"]):
                    logger.warning(
                        f"API key used from unauthorized origin",
                        key_id=key_id,
                        origin=origin
                    )
                    return False, None
            
            # Check required scopes
            if required_scopes:
                key_scopes = set(key_data.get("scopes", []))
                
                # Admin scope has access to everything
                if APIKeyScope.ADMIN.value not in key_scopes:
                    missing_scopes = set(required_scopes) - key_scopes
                    if missing_scopes:
                        logger.warning(
                            f"API key missing required scopes",
                            key_id=key_id,
                            missing_scopes=list(missing_scopes)
                        )
                        return False, None
            
            # Check rate limit
            if not await self._check_rate_limit(key_id, key_data.get("rate_limit", 100)):
                logger.warning(f"API key rate limit exceeded", key_id=key_id)
                return False, None
            
            # Update usage statistics
            await self._update_key_usage(key_id)
            
            return True, {
                "key_id": key_id,
                "user_id": key_data["user_id"],
                "type": key_data["type"],
                "scopes": key_data["scopes"],
                "rate_limit": key_data["rate_limit"]
            }
        
        except Exception as e:
            logger.error(f"Failed to validate API key: {str(e)}")
            return False, None
    
    async def revoke_api_key(
        self,
        user_id: str,
        key_id: str,
        reason: Optional[str] = None
    ) -> bool:
        """
        Revoke an API key
        """
        try:
            # Get key data
            storage_key = f"api_key:{key_id}"
            key_data = await cache_service.get(storage_key)
            
            if not key_data:
                raise ValidationError("API key not found")
            
            if key_data["user_id"] != user_id:
                raise AuthorizationError("Unauthorized to revoke this key")
            
            # Mark as revoked
            key_data["active"] = False
            key_data["revoked_at"] = datetime.utcnow().isoformat()
            key_data["revoke_reason"] = reason
            
            # Update key data
            await cache_service.set(storage_key, key_data)
            
            # Remove from quick lookup
            hash_key = f"api_key_hash:{key_data['key_hash']}"
            await cache_service.delete(hash_key)
            
            logger.info(
                f"API key revoked",
                key_id=key_id,
                user_id=user_id,
                reason=reason
            )
            
            return True
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to revoke API key: {str(e)}")
            return False
    
    async def get_user_api_keys(
        self,
        user_id: str,
        include_revoked: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get all API keys for a user
        """
        try:
            user_keys_key = f"user_api_keys:{user_id}"
            key_ids = await cache_service.get_set_members(user_keys_key)
            
            keys = []
            for key_id in key_ids:
                storage_key = f"api_key:{key_id}"
                key_data = await cache_service.get(storage_key)
                
                if key_data:
                    if include_revoked or key_data.get("active", False):
                        # Don't include the actual key or hash
                        safe_data = {
                            "key_id": key_data["key_id"],
                            "name": key_data["name"],
                            "type": key_data["type"],
                            "key_prefix": key_data["key_prefix"],
                            "scopes": key_data["scopes"],
                            "created_at": key_data["created_at"],
                            "expires_at": key_data["expires_at"],
                            "last_used_at": key_data.get("last_used_at"),
                            "usage_count": key_data.get("usage_count", 0),
                            "active": key_data.get("active", False),
                            "rotated": key_data.get("rotated", False),
                            "rate_limit": key_data.get("rate_limit")
                        }
                        keys.append(safe_data)
            
            # Sort by creation date (newest first)
            keys.sort(key=lambda k: k["created_at"], reverse=True)
            
            return keys
        
        except Exception as e:
            logger.error(f"Failed to get user API keys: {str(e)}")
            return []
    
    async def update_api_key(
        self,
        user_id: str,
        key_id: str,
        name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        allowed_ips: Optional[List[str]] = None,
        allowed_origins: Optional[List[str]] = None,
        rate_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Update API key settings
        """
        try:
            # Get key data
            storage_key = f"api_key:{key_id}"
            key_data = await cache_service.get(storage_key)
            
            if not key_data:
                raise ValidationError("API key not found")
            
            if key_data["user_id"] != user_id:
                raise AuthorizationError("Unauthorized to update this key")
            
            if not key_data.get("active"):
                raise ValidationError("Cannot update revoked key")
            
            # Update fields
            if name is not None:
                key_data["name"] = name
            
            if scopes is not None:
                # Validate scopes
                invalid_scopes = set(scopes) - set(APIKeyScope.get_all_scopes())
                if invalid_scopes:
                    raise ValidationError(f"Invalid scopes: {', '.join(invalid_scopes)}")
                
                # Publishable keys can only have read scopes
                if key_data["type"] == "publishable":
                    write_scopes = set(scopes) & set(APIKeyScope.get_write_scopes())
                    if write_scopes:
                        raise ValidationError(f"Publishable keys cannot have write scopes: {', '.join(write_scopes)}")
                
                key_data["scopes"] = scopes
            
            if allowed_ips is not None:
                key_data["allowed_ips"] = allowed_ips
            
            if allowed_origins is not None:
                key_data["allowed_origins"] = allowed_origins
            
            if rate_limit is not None:
                key_data["rate_limit"] = rate_limit
            
            key_data["updated_at"] = datetime.utcnow().isoformat()
            
            # Save updated data
            await cache_service.set(storage_key, key_data)
            
            logger.info(f"API key updated", key_id=key_id, user_id=user_id)
            
            return {
                "key_id": key_id,
                "name": key_data["name"],
                "scopes": key_data["scopes"],
                "allowed_ips": key_data["allowed_ips"],
                "allowed_origins": key_data["allowed_origins"],
                "rate_limit": key_data["rate_limit"],
                "updated_at": key_data["updated_at"]
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to update API key: {str(e)}")
            raise ValidationError("Failed to update API key")
    
    # ============= Helper Methods =============
    
    async def _check_rate_limit(self, key_id: str, limit: int) -> bool:
        """Check if API key has exceeded rate limit"""
        rate_key = f"api_key_rate:{key_id}"
        current_minute = datetime.utcnow().strftime("%Y%m%d%H%M")
        rate_bucket_key = f"{rate_key}:{current_minute}"
        
        # Increment counter
        count = await cache_service.increment(rate_bucket_key)
        
        # Set expiry on first request
        if count == 1:
            await cache_service.expire(rate_bucket_key, 60)
        
        return count <= limit
    
    async def _update_key_usage(self, key_id: str):
        """Update API key usage statistics"""
        try:
            storage_key = f"api_key:{key_id}"
            key_data = await cache_service.get(storage_key)
            
            if key_data:
                key_data["last_used_at"] = datetime.utcnow().isoformat()
                key_data["usage_count"] = key_data.get("usage_count", 0) + 1
                await cache_service.set(storage_key, key_data)
        
        except Exception as e:
            logger.error(f"Failed to update key usage: {str(e)}")
    
    async def get_api_key_analytics(self, user_id: str) -> Dict[str, Any]:
        """Get API key usage analytics for a user"""
        try:
            keys = await self.get_user_api_keys(user_id, include_revoked=True)
            
            total_keys = len(keys)
            active_keys = len([k for k in keys if k["active"]])
            revoked_keys = len([k for k in keys if not k["active"]])
            
            # Calculate usage statistics
            total_usage = sum(k.get("usage_count", 0) for k in keys)
            
            # Key type breakdown
            publishable_keys = len([k for k in keys if k["type"] == "publishable"])
            secret_keys = len([k for k in keys if k["type"] == "secret"])
            
            # Most used key
            most_used_key = max(keys, key=lambda k: k.get("usage_count", 0)) if keys else None
            
            return {
                "total_keys": total_keys,
                "active_keys": active_keys,
                "revoked_keys": revoked_keys,
                "publishable_keys": publishable_keys,
                "secret_keys": secret_keys,
                "total_usage": total_usage,
                "most_used_key": {
                    "name": most_used_key["name"],
                    "usage_count": most_used_key.get("usage_count", 0)
                } if most_used_key else None,
                "max_keys_allowed": self.max_keys_per_user,
                "remaining_slots": max(0, self.max_keys_per_user - active_keys)
            }
        
        except Exception as e:
            logger.error(f"Failed to get API key analytics: {str(e)}")
            return {}


# Singleton instance
api_key_service = APIKeyService()