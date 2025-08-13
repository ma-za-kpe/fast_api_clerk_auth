from typing import Any, Optional, Dict, List
import json
import redis.asyncio as redis
from datetime import timedelta
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class CacheService:
    """
    Redis caching service for session management and temporary data
    """
    
    def __init__(self):
        self.redis_url = settings.REDIS_URL
        self.redis_client = None
        self._connected = False
    
    async def connect(self):
        """Connect to Redis"""
        if not self._connected:
            try:
                self.redis_client = await redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True
                )
                self._connected = True
                logger.info("Connected to Redis")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {str(e)}")
                raise
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self._connected and self.redis_client:
            await self.redis_client.close()
            self._connected = False
            logger.info("Disconnected from Redis")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            if not self._connected:
                await self.connect()
            
            value = await self.redis_client.get(key)
            
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get from cache: {str(e)}")
            return None
    
    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None
    ) -> bool:
        """Set value in cache with optional expiration"""
        try:
            if not self._connected:
                await self.connect()
            
            # Serialize value if it's not a string
            if not isinstance(value, str):
                value = json.dumps(value)
            
            if expire:
                result = await self.redis_client.setex(key, expire, value)
            else:
                result = await self.redis_client.set(key, value)
            
            return bool(result)
        
        except Exception as e:
            logger.error(f"Failed to set in cache: {str(e)}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if not self._connected:
                await self.connect()
            
            result = await self.redis_client.delete(key)
            return bool(result)
        
        except Exception as e:
            logger.error(f"Failed to delete from cache: {str(e)}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            if not self._connected:
                await self.connect()
            
            result = await self.redis_client.exists(key)
            return bool(result)
        
        except Exception as e:
            logger.error(f"Failed to check existence in cache: {str(e)}")
            return False
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration time for a key"""
        try:
            if not self._connected:
                await self.connect()
            
            result = await self.redis_client.expire(key, seconds)
            return bool(result)
        
        except Exception as e:
            logger.error(f"Failed to set expiration: {str(e)}")
            return False
    
    async def ttl(self, key: str) -> int:
        """Get time to live for a key"""
        try:
            if not self._connected:
                await self.connect()
            
            return await self.redis_client.ttl(key)
        
        except Exception as e:
            logger.error(f"Failed to get TTL: {str(e)}")
            return -1
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a counter"""
        try:
            if not self._connected:
                await self.connect()
            
            return await self.redis_client.incrby(key, amount)
        
        except Exception as e:
            logger.error(f"Failed to increment counter: {str(e)}")
            return None
    
    async def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """Decrement a counter"""
        try:
            if not self._connected:
                await self.connect()
            
            return await self.redis_client.decrby(key, amount)
        
        except Exception as e:
            logger.error(f"Failed to decrement counter: {str(e)}")
            return None
    
    async def get_pattern(self, pattern: str) -> Dict[str, Any]:
        """Get all keys matching a pattern"""
        try:
            if not self._connected:
                await self.connect()
            
            keys = await self.redis_client.keys(pattern)
            result = {}
            
            for key in keys:
                value = await self.get(key)
                if value:
                    result[key] = value
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to get pattern from cache: {str(e)}")
            return {}
    
    async def set_hash(self, key: str, field: str, value: Any) -> bool:
        """Set field in hash"""
        try:
            if not self._connected:
                await self.connect()
            
            if not isinstance(value, str):
                value = json.dumps(value)
            
            result = await self.redis_client.hset(key, field, value)
            return bool(result)
        
        except Exception as e:
            logger.error(f"Failed to set hash field: {str(e)}")
            return False
    
    async def get_hash(self, key: str, field: Optional[str] = None) -> Optional[Any]:
        """Get hash field or entire hash"""
        try:
            if not self._connected:
                await self.connect()
            
            if field:
                value = await self.redis_client.hget(key, field)
                if value:
                    try:
                        return json.loads(value)
                    except json.JSONDecodeError:
                        return value
            else:
                hash_data = await self.redis_client.hgetall(key)
                result = {}
                for k, v in hash_data.items():
                    try:
                        result[k] = json.loads(v)
                    except json.JSONDecodeError:
                        result[k] = v
                return result
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get hash: {str(e)}")
            return None
    
    async def add_to_set(self, key: str, *values) -> int:
        """Add values to a set"""
        try:
            if not self._connected:
                await self.connect()
            
            return await self.redis_client.sadd(key, *values)
        
        except Exception as e:
            logger.error(f"Failed to add to set: {str(e)}")
            return 0
    
    async def remove_from_set(self, key: str, *values) -> int:
        """Remove values from a set"""
        try:
            if not self._connected:
                await self.connect()
            
            return await self.redis_client.srem(key, *values)
        
        except Exception as e:
            logger.error(f"Failed to remove from set: {str(e)}")
            return 0
    
    async def get_set_members(self, key: str) -> List[str]:
        """Get all members of a set"""
        try:
            if not self._connected:
                await self.connect()
            
            return list(await self.redis_client.smembers(key))
        
        except Exception as e:
            logger.error(f"Failed to get set members: {str(e)}")
            return []
    
    async def is_set_member(self, key: str, value: str) -> bool:
        """Check if value is a member of a set"""
        try:
            if not self._connected:
                await self.connect()
            
            return await self.redis_client.sismember(key, value)
        
        except Exception as e:
            logger.error(f"Failed to check set membership: {str(e)}")
            return False
    
    async def push_to_list(self, key: str, *values) -> int:
        """Push values to a list"""
        try:
            if not self._connected:
                await self.connect()
            
            serialized_values = []
            for value in values:
                if not isinstance(value, str):
                    value = json.dumps(value)
                serialized_values.append(value)
            
            return await self.redis_client.rpush(key, *serialized_values)
        
        except Exception as e:
            logger.error(f"Failed to push to list: {str(e)}")
            return 0
    
    async def get_list(self, key: str, start: int = 0, end: int = -1) -> List[Any]:
        """Get list items"""
        try:
            if not self._connected:
                await self.connect()
            
            items = await self.redis_client.lrange(key, start, end)
            result = []
            
            for item in items:
                try:
                    result.append(json.loads(item))
                except json.JSONDecodeError:
                    result.append(item)
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to get list: {str(e)}")
            return []
    
    async def cache_user_session(
        self,
        session_id: str,
        user_id: str,
        data: Dict[str, Any],
        expire: int = 3600
    ) -> bool:
        """Cache user session data"""
        try:
            key = f"session:{session_id}"
            session_data = {
                "user_id": user_id,
                "data": data,
                "created_at": data.get("created_at")
            }
            
            return await self.set(key, session_data, expire)
        
        except Exception as e:
            logger.error(f"Failed to cache session: {str(e)}")
            return False
    
    async def get_user_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get cached user session"""
        try:
            key = f"session:{session_id}"
            return await self.get(key)
        
        except Exception as e:
            logger.error(f"Failed to get session: {str(e)}")
            return None
    
    async def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for a user"""
        try:
            if not self._connected:
                await self.connect()
            
            # Get all session keys for user
            pattern = f"session:*"
            keys = await self.redis_client.keys(pattern)
            
            deleted_count = 0
            for key in keys:
                session_data = await self.get(key)
                if session_data and session_data.get("user_id") == user_id:
                    if await self.delete(key):
                        deleted_count += 1
            
            return deleted_count
        
        except Exception as e:
            logger.error(f"Failed to invalidate sessions: {str(e)}")
            return 0


# Singleton instance
cache_service = CacheService()