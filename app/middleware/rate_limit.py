from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request
import time
from collections import defaultdict
from typing import Dict, Tuple
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware to prevent abuse
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.rate_limit_storage: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, 0))
        self.requests_limit = settings.RATE_LIMIT_REQUESTS
        self.time_window = settings.RATE_LIMIT_PERIOD
    
    async def dispatch(self, request: Request, call_next):
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        client_id = self._get_client_id(request)
        
        if self._is_rate_limited(client_id):
            logger.warning(
                "Rate limit exceeded",
                client_id=client_id,
                path=request.url.path
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please try again later."}
            )
        
        self._update_rate_limit(client_id)
        
        response = await call_next(request)
        
        remaining = self.requests_limit - self.rate_limit_storage[client_id][0]
        response.headers["X-RateLimit-Limit"] = str(self.requests_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(int(self.rate_limit_storage[client_id][1] + self.time_window))
        
        return response
    
    def _get_client_id(self, request: Request) -> str:
        """Get unique client identifier"""
        if hasattr(request.state, "user_id") and request.state.user_id:
            return f"user:{request.state.user_id}"
        
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        
        return f"ip:{client_ip}"
    
    def _is_rate_limited(self, client_id: str) -> bool:
        """Check if client has exceeded rate limit"""
        count, first_request_time = self.rate_limit_storage[client_id]
        current_time = time.time()
        
        if current_time - first_request_time > self.time_window:
            self.rate_limit_storage[client_id] = (0, current_time)
            return False
        
        return count >= self.requests_limit
    
    def _update_rate_limit(self, client_id: str):
        """Update rate limit counter for client"""
        count, first_request_time = self.rate_limit_storage[client_id]
        current_time = time.time()
        
        if current_time - first_request_time > self.time_window:
            self.rate_limit_storage[client_id] = (1, current_time)
        else:
            self.rate_limit_storage[client_id] = (count + 1, first_request_time)