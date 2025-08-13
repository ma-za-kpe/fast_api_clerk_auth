import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
import structlog

logger = structlog.get_logger()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add unique request ID to each request
    """
    
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        
        request.state.request_id = request_id
        
        structlog.contextvars.bind_contextvars(request_id=request_id)
        
        logger.info(
            "Request started",
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown"
        )
        
        response = await call_next(request)
        
        response.headers["X-Request-ID"] = request_id
        
        logger.info(
            "Request completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code
        )
        
        structlog.contextvars.unbind_contextvars("request_id")
        
        return response