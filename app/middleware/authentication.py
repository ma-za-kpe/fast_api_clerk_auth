from typing import Optional
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import structlog

from app.core.clerk import get_clerk_client
from app.core.exceptions import AuthenticationError

logger = structlog.get_logger()


class ClerkAuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to authenticate requests using Clerk
    """
    
    def __init__(self, app, exclude_paths: Optional[list] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/",
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/metrics",
            "/api/v1/auth/webhook",
        ]
        self.clerk = get_clerk_client()
    
    async def dispatch(self, request: Request, call_next):
        if self._should_skip_auth(request):
            return await call_next(request)
        
        try:
            auth_header = request.headers.get("Authorization")
            
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                
                auth_state = await self._authenticate_token(token)
                
                request.state.user_id = auth_state.get("user_id")
                request.state.session_id = auth_state.get("session_id")
                request.state.org_id = auth_state.get("org_id")
                request.state.is_authenticated = True
                request.state.auth_payload = auth_state.get("payload", {})
                
                logger.info(
                    "Request authenticated",
                    user_id=request.state.user_id,
                    path=request.url.path
                )
            else:
                request.state.is_authenticated = False
                request.state.user_id = None
                request.state.session_id = None
                request.state.org_id = None
                request.state.auth_payload = {}
        
        except AuthenticationError as e:
            logger.warning(
                "Authentication failed",
                path=request.url.path,
                error=str(e)
            )
            request.state.is_authenticated = False
            request.state.user_id = None
            request.state.session_id = None
            request.state.org_id = None
            request.state.auth_payload = {}
        
        except Exception as e:
            logger.error(
                "Unexpected error during authentication",
                path=request.url.path,
                error=str(e)
            )
            request.state.is_authenticated = False
            request.state.user_id = None
            request.state.session_id = None
            request.state.org_id = None
            request.state.auth_payload = {}
        
        response = await call_next(request)
        
        if hasattr(request.state, "user_id") and request.state.user_id:
            response.headers["X-User-ID"] = request.state.user_id
        
        return response
    
    def _should_skip_auth(self, request: Request) -> bool:
        """Check if the request path should skip authentication"""
        path = request.url.path
        
        for exclude_path in self.exclude_paths:
            if path.startswith(exclude_path):
                return True
        
        return False
    
    async def _authenticate_token(self, token: str) -> dict:
        """Authenticate a JWT token using Clerk"""
        try:
            return await self.clerk.verify_token(token)
        except Exception as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")


class HTTPBearerWithCookie(HTTPBearer):
    """
    Custom HTTPBearer that also checks for session cookie
    """
    
    async def __call__(self, request: Request) -> Optional[HTTPAuthorizationCredentials]:
        authorization = request.headers.get("Authorization")
        session_cookie = request.cookies.get("__session")
        
        if authorization:
            return await super().__call__(request)
        elif session_cookie:
            return HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials=session_cookie
            )
        else:
            if self.auto_error:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None