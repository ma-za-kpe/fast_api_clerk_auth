from typing import Optional, Dict, Any, List
from clerk_backend_api import Clerk
from clerk_backend_api.models import User, Session, Organization
from clerk_backend_api.security.types import AuthenticateRequestOptions
import httpx
import structlog
from functools import lru_cache

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ClerkAPIError
)

logger = structlog.get_logger()


class ClerkClient:
    """
    Wrapper class for Clerk SDK with additional functionality
    """
    
    def __init__(self):
        self.client = Clerk(bearer_auth=settings.CLERK_SECRET_KEY)
        self.publishable_key = settings.CLERK_PUBLISHABLE_KEY
        self.jwt_key = settings.CLERK_JWT_VERIFICATION_KEY
        
    def authenticate_request(
        self,
        request: httpx.Request,
        authorized_parties: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Authenticate a request using Clerk
        """
        try:
            options = AuthenticateRequestOptions(
                authorized_parties=authorized_parties or [settings.FRONTEND_URL]
            )
            
            request_state = self.client.authenticate_request(request, options)
            
            if not request_state.is_signed_in:
                logger.warning(
                    "Authentication failed",
                    reason=request_state.reason
                )
                raise AuthenticationError(f"Authentication failed: {request_state.reason}")
            
            return {
                "is_signed_in": request_state.is_signed_in,
                "user_id": request_state.user_id,
                "session_id": request_state.session_id,
                "org_id": request_state.org_id,
                "payload": request_state.payload
            }
            
        except Exception as e:
            logger.error("Failed to authenticate request", error=str(e))
            raise AuthenticationError(f"Failed to authenticate: {str(e)}")
    
    async def get_user(self, user_id: str) -> Optional[User]:
        """
        Get user by ID from Clerk
        """
        try:
            response = await self.client.users.get(user_id=user_id)
            return response
        except Exception as e:
            logger.error(f"Failed to get user {user_id}", error=str(e))
            raise ClerkAPIError(f"Failed to get user: {str(e)}")
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email from Clerk
        """
        try:
            response = await self.client.users.list(email_address=[email])
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
            logger.error(f"Failed to get user by email {email}", error=str(e))
            raise ClerkAPIError(f"Failed to get user: {str(e)}")
    
    async def create_user(
        self,
        email_address: str,
        password: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
        phone_number: Optional[str] = None,
        public_metadata: Optional[Dict[str, Any]] = None,
        private_metadata: Optional[Dict[str, Any]] = None,
        unsafe_metadata: Optional[Dict[str, Any]] = None
    ) -> User:
        """
        Create a new user in Clerk
        """
        try:
            user_data = {
                "email_addresses": [email_address],
                "first_name": first_name,
                "last_name": last_name,
                "username": username,
                "phone_numbers": [phone_number] if phone_number else None,
                "public_metadata": public_metadata or {},
                "private_metadata": private_metadata or {},
                "unsafe_metadata": unsafe_metadata or {}
            }
            
            if password:
                user_data["password"] = password
            
            response = await self.client.users.create(**user_data)
            logger.info(f"User created successfully", user_id=response.id)
            return response
            
        except Exception as e:
            logger.error("Failed to create user", error=str(e))
            raise ClerkAPIError(f"Failed to create user: {str(e)}")
    
    async def update_user(
        self,
        user_id: str,
        **kwargs
    ) -> User:
        """
        Update user information in Clerk
        """
        try:
            response = await self.client.users.update(user_id=user_id, **kwargs)
            logger.info(f"User updated successfully", user_id=user_id)
            return response
        except Exception as e:
            logger.error(f"Failed to update user {user_id}", error=str(e))
            raise ClerkAPIError(f"Failed to update user: {str(e)}")
    
    async def delete_user(self, user_id: str) -> bool:
        """
        Delete a user from Clerk
        """
        try:
            await self.client.users.delete(user_id=user_id)
            logger.info(f"User deleted successfully", user_id=user_id)
            return True
        except Exception as e:
            logger.error(f"Failed to delete user {user_id}", error=str(e))
            raise ClerkAPIError(f"Failed to delete user: {str(e)}")
    
    async def list_users(
        self,
        limit: int = 10,
        offset: int = 0,
        email_address: Optional[List[str]] = None,
        phone_number: Optional[List[str]] = None,
        username: Optional[List[str]] = None,
        order_by: str = "-created_at"
    ) -> List[User]:
        """
        List users from Clerk with pagination and filters
        """
        try:
            response = await self.client.users.list(
                limit=limit,
                offset=offset,
                email_address=email_address,
                phone_number=phone_number,
                username=username,
                order_by=order_by
            )
            return response.data
        except Exception as e:
            logger.error("Failed to list users", error=str(e))
            raise ClerkAPIError(f"Failed to list users: {str(e)}")
    
    async def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get session by ID from Clerk
        """
        try:
            response = await self.client.sessions.get(session_id=session_id)
            return response
        except Exception as e:
            logger.error(f"Failed to get session {session_id}", error=str(e))
            raise ClerkAPIError(f"Failed to get session: {str(e)}")
    
    async def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session in Clerk
        """
        try:
            await self.client.sessions.revoke(session_id=session_id)
            logger.info(f"Session revoked successfully", session_id=session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to revoke session {session_id}", error=str(e))
            raise ClerkAPIError(f"Failed to revoke session: {str(e)}")
    
    async def list_user_sessions(self, user_id: str) -> List[Session]:
        """
        List all sessions for a user
        """
        try:
            response = await self.client.sessions.list(user_id=user_id, status="active")
            return response.data
        except Exception as e:
            logger.error(f"Failed to list sessions for user {user_id}", error=str(e))
            raise ClerkAPIError(f"Failed to list sessions: {str(e)}")
    
    async def create_organization(
        self,
        name: str,
        created_by: str,
        slug: Optional[str] = None,
        public_metadata: Optional[Dict[str, Any]] = None,
        private_metadata: Optional[Dict[str, Any]] = None
    ) -> Organization:
        """
        Create a new organization in Clerk
        """
        try:
            response = await self.client.organizations.create(
                name=name,
                created_by=created_by,
                slug=slug,
                public_metadata=public_metadata or {},
                private_metadata=private_metadata or {}
            )
            logger.info(f"Organization created successfully", org_id=response.id)
            return response
        except Exception as e:
            logger.error("Failed to create organization", error=str(e))
            raise ClerkAPIError(f"Failed to create organization: {str(e)}")
    
    async def get_organization(self, org_id: str) -> Optional[Organization]:
        """
        Get organization by ID from Clerk
        """
        try:
            response = await self.client.organizations.get(organization_id=org_id)
            return response
        except Exception as e:
            logger.error(f"Failed to get organization {org_id}", error=str(e))
            raise ClerkAPIError(f"Failed to get organization: {str(e)}")
    
    async def update_organization(
        self,
        org_id: str,
        **kwargs
    ) -> Organization:
        """
        Update organization information in Clerk
        """
        try:
            response = await self.client.organizations.update(
                organization_id=org_id,
                **kwargs
            )
            logger.info(f"Organization updated successfully", org_id=org_id)
            return response
        except Exception as e:
            logger.error(f"Failed to update organization {org_id}", error=str(e))
            raise ClerkAPIError(f"Failed to update organization: {str(e)}")
    
    async def delete_organization(self, org_id: str) -> bool:
        """
        Delete an organization from Clerk
        """
        try:
            await self.client.organizations.delete(organization_id=org_id)
            logger.info(f"Organization deleted successfully", org_id=org_id)
            return True
        except Exception as e:
            logger.error(f"Failed to delete organization {org_id}", error=str(e))
            raise ClerkAPIError(f"Failed to delete organization: {str(e)}")
    
    async def add_organization_member(
        self,
        org_id: str,
        user_id: str,
        role: str = "member"
    ) -> bool:
        """
        Add a member to an organization
        """
        try:
            await self.client.organization_memberships.create(
                organization_id=org_id,
                user_id=user_id,
                role=role
            )
            logger.info(f"Member added to organization", org_id=org_id, user_id=user_id)
            return True
        except Exception as e:
            logger.error(f"Failed to add member to organization", error=str(e))
            raise ClerkAPIError(f"Failed to add member: {str(e)}")
    
    async def remove_organization_member(
        self,
        org_id: str,
        user_id: str
    ) -> bool:
        """
        Remove a member from an organization
        """
        try:
            memberships = await self.client.organization_memberships.list(
                organization_id=org_id,
                user_id=user_id
            )
            
            if memberships.data:
                membership_id = memberships.data[0].id
                await self.client.organization_memberships.delete(
                    organization_id=org_id,
                    membership_id=membership_id
                )
                logger.info(f"Member removed from organization", org_id=org_id, user_id=user_id)
                return True
            
            return False
        except Exception as e:
            logger.error(f"Failed to remove member from organization", error=str(e))
            raise ClerkAPIError(f"Failed to remove member: {str(e)}")
    
    async def list_organization_members(
        self,
        org_id: str,
        limit: int = 10,
        offset: int = 0
    ) -> List[Any]:
        """
        List members of an organization
        """
        try:
            response = await self.client.organization_memberships.list(
                organization_id=org_id,
                limit=limit,
                offset=offset
            )
            return response.data
        except Exception as e:
            logger.error(f"Failed to list organization members", error=str(e))
            raise ClerkAPIError(f"Failed to list members: {str(e)}")
    
    async def create_invitation(
        self,
        email_address: str,
        org_id: Optional[str] = None,
        redirect_url: Optional[str] = None,
        public_metadata: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Create an invitation to join the application or organization
        """
        try:
            invitation_data = {
                "email_address": email_address,
                "redirect_url": redirect_url or settings.FRONTEND_URL,
                "public_metadata": public_metadata or {}
            }
            
            if org_id:
                response = await self.client.organization_invitations.create(
                    organization_id=org_id,
                    **invitation_data
                )
            else:
                response = await self.client.invitations.create(**invitation_data)
            
            logger.info(f"Invitation created successfully", email=email_address)
            return response
        except Exception as e:
            logger.error(f"Failed to create invitation", error=str(e))
            raise ClerkAPIError(f"Failed to create invitation: {str(e)}")
    
    async def revoke_invitation(
        self,
        invitation_id: str,
        org_id: Optional[str] = None
    ) -> bool:
        """
        Revoke an invitation
        """
        try:
            if org_id:
                await self.client.organization_invitations.revoke(
                    organization_id=org_id,
                    invitation_id=invitation_id
                )
            else:
                await self.client.invitations.revoke(invitation_id=invitation_id)
            
            logger.info(f"Invitation revoked successfully", invitation_id=invitation_id)
            return True
        except Exception as e:
            logger.error(f"Failed to revoke invitation", error=str(e))
            raise ClerkAPIError(f"Failed to revoke invitation: {str(e)}")
    
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify a JWT token from Clerk
        """
        try:
            import jwt
            
            if not self.jwt_key:
                raise ValueError("JWT verification key not configured")
            
            decoded = jwt.decode(
                token,
                self.jwt_key,
                algorithms=["RS256"],
                audience=self.publishable_key
            )
            
            return decoded
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to verify token", error=str(e))
            raise AuthenticationError(f"Failed to verify token: {str(e)}")


@lru_cache()
def get_clerk_client() -> ClerkClient:
    """
    Get cached Clerk client instance
    """
    return ClerkClient()