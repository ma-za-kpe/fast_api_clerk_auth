from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets
import structlog
from enum import Enum

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthorizationError
from app.services.cache_service import cache_service
from app.services.email_service import EmailService
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class InvitationStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class InvitationService:
    """
    Service for managing organization invitations
    """
    
    def __init__(self):
        self.default_expiry_days = 7
        self.max_invitations_per_org = 100
        self.max_bulk_invitations = 50
        self.email_service = EmailService()
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def create_invitation(
        self,
        org_id: str,
        inviter_id: str,
        email: str,
        role: str = "member",
        custom_message: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create an organization invitation
        """
        try:
            # Validate email
            if not self._validate_email(email):
                raise ValidationError("Invalid email address")
            
            # Check if user already exists
            clerk_client = await self._get_clerk_client()
            existing_users = await clerk_client.list_users(email_address=[email])
            
            if existing_users:
                # User exists - check if already a member
                user = existing_users[0]
                if await self._is_org_member(user.id, org_id):
                    raise ValidationError("User is already a member of this organization")
            
            # Check if invitation already exists
            existing_invitation = await self._get_pending_invitation(org_id, email)
            if existing_invitation:
                raise ValidationError("An invitation is already pending for this email")
            
            # Check organization invitation limit
            org_invitations = await self._get_org_invitations(org_id)
            if len(org_invitations) >= self.max_invitations_per_org:
                raise ValidationError(f"Organization has reached maximum of {self.max_invitations_per_org} invitations")
            
            # Generate invitation token
            invitation_id = secrets.token_urlsafe(16)
            invitation_token = secrets.token_urlsafe(32)
            
            # Calculate expiry
            expiry_days = expires_in_days or self.default_expiry_days
            expires_at = datetime.utcnow() + timedelta(days=expiry_days)
            
            # Create invitation data
            invitation_data = {
                "invitation_id": invitation_id,
                "org_id": org_id,
                "inviter_id": inviter_id,
                "email": email,
                "role": role,
                "token": invitation_token,
                "status": InvitationStatus.PENDING.value,
                "custom_message": custom_message,
                "metadata": metadata or {},
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at.isoformat(),
                "invitation_url": self._generate_invitation_url(invitation_token)
            }
            
            # Store invitation
            invitation_key = f"invitation:{invitation_id}"
            await cache_service.set(
                invitation_key,
                invitation_data,
                expire=expiry_days * 86400
            )
            
            # Add to organization's invitation list
            org_invitations_key = f"org_invitations:{org_id}"
            await cache_service.add_to_set(org_invitations_key, invitation_id)
            
            # Add to email index for quick lookup
            email_invitation_key = f"invitation_email:{org_id}:{email}"
            await cache_service.set(email_invitation_key, invitation_id, expire=expiry_days * 86400)
            
            # Send invitation email
            await self._send_invitation_email(invitation_data)
            
            logger.info(
                f"Invitation created",
                invitation_id=invitation_id,
                org_id=org_id,
                email=email
            )
            
            return {
                "invitation_id": invitation_id,
                "email": email,
                "role": role,
                "expires_at": expires_at.isoformat(),
                "invitation_url": invitation_data["invitation_url"],
                "status": InvitationStatus.PENDING.value
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to create invitation: {str(e)}")
            raise ValidationError("Failed to create invitation")
    
    async def create_bulk_invitations(
        self,
        org_id: str,
        inviter_id: str,
        emails: List[str],
        role: str = "member",
        custom_message: Optional[str] = None,
        expires_in_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create multiple invitations at once
        """
        try:
            if len(emails) > self.max_bulk_invitations:
                raise ValidationError(f"Maximum {self.max_bulk_invitations} invitations allowed at once")
            
            # Remove duplicates
            unique_emails = list(set(emails))
            
            successful = []
            failed = []
            
            for email in unique_emails:
                try:
                    result = await self.create_invitation(
                        org_id=org_id,
                        inviter_id=inviter_id,
                        email=email,
                        role=role,
                        custom_message=custom_message,
                        expires_in_days=expires_in_days
                    )
                    successful.append({
                        "email": email,
                        "invitation_id": result["invitation_id"]
                    })
                except ValidationError as e:
                    failed.append({
                        "email": email,
                        "error": str(e)
                    })
            
            logger.info(
                f"Bulk invitations created",
                org_id=org_id,
                successful_count=len(successful),
                failed_count=len(failed)
            )
            
            return {
                "successful": successful,
                "failed": failed,
                "total_sent": len(successful),
                "total_failed": len(failed)
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to create bulk invitations: {str(e)}")
            raise ValidationError("Failed to create bulk invitations")
    
    async def accept_invitation(
        self,
        invitation_token: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Accept an organization invitation
        """
        try:
            # Find invitation by token
            invitation_data = await self._get_invitation_by_token(invitation_token)
            
            if not invitation_data:
                raise ValidationError("Invalid or expired invitation")
            
            # Check if invitation is still pending
            if invitation_data["status"] != InvitationStatus.PENDING.value:
                raise ValidationError(f"Invitation is {invitation_data['status']}")
            
            # Check if invitation has expired
            expires_at = datetime.fromisoformat(invitation_data["expires_at"])
            if datetime.utcnow() > expires_at:
                # Update status to expired
                invitation_data["status"] = InvitationStatus.EXPIRED.value
                await self._update_invitation(invitation_data["invitation_id"], invitation_data)
                raise ValidationError("Invitation has expired")
            
            # Verify user email matches invitation
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            user_emails = [e.email_address for e in user.email_addresses]
            if invitation_data["email"] not in user_emails:
                raise ValidationError("Invitation email does not match user email")
            
            # Add user to organization
            org_id = invitation_data["org_id"]
            role = invitation_data["role"]
            
            # Create organization membership through Clerk
            await clerk_client.create_organization_membership(
                organization_id=org_id,
                user_id=user_id,
                role=role
            )
            
            # Update invitation status
            invitation_data["status"] = InvitationStatus.ACCEPTED.value
            invitation_data["accepted_at"] = datetime.utcnow().isoformat()
            invitation_data["accepted_by"] = user_id
            
            await self._update_invitation(invitation_data["invitation_id"], invitation_data)
            
            # Remove from pending invitations
            email_invitation_key = f"invitation_email:{org_id}:{invitation_data['email']}"
            await cache_service.delete(email_invitation_key)
            
            logger.info(
                f"Invitation accepted",
                invitation_id=invitation_data["invitation_id"],
                user_id=user_id,
                org_id=org_id
            )
            
            return {
                "success": True,
                "org_id": org_id,
                "role": role,
                "message": "Successfully joined organization"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to accept invitation: {str(e)}")
            raise ValidationError("Failed to accept invitation")
    
    async def reject_invitation(
        self,
        invitation_token: str,
        user_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Reject an organization invitation
        """
        try:
            # Find invitation by token
            invitation_data = await self._get_invitation_by_token(invitation_token)
            
            if not invitation_data:
                raise ValidationError("Invalid or expired invitation")
            
            # Check if invitation is still pending
            if invitation_data["status"] != InvitationStatus.PENDING.value:
                raise ValidationError(f"Invitation is {invitation_data['status']}")
            
            # Update invitation status
            invitation_data["status"] = InvitationStatus.REJECTED.value
            invitation_data["rejected_at"] = datetime.utcnow().isoformat()
            invitation_data["rejected_by"] = user_id
            invitation_data["rejection_reason"] = reason
            
            await self._update_invitation(invitation_data["invitation_id"], invitation_data)
            
            # Remove from pending invitations
            org_id = invitation_data["org_id"]
            email_invitation_key = f"invitation_email:{org_id}:{invitation_data['email']}"
            await cache_service.delete(email_invitation_key)
            
            logger.info(
                f"Invitation rejected",
                invitation_id=invitation_data["invitation_id"],
                user_id=user_id
            )
            
            return {
                "success": True,
                "message": "Invitation rejected"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to reject invitation: {str(e)}")
            raise ValidationError("Failed to reject invitation")
    
    async def revoke_invitation(
        self,
        invitation_id: str,
        revoker_id: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Revoke a pending invitation
        """
        try:
            # Get invitation data
            invitation_key = f"invitation:{invitation_id}"
            invitation_data = await cache_service.get(invitation_key)
            
            if not invitation_data:
                raise ValidationError("Invitation not found")
            
            # Check if invitation is still pending
            if invitation_data["status"] != InvitationStatus.PENDING.value:
                raise ValidationError(f"Cannot revoke {invitation_data['status']} invitation")
            
            # Update invitation status
            invitation_data["status"] = InvitationStatus.REVOKED.value
            invitation_data["revoked_at"] = datetime.utcnow().isoformat()
            invitation_data["revoked_by"] = revoker_id
            invitation_data["revocation_reason"] = reason
            
            await self._update_invitation(invitation_id, invitation_data)
            
            # Remove from pending invitations
            org_id = invitation_data["org_id"]
            email_invitation_key = f"invitation_email:{org_id}:{invitation_data['email']}"
            await cache_service.delete(email_invitation_key)
            
            logger.info(
                f"Invitation revoked",
                invitation_id=invitation_id,
                revoker_id=revoker_id
            )
            
            return {
                "success": True,
                "message": "Invitation revoked successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to revoke invitation: {str(e)}")
            raise ValidationError("Failed to revoke invitation")
    
    async def resend_invitation(
        self,
        invitation_id: str,
        sender_id: str
    ) -> Dict[str, Any]:
        """
        Resend an invitation email
        """
        try:
            # Get invitation data
            invitation_key = f"invitation:{invitation_id}"
            invitation_data = await cache_service.get(invitation_key)
            
            if not invitation_data:
                raise ValidationError("Invitation not found")
            
            # Check if invitation is still pending
            if invitation_data["status"] != InvitationStatus.PENDING.value:
                raise ValidationError(f"Cannot resend {invitation_data['status']} invitation")
            
            # Check if invitation has expired
            expires_at = datetime.fromisoformat(invitation_data["expires_at"])
            if datetime.utcnow() > expires_at:
                raise ValidationError("Invitation has expired")
            
            # Update resend information
            invitation_data["last_resent_at"] = datetime.utcnow().isoformat()
            invitation_data["last_resent_by"] = sender_id
            invitation_data["resend_count"] = invitation_data.get("resend_count", 0) + 1
            
            await self._update_invitation(invitation_id, invitation_data)
            
            # Resend email
            await self._send_invitation_email(invitation_data)
            
            logger.info(
                f"Invitation resent",
                invitation_id=invitation_id,
                sender_id=sender_id
            )
            
            return {
                "success": True,
                "message": "Invitation resent successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to resend invitation: {str(e)}")
            raise ValidationError("Failed to resend invitation")
    
    async def get_organization_invitations(
        self,
        org_id: str,
        status: Optional[str] = None,
        include_expired: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get all invitations for an organization
        """
        try:
            org_invitations_key = f"org_invitations:{org_id}"
            invitation_ids = await cache_service.get_set_members(org_invitations_key)
            
            invitations = []
            for invitation_id in invitation_ids:
                invitation_key = f"invitation:{invitation_id}"
                invitation_data = await cache_service.get(invitation_key)
                
                if invitation_data:
                    # Check if expired
                    expires_at = datetime.fromisoformat(invitation_data["expires_at"])
                    if datetime.utcnow() > expires_at:
                        if invitation_data["status"] == InvitationStatus.PENDING.value:
                            invitation_data["status"] = InvitationStatus.EXPIRED.value
                            await self._update_invitation(invitation_id, invitation_data)
                    
                    # Filter by status if specified
                    if status and invitation_data["status"] != status:
                        continue
                    
                    # Skip expired if not included
                    if not include_expired and invitation_data["status"] == InvitationStatus.EXPIRED.value:
                        continue
                    
                    # Add safe data (exclude token)
                    safe_data = {
                        "invitation_id": invitation_data["invitation_id"],
                        "email": invitation_data["email"],
                        "role": invitation_data["role"],
                        "status": invitation_data["status"],
                        "inviter_id": invitation_data["inviter_id"],
                        "created_at": invitation_data["created_at"],
                        "expires_at": invitation_data["expires_at"],
                        "resend_count": invitation_data.get("resend_count", 0)
                    }
                    
                    if invitation_data["status"] == InvitationStatus.ACCEPTED.value:
                        safe_data["accepted_at"] = invitation_data.get("accepted_at")
                        safe_data["accepted_by"] = invitation_data.get("accepted_by")
                    
                    invitations.append(safe_data)
            
            # Sort by creation date (newest first)
            invitations.sort(key=lambda x: x["created_at"], reverse=True)
            
            return invitations
        
        except Exception as e:
            logger.error(f"Failed to get organization invitations: {str(e)}")
            return []
    
    async def update_invitation_expiry(
        self,
        invitation_id: str,
        new_expiry_days: int
    ) -> Dict[str, Any]:
        """
        Update invitation expiry time
        """
        try:
            # Get invitation data
            invitation_key = f"invitation:{invitation_id}"
            invitation_data = await cache_service.get(invitation_key)
            
            if not invitation_data:
                raise ValidationError("Invitation not found")
            
            # Check if invitation is still pending
            if invitation_data["status"] != InvitationStatus.PENDING.value:
                raise ValidationError(f"Cannot update {invitation_data['status']} invitation")
            
            # Update expiry
            new_expires_at = datetime.utcnow() + timedelta(days=new_expiry_days)
            invitation_data["expires_at"] = new_expires_at.isoformat()
            invitation_data["expiry_updated_at"] = datetime.utcnow().isoformat()
            
            # Update cache expiry
            await cache_service.set(
                invitation_key,
                invitation_data,
                expire=new_expiry_days * 86400
            )
            
            logger.info(
                f"Invitation expiry updated",
                invitation_id=invitation_id,
                new_expiry_days=new_expiry_days
            )
            
            return {
                "success": True,
                "new_expires_at": new_expires_at.isoformat()
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to update invitation expiry: {str(e)}")
            raise ValidationError("Failed to update invitation expiry")
    
    # ============= Helper Methods =============
    
    def _validate_email(self, email: str) -> bool:
        """Basic email validation"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    async def _is_org_member(self, user_id: str, org_id: str) -> bool:
        """Check if user is already an organization member"""
        try:
            clerk_client = await self._get_clerk_client()
            memberships = await clerk_client.list_organization_memberships(
                organization_id=org_id,
                user_id=user_id
            )
            return len(memberships) > 0
        except:
            return False
    
    async def _get_pending_invitation(self, org_id: str, email: str) -> Optional[Dict[str, Any]]:
        """Get pending invitation for email"""
        email_invitation_key = f"invitation_email:{org_id}:{email}"
        invitation_id = await cache_service.get(email_invitation_key)
        
        if invitation_id:
            invitation_key = f"invitation:{invitation_id}"
            return await cache_service.get(invitation_key)
        
        return None
    
    async def _get_org_invitations(self, org_id: str) -> List[str]:
        """Get all invitation IDs for an organization"""
        org_invitations_key = f"org_invitations:{org_id}"
        return await cache_service.get_set_members(org_invitations_key)
    
    def _generate_invitation_url(self, token: str) -> str:
        """Generate invitation acceptance URL"""
        base_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:3000"
        return f"{base_url}/invitations/accept?token={token}"
    
    async def _send_invitation_email(self, invitation_data: Dict[str, Any]):
        """Send invitation email"""
        try:
            # Get organization details
            clerk_client = await self._get_clerk_client()
            org = await clerk_client.get_organization(invitation_data["org_id"])
            
            # Get inviter details
            inviter = await clerk_client.get_user(invitation_data["inviter_id"])
            
            email_data = {
                "organization_name": org.name,
                "inviter_name": f"{inviter.first_name} {inviter.last_name}",
                "role": invitation_data["role"],
                "invitation_url": invitation_data["invitation_url"],
                "custom_message": invitation_data.get("custom_message"),
                "expires_at": invitation_data["expires_at"]
            }
            
            await self.email_service.send_invitation_email(
                invitation_data["email"],
                email_data
            )
        
        except Exception as e:
            logger.error(f"Failed to send invitation email: {str(e)}")
    
    async def _get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Find invitation by token"""
        # This requires searching through all invitations
        # In production, you'd want to maintain a token index
        # For now, we'll search through recent invitations
        
        # Get all organizations (this would be limited in production)
        pattern = "invitation:*"
        invitations = await cache_service.get_pattern(pattern)
        
        for key, invitation_data in invitations.items():
            if invitation_data.get("token") == token:
                return invitation_data
        
        return None
    
    async def _update_invitation(self, invitation_id: str, invitation_data: Dict[str, Any]):
        """Update invitation data"""
        invitation_key = f"invitation:{invitation_id}"
        
        # Calculate remaining TTL
        ttl = await cache_service.ttl(invitation_key)
        if ttl > 0:
            await cache_service.set(invitation_key, invitation_data, expire=ttl)
        else:
            # Default to 7 days if TTL expired
            await cache_service.set(invitation_key, invitation_data, expire=7 * 86400)


# Singleton instance
invitation_service = InvitationService()