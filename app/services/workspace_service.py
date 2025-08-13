"""
Workspace/Teams Service
Handles multi-tenant workspace functionality with team collaboration
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import secrets
import uuid
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.cache import cache_service
from app.core.config import settings
from app.models.workspace import Workspace, WorkspaceMember, WorkspaceInvitation, WorkspaceRole
from app.services.email_service import email_service
from app.services.audit_service import audit_service
from app.services.activity_service import activity_service
from app.core.exceptions import (
    BadRequestError,
    NotFoundError,
    ForbiddenError,
    ConflictError
)


class MemberRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"
    GUEST = "guest"


class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class WorkspaceStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    DELETED = "deleted"


@dataclass
class WorkspaceSettings:
    """Workspace configuration settings"""
    allow_guest_access: bool = False
    require_2fa: bool = False
    allow_public_projects: bool = False
    max_members: int = 100
    max_projects: int = 50
    max_storage_gb: int = 100
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    default_member_role: str = MemberRole.MEMBER
    auto_join_domains: List[str] = field(default_factory=list)
    enable_sso: bool = False
    sso_provider: Optional[str] = None
    data_retention_days: int = 365
    audit_log_retention_days: int = 90
    custom_branding: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkspaceFeatures:
    """Feature flags for workspace"""
    analytics: bool = True
    advanced_permissions: bool = True
    custom_roles: bool = False
    api_access: bool = True
    webhooks: bool = True
    integrations: bool = True
    bulk_operations: bool = True
    export_data: bool = True
    custom_fields: bool = False
    automation: bool = False
    ai_features: bool = False


@dataclass
class WorkspaceQuota:
    """Resource quotas for workspace"""
    members_used: int = 0
    members_limit: int = 100
    projects_used: int = 0
    projects_limit: int = 50
    storage_used_gb: float = 0.0
    storage_limit_gb: float = 100.0
    api_calls_used: int = 0
    api_calls_limit: int = 100000
    seats_used: int = 0
    seats_limit: int = 100


class WorkspaceService:
    """Service for managing workspaces and teams"""
    
    def __init__(self):
        self.cache_ttl = 3600  # 1 hour
        self.invitation_expiry_days = 7
        self.max_workspaces_per_user = 10
        self.max_pending_invitations = 100
        
    async def create_workspace(
        self,
        name: str,
        owner_id: str,
        description: Optional[str] = None,
        settings: Optional[WorkspaceSettings] = None,
        features: Optional[WorkspaceFeatures] = None
    ) -> Dict[str, Any]:
        """Create a new workspace"""
        async with get_db() as session:
            # Check user workspace limit
            existing_count = await session.scalar(
                select(func.count(WorkspaceMember.id))
                .where(
                    and_(
                        WorkspaceMember.user_id == owner_id,
                        WorkspaceMember.role == MemberRole.OWNER
                    )
                )
            )
            
            if existing_count >= self.max_workspaces_per_user:
                raise BadRequestError(
                    f"Maximum workspace limit ({self.max_workspaces_per_user}) reached"
                )
            
            # Create workspace
            workspace = Workspace(
                id=str(uuid.uuid4()),
                name=name,
                slug=self._generate_slug(name),
                description=description,
                owner_id=owner_id,
                settings=settings.__dict__ if settings else WorkspaceSettings().__dict__,
                features=features.__dict__ if features else WorkspaceFeatures().__dict__,
                status=WorkspaceStatus.ACTIVE,
                created_at=datetime.utcnow()
            )
            
            session.add(workspace)
            
            # Add owner as member
            owner_member = WorkspaceMember(
                id=str(uuid.uuid4()),
                workspace_id=workspace.id,
                user_id=owner_id,
                role=MemberRole.OWNER,
                joined_at=datetime.utcnow()
            )
            
            session.add(owner_member)
            await session.commit()
            
            # Log activity
            await activity_service.log_activity(
                user_id=owner_id,
                action="workspace.created",
                resource_type="workspace",
                resource_id=workspace.id,
                details={"workspace_name": name}
            )
            
            # Clear cache
            await cache_service.delete(f"user_workspaces:{owner_id}")
            
            return {
                "id": workspace.id,
                "name": workspace.name,
                "slug": workspace.slug,
                "description": workspace.description,
                "owner_id": workspace.owner_id,
                "settings": workspace.settings,
                "features": workspace.features,
                "status": workspace.status,
                "created_at": workspace.created_at.isoformat()
            }
    
    async def get_workspace(
        self,
        workspace_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """Get workspace details"""
        # Check cache
        cache_key = f"workspace:{workspace_id}"
        cached = await cache_service.get(cache_key)
        if cached:
            # Verify user access
            if not await self._check_workspace_access(workspace_id, user_id):
                raise ForbiddenError("Access denied to workspace")
            return cached
        
        async with get_db() as session:
            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                raise NotFoundError("Workspace not found")
            
            # Check user access
            member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == user_id
                    )
                )
            )
            
            if not member:
                raise ForbiddenError("Access denied to workspace")
            
            # Get member count
            member_count = await session.scalar(
                select(func.count(WorkspaceMember.id))
                .where(WorkspaceMember.workspace_id == workspace_id)
            )
            
            result = {
                "id": workspace.id,
                "name": workspace.name,
                "slug": workspace.slug,
                "description": workspace.description,
                "owner_id": workspace.owner_id,
                "settings": workspace.settings,
                "features": workspace.features,
                "status": workspace.status,
                "member_count": member_count,
                "user_role": member.role,
                "created_at": workspace.created_at.isoformat(),
                "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None
            }
            
            # Cache result
            await cache_service.set(cache_key, result, ttl=self.cache_ttl)
            
            return result
    
    async def update_workspace(
        self,
        workspace_id: str,
        user_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        settings: Optional[WorkspaceSettings] = None,
        features: Optional[WorkspaceFeatures] = None
    ) -> Dict[str, Any]:
        """Update workspace details"""
        async with get_db() as session:
            # Check admin access
            if not await self._check_admin_access(workspace_id, user_id):
                raise ForbiddenError("Admin access required")
            
            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                raise NotFoundError("Workspace not found")
            
            # Update fields
            if name:
                workspace.name = name
                workspace.slug = self._generate_slug(name)
            if description is not None:
                workspace.description = description
            if settings:
                workspace.settings = {**workspace.settings, **settings.__dict__}
            if features:
                workspace.features = {**workspace.features, **features.__dict__}
            
            workspace.updated_at = datetime.utcnow()
            
            await session.commit()
            
            # Log activity
            await activity_service.log_activity(
                user_id=user_id,
                action="workspace.updated",
                resource_type="workspace",
                resource_id=workspace_id,
                details={"changes": {"name": name, "description": description}}
            )
            
            # Clear cache
            await cache_service.delete(f"workspace:{workspace_id}")
            
            return await self.get_workspace(workspace_id, user_id)
    
    async def delete_workspace(
        self,
        workspace_id: str,
        user_id: str,
        permanent: bool = False
    ) -> Dict[str, str]:
        """Delete or archive workspace"""
        async with get_db() as session:
            # Check owner access
            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                raise NotFoundError("Workspace not found")
            
            if workspace.owner_id != user_id:
                raise ForbiddenError("Only workspace owner can delete workspace")
            
            if permanent:
                # Permanent deletion
                await session.delete(workspace)
                action = "workspace.deleted"
            else:
                # Soft delete (archive)
                workspace.status = WorkspaceStatus.ARCHIVED
                workspace.deleted_at = datetime.utcnow()
                action = "workspace.archived"
            
            await session.commit()
            
            # Log activity
            await audit_service.log_audit_event(
                user_id=user_id,
                action=action,
                resource_type="workspace",
                resource_id=workspace_id,
                details={"permanent": permanent}
            )
            
            # Clear cache
            await cache_service.delete(f"workspace:{workspace_id}")
            await cache_service.delete(f"user_workspaces:{user_id}")
            
            return {"message": f"Workspace {'deleted' if permanent else 'archived'} successfully"}
    
    async def add_member(
        self,
        workspace_id: str,
        admin_id: str,
        user_id: str,
        role: str = MemberRole.MEMBER,
        permissions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Add member to workspace"""
        async with get_db() as session:
            # Check admin access
            if not await self._check_admin_access(workspace_id, admin_id):
                raise ForbiddenError("Admin access required")
            
            # Check if already member
            existing = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == user_id
                    )
                )
            )
            
            if existing:
                raise ConflictError("User is already a member")
            
            # Check workspace member limit
            workspace = await session.get(Workspace, workspace_id)
            member_count = await session.scalar(
                select(func.count(WorkspaceMember.id))
                .where(WorkspaceMember.workspace_id == workspace_id)
            )
            
            max_members = workspace.settings.get("max_members", 100)
            if member_count >= max_members:
                raise BadRequestError(f"Workspace member limit ({max_members}) reached")
            
            # Add member
            member = WorkspaceMember(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                user_id=user_id,
                role=role,
                permissions=permissions or [],
                joined_at=datetime.utcnow(),
                invited_by=admin_id
            )
            
            session.add(member)
            await session.commit()
            
            # Send notification
            await email_service.send_templated_email(
                to_email=user_id,  # Assuming user_id is email
                template="workspace_added",
                context={
                    "workspace_name": workspace.name,
                    "role": role
                }
            )
            
            # Log activity
            await activity_service.log_activity(
                user_id=admin_id,
                action="workspace.member_added",
                resource_type="workspace",
                resource_id=workspace_id,
                details={"new_member": user_id, "role": role}
            )
            
            # Clear cache
            await cache_service.delete(f"workspace_members:{workspace_id}")
            await cache_service.delete(f"user_workspaces:{user_id}")
            
            return {
                "id": member.id,
                "workspace_id": workspace_id,
                "user_id": user_id,
                "role": role,
                "permissions": permissions,
                "joined_at": member.joined_at.isoformat()
            }
    
    async def remove_member(
        self,
        workspace_id: str,
        admin_id: str,
        user_id: str
    ) -> Dict[str, str]:
        """Remove member from workspace"""
        async with get_db() as session:
            # Check admin access
            if not await self._check_admin_access(workspace_id, admin_id):
                raise ForbiddenError("Admin access required")
            
            # Check if user is owner
            workspace = await session.get(Workspace, workspace_id)
            if workspace.owner_id == user_id:
                raise BadRequestError("Cannot remove workspace owner")
            
            # Find and remove member
            member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == user_id
                    )
                )
            )
            
            if not member:
                raise NotFoundError("Member not found")
            
            await session.delete(member)
            await session.commit()
            
            # Log activity
            await activity_service.log_activity(
                user_id=admin_id,
                action="workspace.member_removed",
                resource_type="workspace",
                resource_id=workspace_id,
                details={"removed_member": user_id}
            )
            
            # Clear cache
            await cache_service.delete(f"workspace_members:{workspace_id}")
            await cache_service.delete(f"user_workspaces:{user_id}")
            
            return {"message": "Member removed successfully"}
    
    async def update_member_role(
        self,
        workspace_id: str,
        admin_id: str,
        user_id: str,
        new_role: str,
        permissions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Update member role and permissions"""
        async with get_db() as session:
            # Check admin access
            if not await self._check_admin_access(workspace_id, admin_id):
                raise ForbiddenError("Admin access required")
            
            # Check if trying to change owner
            workspace = await session.get(Workspace, workspace_id)
            if workspace.owner_id == user_id and new_role != MemberRole.OWNER:
                raise BadRequestError("Cannot change owner role")
            
            # Update member
            member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == user_id
                    )
                )
            )
            
            if not member:
                raise NotFoundError("Member not found")
            
            old_role = member.role
            member.role = new_role
            if permissions is not None:
                member.permissions = permissions
            member.updated_at = datetime.utcnow()
            
            await session.commit()
            
            # Log activity
            await activity_service.log_activity(
                user_id=admin_id,
                action="workspace.member_role_updated",
                resource_type="workspace",
                resource_id=workspace_id,
                details={
                    "user_id": user_id,
                    "old_role": old_role,
                    "new_role": new_role
                }
            )
            
            # Clear cache
            await cache_service.delete(f"workspace_members:{workspace_id}")
            
            return {
                "user_id": user_id,
                "role": new_role,
                "permissions": member.permissions,
                "updated_at": member.updated_at.isoformat()
            }
    
    async def create_invitation(
        self,
        workspace_id: str,
        inviter_id: str,
        email: str,
        role: str = MemberRole.MEMBER,
        message: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create workspace invitation"""
        async with get_db() as session:
            # Check admin access
            if not await self._check_admin_access(workspace_id, inviter_id):
                raise ForbiddenError("Admin access required")
            
            # Check if already invited
            existing = await session.scalar(
                select(WorkspaceInvitation).where(
                    and_(
                        WorkspaceInvitation.workspace_id == workspace_id,
                        WorkspaceInvitation.email == email,
                        WorkspaceInvitation.status == InvitationStatus.PENDING
                    )
                )
            )
            
            if existing:
                raise ConflictError("Invitation already pending for this email")
            
            # Check pending invitation limit
            pending_count = await session.scalar(
                select(func.count(WorkspaceInvitation.id))
                .where(
                    and_(
                        WorkspaceInvitation.workspace_id == workspace_id,
                        WorkspaceInvitation.status == InvitationStatus.PENDING
                    )
                )
            )
            
            if pending_count >= self.max_pending_invitations:
                raise BadRequestError(
                    f"Maximum pending invitations ({self.max_pending_invitations}) reached"
                )
            
            # Create invitation
            invitation = WorkspaceInvitation(
                id=str(uuid.uuid4()),
                workspace_id=workspace_id,
                email=email,
                role=role,
                token=secrets.token_urlsafe(32),
                inviter_id=inviter_id,
                message=message,
                status=InvitationStatus.PENDING,
                expires_at=datetime.utcnow() + timedelta(days=self.invitation_expiry_days),
                created_at=datetime.utcnow()
            )
            
            session.add(invitation)
            await session.commit()
            
            # Send invitation email
            workspace = await session.get(Workspace, workspace_id)
            await email_service.send_templated_email(
                to_email=email,
                template="workspace_invitation",
                context={
                    "workspace_name": workspace.name,
                    "inviter_name": inviter_id,  # Should be actual name
                    "role": role,
                    "message": message,
                    "invitation_link": f"{settings.FRONTEND_URL}/workspace/invite/{invitation.token}",
                    "expires_in_days": self.invitation_expiry_days
                }
            )
            
            # Log activity
            await activity_service.log_activity(
                user_id=inviter_id,
                action="workspace.invitation_sent",
                resource_type="workspace",
                resource_id=workspace_id,
                details={"email": email, "role": role}
            )
            
            return {
                "id": invitation.id,
                "workspace_id": workspace_id,
                "email": email,
                "role": role,
                "status": invitation.status,
                "expires_at": invitation.expires_at.isoformat()
            }
    
    async def accept_invitation(
        self,
        token: str,
        user_id: str
    ) -> Dict[str, Any]:
        """Accept workspace invitation"""
        async with get_db() as session:
            # Find invitation
            invitation = await session.scalar(
                select(WorkspaceInvitation).where(
                    WorkspaceInvitation.token == token
                )
            )
            
            if not invitation:
                raise NotFoundError("Invalid invitation token")
            
            # Check status
            if invitation.status != InvitationStatus.PENDING:
                raise BadRequestError(f"Invitation is {invitation.status}")
            
            # Check expiration
            if invitation.expires_at < datetime.utcnow():
                invitation.status = InvitationStatus.EXPIRED
                await session.commit()
                raise BadRequestError("Invitation has expired")
            
            # Accept invitation
            invitation.status = InvitationStatus.ACCEPTED
            invitation.accepted_at = datetime.utcnow()
            invitation.accepted_by = user_id
            
            # Add as member
            member = WorkspaceMember(
                id=str(uuid.uuid4()),
                workspace_id=invitation.workspace_id,
                user_id=user_id,
                role=invitation.role,
                joined_at=datetime.utcnow(),
                invited_by=invitation.inviter_id
            )
            
            session.add(member)
            await session.commit()
            
            # Log activity
            await activity_service.log_activity(
                user_id=user_id,
                action="workspace.invitation_accepted",
                resource_type="workspace",
                resource_id=invitation.workspace_id,
                details={"invitation_id": invitation.id}
            )
            
            # Clear cache
            await cache_service.delete(f"user_workspaces:{user_id}")
            
            return {
                "workspace_id": invitation.workspace_id,
                "role": invitation.role,
                "joined_at": member.joined_at.isoformat()
            }
    
    async def get_user_workspaces(
        self,
        user_id: str,
        include_archived: bool = False
    ) -> List[Dict[str, Any]]:
        """Get all workspaces for a user"""
        # Check cache
        cache_key = f"user_workspaces:{user_id}"
        if not include_archived:
            cached = await cache_service.get(cache_key)
            if cached:
                return cached
        
        async with get_db() as session:
            # Build query
            query = (
                select(Workspace, WorkspaceMember)
                .join(WorkspaceMember)
                .where(WorkspaceMember.user_id == user_id)
            )
            
            if not include_archived:
                query = query.where(Workspace.status != WorkspaceStatus.ARCHIVED)
            
            result = await session.execute(query)
            workspaces = []
            
            for workspace, member in result:
                workspaces.append({
                    "id": workspace.id,
                    "name": workspace.name,
                    "slug": workspace.slug,
                    "description": workspace.description,
                    "role": member.role,
                    "status": workspace.status,
                    "joined_at": member.joined_at.isoformat(),
                    "created_at": workspace.created_at.isoformat()
                })
            
            # Cache if not including archived
            if not include_archived:
                await cache_service.set(cache_key, workspaces, ttl=self.cache_ttl)
            
            return workspaces
    
    async def get_workspace_members(
        self,
        workspace_id: str,
        user_id: str,
        role_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get workspace members"""
        # Check access
        if not await self._check_workspace_access(workspace_id, user_id):
            raise ForbiddenError("Access denied to workspace")
        
        # Check cache
        cache_key = f"workspace_members:{workspace_id}"
        if not role_filter:
            cached = await cache_service.get(cache_key)
            if cached:
                return cached
        
        async with get_db() as session:
            query = select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id
            )
            
            if role_filter:
                query = query.where(WorkspaceMember.role == role_filter)
            
            result = await session.execute(query)
            members = []
            
            for member in result.scalars():
                members.append({
                    "id": member.id,
                    "user_id": member.user_id,
                    "role": member.role,
                    "permissions": member.permissions,
                    "joined_at": member.joined_at.isoformat(),
                    "invited_by": member.invited_by
                })
            
            # Cache if no filter
            if not role_filter:
                await cache_service.set(cache_key, members, ttl=self.cache_ttl)
            
            return members
    
    async def transfer_ownership(
        self,
        workspace_id: str,
        current_owner_id: str,
        new_owner_id: str
    ) -> Dict[str, str]:
        """Transfer workspace ownership"""
        async with get_db() as session:
            # Verify current owner
            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                raise NotFoundError("Workspace not found")
            
            if workspace.owner_id != current_owner_id:
                raise ForbiddenError("Only current owner can transfer ownership")
            
            # Check new owner is member
            new_owner_member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == new_owner_id
                    )
                )
            )
            
            if not new_owner_member:
                raise BadRequestError("New owner must be a workspace member")
            
            # Update workspace owner
            workspace.owner_id = new_owner_id
            workspace.updated_at = datetime.utcnow()
            
            # Update member roles
            new_owner_member.role = MemberRole.OWNER
            
            # Change old owner to admin
            old_owner_member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == current_owner_id
                    )
                )
            )
            if old_owner_member:
                old_owner_member.role = MemberRole.ADMIN
            
            await session.commit()
            
            # Log activity
            await audit_service.log_audit_event(
                user_id=current_owner_id,
                action="workspace.ownership_transferred",
                resource_type="workspace",
                resource_id=workspace_id,
                details={
                    "old_owner": current_owner_id,
                    "new_owner": new_owner_id
                }
            )
            
            # Clear cache
            await cache_service.delete(f"workspace:{workspace_id}")
            await cache_service.delete(f"workspace_members:{workspace_id}")
            
            return {"message": "Ownership transferred successfully"}
    
    async def get_workspace_quota(
        self,
        workspace_id: str,
        user_id: str
    ) -> WorkspaceQuota:
        """Get workspace resource usage and quotas"""
        # Check access
        if not await self._check_workspace_access(workspace_id, user_id):
            raise ForbiddenError("Access denied to workspace")
        
        async with get_db() as session:
            workspace = await session.get(Workspace, workspace_id)
            if not workspace:
                raise NotFoundError("Workspace not found")
            
            # Get member count
            member_count = await session.scalar(
                select(func.count(WorkspaceMember.id))
                .where(WorkspaceMember.workspace_id == workspace_id)
            )
            
            # Get settings
            settings = workspace.settings
            
            # Calculate quotas (simplified - in real app would query actual usage)
            quota = WorkspaceQuota(
                members_used=member_count,
                members_limit=settings.get("max_members", 100),
                projects_used=0,  # Would query projects table
                projects_limit=settings.get("max_projects", 50),
                storage_used_gb=0.0,  # Would calculate from files
                storage_limit_gb=settings.get("max_storage_gb", 100),
                api_calls_used=0,  # Would query from metrics
                api_calls_limit=100000,
                seats_used=member_count,
                seats_limit=settings.get("max_members", 100)
            )
            
            return quota
    
    def _generate_slug(self, name: str) -> str:
        """Generate URL-safe slug from name"""
        import re
        slug = name.lower()
        slug = re.sub(r'[^a-z0-9-]', '-', slug)
        slug = re.sub(r'-+', '-', slug)
        slug = slug.strip('-')
        
        # Add random suffix if needed
        if len(slug) < 3:
            slug = f"{slug}-{secrets.token_hex(3)}"
        
        return slug[:50]  # Limit length
    
    async def _check_workspace_access(
        self,
        workspace_id: str,
        user_id: str
    ) -> bool:
        """Check if user has access to workspace"""
        async with get_db() as session:
            member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == user_id
                    )
                )
            )
            return member is not None
    
    async def _check_admin_access(
        self,
        workspace_id: str,
        user_id: str
    ) -> bool:
        """Check if user has admin access to workspace"""
        async with get_db() as session:
            member = await session.scalar(
                select(WorkspaceMember).where(
                    and_(
                        WorkspaceMember.workspace_id == workspace_id,
                        WorkspaceMember.user_id == user_id,
                        WorkspaceMember.role.in_([MemberRole.OWNER, MemberRole.ADMIN])
                    )
                )
            )
            return member is not None


# Create singleton instance
workspace_service = WorkspaceService()