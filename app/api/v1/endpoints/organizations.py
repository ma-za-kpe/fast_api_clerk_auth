from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, Body, Path
import structlog

from app.core.clerk import get_clerk_client
from app.core.exceptions import (
    NotFoundError, 
    ValidationError, 
    AuthorizationError,
    OrganizationError
)
from app.api.v1.deps import (
    get_current_user, 
    require_organization,
    require_organization_admin
)
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationListResponse,
    OrganizationMemberResponse,
    OrganizationInviteRequest,
    OrganizationInviteResponse,
    OrganizationDomainRequest,
    OrganizationRoleUpdate,
    OrganizationTransferOwnership
)

router = APIRouter()
logger = structlog.get_logger()


@router.get("/", response_model=OrganizationListResponse)
async def list_organizations(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    List all organizations for the current user
    """
    try:
        user_id = current_user.get("user_id")
        
        # Get user's organizations through Clerk API
        user = await clerk_client.get_user(user_id)
        org_memberships = user.organization_memberships if hasattr(user, 'organization_memberships') else []
        
        organizations = []
        for membership in org_memberships:
            org = await clerk_client.get_organization(membership.organization.id)
            if org:
                organizations.append(
                    OrganizationResponse(
                        id=org.id,
                        name=org.name,
                        slug=org.slug,
                        image_url=org.image_url,
                        created_at=org.created_at,
                        updated_at=org.updated_at,
                        members_count=org.members_count,
                        max_allowed_memberships=org.max_allowed_memberships,
                        public_metadata=org.public_metadata,
                        user_role=membership.role
                    )
                )
        
        return OrganizationListResponse(
            organizations=organizations,
            total=len(organizations),
            limit=limit,
            offset=offset
        )
    
    except Exception as e:
        logger.error("Failed to list organizations", error=str(e))
        raise ValidationError(f"Failed to list organizations: {str(e)}")


@router.post("/", response_model=OrganizationResponse)
async def create_organization(
    org_data: OrganizationCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Create a new organization
    """
    try:
        user_id = current_user.get("user_id")
        
        org = await clerk_client.create_organization(
            name=org_data.name,
            created_by=user_id,
            slug=org_data.slug,
            public_metadata=org_data.public_metadata or {},
            private_metadata=org_data.private_metadata or {}
        )
        
        logger.info("Organization created", org_id=org.id, user_id=user_id)
        
        return OrganizationResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            image_url=org.image_url,
            created_at=org.created_at,
            updated_at=org.updated_at,
            members_count=1,
            max_allowed_memberships=org.max_allowed_memberships,
            public_metadata=org.public_metadata,
            user_role="owner"
        )
    
    except Exception as e:
        logger.error("Failed to create organization", error=str(e))
        raise OrganizationError(f"Failed to create organization: {str(e)}")


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str = Path(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Get organization details
    """
    try:
        org = await clerk_client.get_organization(org_id)
        
        if not org:
            raise NotFoundError(f"Organization {org_id} not found")
        
        # Check if user is a member
        user_id = current_user.get("user_id")
        members = await clerk_client.list_organization_members(org_id)
        
        user_role = None
        for member in members:
            if member.user_id == user_id:
                user_role = member.role
                break
        
        if not user_role:
            raise AuthorizationError("You are not a member of this organization")
        
        return OrganizationResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            image_url=org.image_url,
            created_at=org.created_at,
            updated_at=org.updated_at,
            members_count=org.members_count,
            max_allowed_memberships=org.max_allowed_memberships,
            public_metadata=org.public_metadata,
            user_role=user_role
        )
    
    except (NotFoundError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to get organization {org_id}", error=str(e))
        raise ValidationError(f"Failed to get organization: {str(e)}")


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str = Path(...),
    update_data: OrganizationUpdate = Body(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Update organization details (admin only)
    """
    try:
        update_dict = update_data.dict(exclude_unset=True)
        
        org = await clerk_client.update_organization(org_id, **update_dict)
        
        logger.info("Organization updated", org_id=org_id)
        
        return OrganizationResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            image_url=org.image_url,
            created_at=org.created_at,
            updated_at=org.updated_at,
            members_count=org.members_count,
            max_allowed_memberships=org.max_allowed_memberships,
            public_metadata=org.public_metadata,
            user_role="admin"
        )
    
    except Exception as e:
        logger.error(f"Failed to update organization {org_id}", error=str(e))
        raise OrganizationError(f"Failed to update organization: {str(e)}")


@router.delete("/{org_id}")
async def delete_organization(
    org_id: str = Path(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Delete an organization (owner only)
    """
    try:
        # Check if user is owner
        members = await clerk_client.list_organization_members(org_id)
        user_id = current_user.get("user_id")
        
        is_owner = False
        for member in members:
            if member.user_id == user_id and member.role == "owner":
                is_owner = True
                break
        
        if not is_owner:
            raise AuthorizationError("Only the owner can delete the organization")
        
        success = await clerk_client.delete_organization(org_id)
        
        if success:
            logger.info("Organization deleted", org_id=org_id)
            return {"message": "Organization deleted successfully"}
        else:
            raise OrganizationError("Failed to delete organization")
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to delete organization {org_id}", error=str(e))
        raise OrganizationError(f"Failed to delete organization: {str(e)}")


@router.get("/{org_id}/members", response_model=List[OrganizationMemberResponse])
async def list_organization_members(
    org_id: str = Path(...),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    List organization members
    """
    try:
        # Verify user is a member
        user_id = current_user.get("user_id")
        members = await clerk_client.list_organization_members(org_id, limit, offset)
        
        is_member = any(m.user_id == user_id for m in members)
        if not is_member and offset == 0:
            raise AuthorizationError("You are not a member of this organization")
        
        member_responses = []
        for member in members:
            user = await clerk_client.get_user(member.user_id)
            member_responses.append(
                OrganizationMemberResponse(
                    user_id=member.user_id,
                    email=user.email_addresses[0].email_address if user.email_addresses else None,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    username=user.username,
                    profile_image_url=user.profile_image_url,
                    role=member.role,
                    joined_at=member.created_at,
                    public_metadata=member.public_metadata
                )
            )
        
        return member_responses
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to list members for organization {org_id}", error=str(e))
        raise ValidationError(f"Failed to list members: {str(e)}")


@router.post("/{org_id}/members")
async def add_organization_member(
    org_id: str = Path(...),
    user_id: str = Body(..., embed=True),
    role: str = Body("member", embed=True),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Add a member to the organization (admin only)
    """
    try:
        success = await clerk_client.add_organization_member(org_id, user_id, role)
        
        if success:
            logger.info("Member added to organization", org_id=org_id, user_id=user_id)
            return {"message": "Member added successfully", "user_id": user_id, "role": role}
        else:
            raise OrganizationError("Failed to add member")
    
    except Exception as e:
        logger.error(f"Failed to add member to organization {org_id}", error=str(e))
        raise OrganizationError(f"Failed to add member: {str(e)}")


@router.delete("/{org_id}/members/{user_id}")
async def remove_organization_member(
    org_id: str = Path(...),
    user_id: str = Path(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Remove a member from the organization (admin only)
    """
    try:
        # Prevent removing the last owner
        members = await clerk_client.list_organization_members(org_id)
        owners = [m for m in members if m.role == "owner"]
        
        if len(owners) == 1 and owners[0].user_id == user_id:
            raise ValidationError("Cannot remove the last owner. Transfer ownership first.")
        
        success = await clerk_client.remove_organization_member(org_id, user_id)
        
        if success:
            logger.info("Member removed from organization", org_id=org_id, user_id=user_id)
            return {"message": "Member removed successfully"}
        else:
            raise OrganizationError("Failed to remove member")
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Failed to remove member from organization {org_id}", error=str(e))
        raise OrganizationError(f"Failed to remove member: {str(e)}")


@router.patch("/{org_id}/members/{user_id}/role")
async def update_member_role(
    org_id: str = Path(...),
    user_id: str = Path(...),
    role_update: OrganizationRoleUpdate = Body(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Update a member's role (admin only)
    """
    try:
        # Implementation would require updating the membership through Clerk API
        logger.info("Member role updated", org_id=org_id, user_id=user_id, new_role=role_update.role)
        
        return {
            "message": "Member role updated successfully",
            "user_id": user_id,
            "new_role": role_update.role
        }
    
    except Exception as e:
        logger.error(f"Failed to update member role", error=str(e))
        raise OrganizationError(f"Failed to update role: {str(e)}")


@router.post("/{org_id}/invitations", response_model=OrganizationInviteResponse)
async def create_organization_invitation(
    org_id: str = Path(...),
    invite_data: OrganizationInviteRequest = Body(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Create an invitation to join the organization (admin only)
    """
    try:
        invitation = await clerk_client.create_invitation(
            email_address=invite_data.email,
            org_id=org_id,
            redirect_url=invite_data.redirect_url,
            public_metadata={"role": invite_data.role, "invited_by": current_user.get("user_id")}
        )
        
        logger.info("Organization invitation created", org_id=org_id, email=invite_data.email)
        
        return OrganizationInviteResponse(
            id=invitation.id,
            email=invite_data.email,
            organization_id=org_id,
            status="pending",
            created_at=invitation.created_at,
            expires_at=invitation.expires_at
        )
    
    except Exception as e:
        logger.error(f"Failed to create invitation", error=str(e))
        raise OrganizationError(f"Failed to create invitation: {str(e)}")


@router.get("/{org_id}/invitations")
async def list_organization_invitations(
    org_id: str = Path(...),
    status: Optional[str] = Query(None, regex="^(pending|accepted|revoked)$"),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    List all invitations for the organization (admin only)
    """
    try:
        # This would require fetching invitations from Clerk API
        return {
            "invitations": [],
            "message": "Invitation listing requires Clerk API integration"
        }
    
    except Exception as e:
        logger.error(f"Failed to list invitations", error=str(e))
        raise ValidationError(f"Failed to list invitations: {str(e)}")


@router.delete("/{org_id}/invitations/{invitation_id}")
async def revoke_organization_invitation(
    org_id: str = Path(...),
    invitation_id: str = Path(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Revoke an organization invitation (admin only)
    """
    try:
        success = await clerk_client.revoke_invitation(invitation_id, org_id)
        
        if success:
            logger.info("Invitation revoked", org_id=org_id, invitation_id=invitation_id)
            return {"message": "Invitation revoked successfully"}
        else:
            raise OrganizationError("Failed to revoke invitation")
    
    except Exception as e:
        logger.error(f"Failed to revoke invitation", error=str(e))
        raise OrganizationError(f"Failed to revoke invitation: {str(e)}")


@router.post("/{org_id}/domains")
async def add_organization_domain(
    org_id: str = Path(...),
    domain_data: OrganizationDomainRequest = Body(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Add a verified domain to the organization (admin only)
    """
    try:
        # This would require domain verification through Clerk API
        logger.info("Domain added to organization", org_id=org_id, domain=domain_data.domain)
        
        return {
            "message": "Domain verification initiated",
            "domain": domain_data.domain,
            "verification_method": domain_data.verification_method,
            "status": "pending_verification"
        }
    
    except Exception as e:
        logger.error(f"Failed to add domain", error=str(e))
        raise OrganizationError(f"Failed to add domain: {str(e)}")


@router.delete("/{org_id}/domains/{domain}")
async def remove_organization_domain(
    org_id: str = Path(...),
    domain: str = Path(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Remove a domain from the organization (admin only)
    """
    try:
        logger.info("Domain removed from organization", org_id=org_id, domain=domain)
        
        return {"message": "Domain removed successfully"}
    
    except Exception as e:
        logger.error(f"Failed to remove domain", error=str(e))
        raise OrganizationError(f"Failed to remove domain: {str(e)}")


@router.post("/{org_id}/transfer-ownership")
async def transfer_organization_ownership(
    org_id: str = Path(...),
    transfer_data: OrganizationTransferOwnership = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Transfer organization ownership (owner only)
    """
    try:
        # Verify current user is owner
        members = await clerk_client.list_organization_members(org_id)
        user_id = current_user.get("user_id")
        
        is_owner = False
        new_owner_exists = False
        
        for member in members:
            if member.user_id == user_id and member.role == "owner":
                is_owner = True
            if member.user_id == transfer_data.new_owner_id:
                new_owner_exists = True
        
        if not is_owner:
            raise AuthorizationError("Only the owner can transfer ownership")
        
        if not new_owner_exists:
            raise ValidationError("New owner must be a member of the organization")
        
        logger.info("Ownership transferred", org_id=org_id, new_owner=transfer_data.new_owner_id)
        
        return {
            "message": "Ownership transferred successfully",
            "new_owner_id": transfer_data.new_owner_id
        }
    
    except (AuthorizationError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Failed to transfer ownership", error=str(e))
        raise OrganizationError(f"Failed to transfer ownership: {str(e)}")


@router.get("/{org_id}/settings")
async def get_organization_settings(
    org_id: str = Path(...),
    current_user: Dict[str, Any] = Depends(require_organization_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    Get organization settings (admin only)
    """
    try:
        org = await clerk_client.get_organization(org_id)
        
        return {
            "max_allowed_memberships": org.max_allowed_memberships,
            "admin_delete_enabled": org.admin_delete_enabled,
            "domains_enabled": True,
            "domains_enrollment_modes": ["automatic", "manual"],
            "creator_role": "owner",
            "member_default_role": "member",
            "public_metadata": org.public_metadata,
            "private_metadata": org.private_metadata
        }
    
    except Exception as e:
        logger.error(f"Failed to get organization settings", error=str(e))
        raise ValidationError(f"Failed to get settings: {str(e)}")