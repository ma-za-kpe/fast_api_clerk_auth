from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, Body, Query, HTTPException
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user, get_current_org_member
from app.services.invitation_service import invitation_service, InvitationStatus

router = APIRouter()
logger = structlog.get_logger()


@router.post("/")
async def create_invitation(
    org_id: str = Body(...),
    email: str = Body(...),
    role: str = Body("member", description="Role to assign (member, admin, owner)"),
    custom_message: Optional[str] = Body(None),
    expires_in_days: Optional[int] = Body(None, ge=1, le=30),
    metadata: Optional[Dict[str, Any]] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create an organization invitation
    """
    try:
        # Check if user has permission to invite (must be admin or owner)
        member = await get_current_org_member(org_id, current_user)
        if member.get("role") not in ["admin", "owner"]:
            raise AuthorizationError("Only admins and owners can send invitations")
        
        result = await invitation_service.create_invitation(
            org_id=org_id,
            inviter_id=current_user.get("user_id"),
            email=email,
            role=role,
            custom_message=custom_message,
            expires_in_days=expires_in_days,
            metadata=metadata
        )
        
        logger.info(
            f"Invitation created",
            org_id=org_id,
            email=email,
            inviter_id=current_user.get("user_id")
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create invitation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create invitation")


@router.post("/bulk")
async def create_bulk_invitations(
    org_id: str = Body(...),
    emails: List[str] = Body(..., description="List of email addresses"),
    role: str = Body("member"),
    custom_message: Optional[str] = Body(None),
    expires_in_days: Optional[int] = Body(None, ge=1, le=30),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create multiple invitations at once
    """
    try:
        # Check permission
        member = await get_current_org_member(org_id, current_user)
        if member.get("role") not in ["admin", "owner"]:
            raise AuthorizationError("Only admins and owners can send invitations")
        
        result = await invitation_service.create_bulk_invitations(
            org_id=org_id,
            inviter_id=current_user.get("user_id"),
            emails=emails,
            role=role,
            custom_message=custom_message,
            expires_in_days=expires_in_days
        )
        
        logger.info(
            f"Bulk invitations created",
            org_id=org_id,
            count=len(emails),
            inviter_id=current_user.get("user_id")
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create bulk invitations: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create invitations")


@router.post("/accept")
async def accept_invitation(
    token: str = Body(..., embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Accept an organization invitation
    """
    try:
        result = await invitation_service.accept_invitation(
            invitation_token=token,
            user_id=current_user.get("user_id")
        )
        
        logger.info(
            f"Invitation accepted",
            user_id=current_user.get("user_id"),
            org_id=result.get("org_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to accept invitation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to accept invitation")


@router.post("/reject")
async def reject_invitation(
    token: str = Body(..., embed=True),
    reason: Optional[str] = Body(None, embed=True),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user)
):
    """
    Reject an organization invitation
    """
    try:
        user_id = current_user.get("user_id") if current_user else None
        
        result = await invitation_service.reject_invitation(
            invitation_token=token,
            user_id=user_id,
            reason=reason
        )
        
        logger.info(f"Invitation rejected", user_id=user_id)
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to reject invitation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to reject invitation")


@router.post("/{invitation_id}/revoke")
async def revoke_invitation(
    invitation_id: str,
    reason: Optional[str] = Body(None, embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Revoke a pending invitation
    """
    try:
        # Note: Should check if user has permission to revoke
        # For now, allowing the inviter to revoke
        
        result = await invitation_service.revoke_invitation(
            invitation_id=invitation_id,
            revoker_id=current_user.get("user_id"),
            reason=reason
        )
        
        logger.info(
            f"Invitation revoked",
            invitation_id=invitation_id,
            revoker_id=current_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to revoke invitation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke invitation")


@router.post("/{invitation_id}/resend")
async def resend_invitation(
    invitation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Resend an invitation email
    """
    try:
        result = await invitation_service.resend_invitation(
            invitation_id=invitation_id,
            sender_id=current_user.get("user_id")
        )
        
        logger.info(
            f"Invitation resent",
            invitation_id=invitation_id,
            sender_id=current_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to resend invitation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to resend invitation")


@router.get("/organization/{org_id}")
async def get_organization_invitations(
    org_id: str,
    status: Optional[str] = Query(None, description="Filter by status"),
    include_expired: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all invitations for an organization
    """
    try:
        # Check if user is a member of the organization
        member = await get_current_org_member(org_id, current_user)
        if not member:
            raise AuthorizationError("You must be a member to view invitations")
        
        invitations = await invitation_service.get_organization_invitations(
            org_id=org_id,
            status=status,
            include_expired=include_expired
        )
        
        return {
            "invitations": invitations,
            "total": len(invitations),
            "pending": len([i for i in invitations if i["status"] == InvitationStatus.PENDING.value]),
            "accepted": len([i for i in invitations if i["status"] == InvitationStatus.ACCEPTED.value])
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get organization invitations: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve invitations")


@router.patch("/{invitation_id}/expiry")
async def update_invitation_expiry(
    invitation_id: str,
    new_expiry_days: int = Body(..., embed=True, ge=1, le=30),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update invitation expiry time
    """
    try:
        result = await invitation_service.update_invitation_expiry(
            invitation_id=invitation_id,
            new_expiry_days=new_expiry_days
        )
        
        logger.info(
            f"Invitation expiry updated",
            invitation_id=invitation_id,
            new_expiry_days=new_expiry_days
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update invitation expiry: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update expiry")


@router.get("/validate")
async def validate_invitation_token(
    token: str = Query(...)
):
    """
    Validate an invitation token without accepting it
    """
    try:
        # This would check if the token is valid and return invitation details
        # For security, limit the information returned
        
        # Placeholder implementation
        return {
            "valid": True,
            "message": "Token validation endpoint"
        }
    
    except Exception as e:
        logger.error(f"Failed to validate invitation token: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to validate token")


@router.get("/stats/{org_id}")
async def get_invitation_statistics(
    org_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get invitation statistics for an organization
    """
    try:
        # Check permission (admin or owner only)
        member = await get_current_org_member(org_id, current_user)
        if member.get("role") not in ["admin", "owner"]:
            raise AuthorizationError("Only admins and owners can view statistics")
        
        invitations = await invitation_service.get_organization_invitations(
            org_id=org_id,
            include_expired=True
        )
        
        # Calculate statistics
        total = len(invitations)
        pending = len([i for i in invitations if i["status"] == InvitationStatus.PENDING.value])
        accepted = len([i for i in invitations if i["status"] == InvitationStatus.ACCEPTED.value])
        rejected = len([i for i in invitations if i["status"] == InvitationStatus.REJECTED.value])
        expired = len([i for i in invitations if i["status"] == InvitationStatus.EXPIRED.value])
        revoked = len([i for i in invitations if i["status"] == InvitationStatus.REVOKED.value])
        
        # Calculate acceptance rate
        completed = accepted + rejected
        acceptance_rate = (accepted / completed * 100) if completed > 0 else 0
        
        return {
            "total_invitations": total,
            "pending": pending,
            "accepted": accepted,
            "rejected": rejected,
            "expired": expired,
            "revoked": revoked,
            "acceptance_rate": round(acceptance_rate, 2),
            "max_allowed": invitation_service.max_invitations_per_org,
            "remaining_slots": max(0, invitation_service.max_invitations_per_org - pending)
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get invitation statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")