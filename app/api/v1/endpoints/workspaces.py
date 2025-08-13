"""
Workspace/Teams API Endpoints
Handles workspace management and team collaboration
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Body, Path, status
from fastapi.responses import JSONResponse

from app.api.deps import get_current_user, require_verified_user
from app.services.workspace_service import (
    workspace_service,
    WorkspaceSettings,
    WorkspaceFeatures,
    MemberRole
)
from app.schemas.workspace import (
    WorkspaceCreate,
    WorkspaceUpdate,
    WorkspaceResponse,
    WorkspaceMemberResponse,
    WorkspaceInvitationCreate,
    WorkspaceInvitationResponse,
    MemberRoleUpdate,
    WorkspaceQuotaResponse
)
from app.core.exceptions import BadRequestError, NotFoundError, ForbiddenError

router = APIRouter()


@router.post("/", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    workspace_data: WorkspaceCreate,
    current_user: dict = Depends(require_verified_user)
):
    """
    Create a new workspace
    
    Requires verified user account
    """
    settings = None
    if workspace_data.settings:
        settings = WorkspaceSettings(**workspace_data.settings)
    
    features = None
    if workspace_data.features:
        features = WorkspaceFeatures(**workspace_data.features)
    
    workspace = await workspace_service.create_workspace(
        name=workspace_data.name,
        owner_id=current_user["id"],
        description=workspace_data.description,
        settings=settings,
        features=features
    )
    
    return workspace


@router.get("/", response_model=List[WorkspaceResponse])
async def get_user_workspaces(
    include_archived: bool = Query(False, description="Include archived workspaces"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get all workspaces for current user
    """
    workspaces = await workspace_service.get_user_workspaces(
        user_id=current_user["id"],
        include_archived=include_archived
    )
    
    return workspaces


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
async def get_workspace(
    workspace_id: str = Path(..., description="Workspace ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get workspace details
    
    User must be a member of the workspace
    """
    workspace = await workspace_service.get_workspace(
        workspace_id=workspace_id,
        user_id=current_user["id"]
    )
    
    return workspace


@router.put("/{workspace_id}", response_model=WorkspaceResponse)
async def update_workspace(
    workspace_id: str = Path(..., description="Workspace ID"),
    workspace_data: WorkspaceUpdate = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Update workspace details
    
    Requires admin or owner role
    """
    settings = None
    if workspace_data.settings:
        settings = WorkspaceSettings(**workspace_data.settings)
    
    features = None
    if workspace_data.features:
        features = WorkspaceFeatures(**workspace_data.features)
    
    workspace = await workspace_service.update_workspace(
        workspace_id=workspace_id,
        user_id=current_user["id"],
        name=workspace_data.name,
        description=workspace_data.description,
        settings=settings,
        features=features
    )
    
    return workspace


@router.delete("/{workspace_id}")
async def delete_workspace(
    workspace_id: str = Path(..., description="Workspace ID"),
    permanent: bool = Query(False, description="Permanently delete workspace"),
    current_user: dict = Depends(get_current_user)
):
    """
    Delete or archive workspace
    
    Only workspace owner can delete
    """
    result = await workspace_service.delete_workspace(
        workspace_id=workspace_id,
        user_id=current_user["id"],
        permanent=permanent
    )
    
    return result


@router.get("/{workspace_id}/members", response_model=List[WorkspaceMemberResponse])
async def get_workspace_members(
    workspace_id: str = Path(..., description="Workspace ID"),
    role: Optional[str] = Query(None, description="Filter by role"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get workspace members
    
    User must be a member of the workspace
    """
    members = await workspace_service.get_workspace_members(
        workspace_id=workspace_id,
        user_id=current_user["id"],
        role_filter=role
    )
    
    return members


@router.post("/{workspace_id}/members")
async def add_workspace_member(
    workspace_id: str = Path(..., description="Workspace ID"),
    user_id: str = Body(..., embed=True),
    role: str = Body(MemberRole.MEMBER, embed=True),
    permissions: Optional[List[str]] = Body(None, embed=True),
    current_user: dict = Depends(get_current_user)
):
    """
    Add member to workspace
    
    Requires admin or owner role
    """
    member = await workspace_service.add_member(
        workspace_id=workspace_id,
        admin_id=current_user["id"],
        user_id=user_id,
        role=role,
        permissions=permissions
    )
    
    return member


@router.delete("/{workspace_id}/members/{user_id}")
async def remove_workspace_member(
    workspace_id: str = Path(..., description="Workspace ID"),
    user_id: str = Path(..., description="User ID to remove"),
    current_user: dict = Depends(get_current_user)
):
    """
    Remove member from workspace
    
    Requires admin or owner role
    Cannot remove workspace owner
    """
    result = await workspace_service.remove_member(
        workspace_id=workspace_id,
        admin_id=current_user["id"],
        user_id=user_id
    )
    
    return result


@router.put("/{workspace_id}/members/{user_id}/role")
async def update_member_role(
    workspace_id: str = Path(..., description="Workspace ID"),
    user_id: str = Path(..., description="User ID"),
    role_update: MemberRoleUpdate = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Update member role and permissions
    
    Requires admin or owner role
    """
    member = await workspace_service.update_member_role(
        workspace_id=workspace_id,
        admin_id=current_user["id"],
        user_id=user_id,
        new_role=role_update.role,
        permissions=role_update.permissions
    )
    
    return member


@router.post("/{workspace_id}/invitations", response_model=WorkspaceInvitationResponse)
async def create_invitation(
    workspace_id: str = Path(..., description="Workspace ID"),
    invitation_data: WorkspaceInvitationCreate = Body(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Create workspace invitation
    
    Requires admin or owner role
    """
    invitation = await workspace_service.create_invitation(
        workspace_id=workspace_id,
        inviter_id=current_user["id"],
        email=invitation_data.email,
        role=invitation_data.role,
        message=invitation_data.message
    )
    
    return invitation


@router.post("/invitations/{token}/accept")
async def accept_invitation(
    token: str = Path(..., description="Invitation token"),
    current_user: dict = Depends(require_verified_user)
):
    """
    Accept workspace invitation
    
    Requires verified user account
    """
    result = await workspace_service.accept_invitation(
        token=token,
        user_id=current_user["id"]
    )
    
    return result


@router.post("/{workspace_id}/transfer-ownership")
async def transfer_ownership(
    workspace_id: str = Path(..., description="Workspace ID"),
    new_owner_id: str = Body(..., embed=True),
    current_user: dict = Depends(get_current_user)
):
    """
    Transfer workspace ownership
    
    Only current owner can transfer ownership
    New owner must be an existing member
    """
    result = await workspace_service.transfer_ownership(
        workspace_id=workspace_id,
        current_owner_id=current_user["id"],
        new_owner_id=new_owner_id
    )
    
    return result


@router.get("/{workspace_id}/quota", response_model=WorkspaceQuotaResponse)
async def get_workspace_quota(
    workspace_id: str = Path(..., description="Workspace ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get workspace resource usage and quotas
    
    User must be a member of the workspace
    """
    quota = await workspace_service.get_workspace_quota(
        workspace_id=workspace_id,
        user_id=current_user["id"]
    )
    
    return WorkspaceQuotaResponse(
        members_used=quota.members_used,
        members_limit=quota.members_limit,
        projects_used=quota.projects_used,
        projects_limit=quota.projects_limit,
        storage_used_gb=quota.storage_used_gb,
        storage_limit_gb=quota.storage_limit_gb,
        api_calls_used=quota.api_calls_used,
        api_calls_limit=quota.api_calls_limit,
        seats_used=quota.seats_used,
        seats_limit=quota.seats_limit
    )


@router.post("/{workspace_id}/leave")
async def leave_workspace(
    workspace_id: str = Path(..., description="Workspace ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Leave workspace
    
    Owner cannot leave without transferring ownership first
    """
    # Check if user is owner
    workspace = await workspace_service.get_workspace(
        workspace_id=workspace_id,
        user_id=current_user["id"]
    )
    
    if workspace["owner_id"] == current_user["id"]:
        raise BadRequestError("Owner cannot leave workspace. Transfer ownership first.")
    
    # Remove self from workspace
    result = await workspace_service.remove_member(
        workspace_id=workspace_id,
        admin_id=current_user["id"],  # Self-removal
        user_id=current_user["id"]
    )
    
    return result