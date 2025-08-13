"""
Workspace/Team Models
Database models for multi-tenant workspace functionality
"""

from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, Float, JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime

from app.core.database import Base


class Workspace(Base):
    """Workspace/Team model"""
    __tablename__ = "workspaces"
    
    id = Column(String, primary_key=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    owner_id = Column(String, nullable=False, index=True)
    
    # Settings and features as JSON
    settings = Column(JSON, default={})
    features = Column(JSON, default={})
    
    # Status
    status = Column(String(50), default="active", index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime)
    
    # Relationships
    members = relationship("WorkspaceMember", back_populates="workspace", cascade="all, delete-orphan")
    invitations = relationship("WorkspaceInvitation", back_populates="workspace", cascade="all, delete-orphan")
    roles = relationship("WorkspaceRole", back_populates="workspace", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_workspace_owner", "owner_id"),
        Index("idx_workspace_status", "status"),
        Index("idx_workspace_created", "created_at"),
    )


class WorkspaceMember(Base):
    """Workspace member model"""
    __tablename__ = "workspace_members"
    
    id = Column(String, primary_key=True)
    workspace_id = Column(String, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, nullable=False, index=True)
    role = Column(String(50), nullable=False, default="member")
    
    # Custom permissions (JSON array)
    permissions = Column(JSON, default=[])
    
    # Member details
    joined_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    invited_by = Column(String)
    last_active_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="members")
    
    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint("workspace_id", "user_id", name="uq_workspace_member"),
        Index("idx_member_workspace", "workspace_id"),
        Index("idx_member_user", "user_id"),
        Index("idx_member_role", "role"),
    )


class WorkspaceInvitation(Base):
    """Workspace invitation model"""
    __tablename__ = "workspace_invitations"
    
    id = Column(String, primary_key=True)
    workspace_id = Column(String, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    role = Column(String(50), default="member")
    
    # Invitation details
    token = Column(String(255), unique=True, nullable=False, index=True)
    inviter_id = Column(String, nullable=False)
    message = Column(Text)
    
    # Status tracking
    status = Column(String(50), default="pending", index=True)
    expires_at = Column(DateTime, nullable=False)
    accepted_at = Column(DateTime)
    accepted_by = Column(String)
    declined_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="invitations")
    
    # Indexes
    __table_args__ = (
        Index("idx_invitation_workspace", "workspace_id"),
        Index("idx_invitation_email", "email"),
        Index("idx_invitation_status", "status"),
        Index("idx_invitation_expires", "expires_at"),
    )


class WorkspaceRole(Base):
    """Custom workspace roles"""
    __tablename__ = "workspace_roles"
    
    id = Column(String, primary_key=True)
    workspace_id = Column(String, ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Permissions as JSON array
    permissions = Column(JSON, default=[])
    
    # Role hierarchy
    priority = Column(Integer, default=0)
    is_system = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="roles")
    
    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_workspace_role"),
        Index("idx_role_workspace", "workspace_id"),
        Index("idx_role_priority", "priority"),
    )