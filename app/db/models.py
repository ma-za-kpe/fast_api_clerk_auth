from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime

from app.db.database import Base


class WebhookEvent(Base):
    __tablename__ = "webhook_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(255), unique=True, index=True, nullable=False)
    event_type = Column(String(100), index=True, nullable=False)
    payload = Column(Text, nullable=False)
    status = Column(String(50), default="pending", index=True)
    error = Column(Text, nullable=True)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    processed_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index("idx_webhook_events_status_type", "status", "event_type"),
        Index("idx_webhook_events_received_at", "received_at"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), index=True, nullable=False)
    user_id = Column(String(255), index=True, nullable=True)
    organization_id = Column(String(255), index=True, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index("idx_audit_logs_user_event", "user_id", "event_type"),
        Index("idx_audit_logs_created_at", "created_at"),
        Index("idx_audit_logs_org_event", "organization_id", "event_type"),
    )


class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(String(255), index=True, nullable=False)
    organization_id = Column(String(255), index=True, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    location = Column(String(255), nullable=True)
    device_info = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_activity_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index("idx_user_sessions_user_active", "user_id", "is_active"),
        Index("idx_user_sessions_last_activity", "last_activity_at"),
    )


class UserProfile(Base):
    __tablename__ = "user_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255), unique=True, index=True, nullable=False)
    preferences = Column(JSON, default={})
    settings = Column(JSON, default={})
    metadata = Column(JSON, default={})
    onboarding_completed = Column(Boolean, default=False)
    email_notifications_enabled = Column(Boolean, default=True)
    sms_notifications_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class OrganizationSettings(Base):
    __tablename__ = "organization_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(String(255), unique=True, index=True, nullable=False)
    settings = Column(JSON, default={})
    features = Column(JSON, default={})
    limits = Column(JSON, default={})
    billing_info = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    resource = Column(String(100), index=True, nullable=False)
    action = Column(String(50), index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index("idx_permissions_resource_action", "resource", "action"),
    )


class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    organization_id = Column(String(255), index=True, nullable=True)
    permissions = Column(JSON, default=[])
    is_system = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index("idx_roles_org_name", "organization_id", "name"),
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255), index=True, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    organization_id = Column(String(255), index=True, nullable=True)
    granted_by = Column(String(255), nullable=True)
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    
    role = relationship("Role", backref="user_roles")
    
    __table_args__ = (
        Index("idx_user_roles_user_org", "user_id", "organization_id"),
        Index("idx_user_roles_role_org", "role_id", "organization_id"),
    )


class EmailTemplate(Base):
    __tablename__ = "email_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    subject = Column(String(255), nullable=False)
    body_html = Column(Text, nullable=False)
    body_text = Column(Text, nullable=True)
    variables = Column(JSON, default=[])
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255), index=True, nullable=False)
    type = Column(String(50), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    data = Column(JSON, nullable=True)
    is_read = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    read_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index("idx_notifications_user_read", "user_id", "is_read"),
        Index("idx_notifications_created_at", "created_at"),
    )


class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    user_id = Column(String(255), index=True, nullable=False)
    organization_id = Column(String(255), index=True, nullable=True)
    permissions = Column(JSON, default=[])
    rate_limit = Column(Integer, default=1000)
    is_active = Column(Boolean, default=True, index=True)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index("idx_api_keys_user_active", "user_id", "is_active"),
        Index("idx_api_keys_org_active", "organization_id", "is_active"),
    )


class DataExport(Base):
    __tablename__ = "data_exports"
    
    id = Column(Integer, primary_key=True, index=True)
    export_id = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(String(255), index=True, nullable=False)
    type = Column(String(50), nullable=False)  # gdpr, backup, etc.
    status = Column(String(50), default="pending", index=True)
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    
    __table_args__ = (
        Index("idx_data_exports_user_status", "user_id", "status"),
    )