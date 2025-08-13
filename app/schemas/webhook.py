from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum


class WebhookStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"
    RETRYING = "retrying"
    ABANDONED = "abandoned"


class WebhookEventType(str, Enum):
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    SESSION_CREATED = "session.created"
    SESSION_ENDED = "session.ended"
    SESSION_REMOVED = "session.removed"
    ORG_CREATED = "organization.created"
    ORG_UPDATED = "organization.updated"
    ORG_DELETED = "organization.deleted"
    MEMBERSHIP_CREATED = "organizationMembership.created"
    MEMBERSHIP_UPDATED = "organizationMembership.updated"
    MEMBERSHIP_DELETED = "organizationMembership.deleted"
    INVITATION_CREATED = "organizationInvitation.created"
    INVITATION_ACCEPTED = "organizationInvitation.accepted"
    INVITATION_REVOKED = "organizationInvitation.revoked"
    EMAIL_CREATED = "email.created"
    SMS_CREATED = "sms.created"


class WebhookEventResponse(BaseModel):
    id: int
    event_id: str
    event_type: str
    status: WebhookStatus
    received_at: datetime
    processed_at: Optional[datetime] = None
    error: Optional[str] = None
    payload_size: int

    class Config:
        from_attributes = True


class WebhookConfigRequest(BaseModel):
    enabled: bool = True
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay_base: int = Field(default=60, ge=1, le=3600)
    max_retry_delay: int = Field(default=3600, ge=60, le=86400)
    retention_days: int = Field(default=30, ge=1, le=365)


class WebhookRetryConfig(BaseModel):
    max_retries: int = Field(default=3, ge=0, le=10)
    base_delay: int = Field(default=60, ge=1, le=3600)
    max_delay: int = Field(default=3600, ge=60, le=86400)


class WebhookEndpointRequest(BaseModel):
    endpoint_url: HttpUrl
    event_types: List[WebhookEventType]
    enabled: bool = True
    retry_config: Optional[WebhookRetryConfig] = None


class WebhookStatsResponse(BaseModel):
    period_days: int
    total_events: int
    success_rate: float
    retry_rate: float
    abandonment_rate: float
    status_breakdown: Dict[str, int]
    event_type_breakdown: Dict[str, int]


class WebhookProcessResult(BaseModel):
    processed: int
    failed: int
    total: int


class WebhookRetryResult(BaseModel):
    retried: int
    abandoned: int
    total_checked: int


class WebhookCleanupResult(BaseModel):
    events_deleted: int
    cutoff_date: datetime
    retention_days: int


class WebhookHealthResponse(BaseModel):
    status: str
    webhook_processing: Dict[str, Any]
    timestamp: datetime


class WebhookFilterRequest(BaseModel):
    event_types: Optional[List[WebhookEventType]] = None
    status: Optional[WebhookStatus] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class WebhookEventCreate(BaseModel):
    event_id: str
    event_type: WebhookEventType
    payload: Dict[str, Any]
    priority: int = Field(default=0, ge=0, le=10)
    filter_conditions: Optional[Dict[str, Any]] = None


class WebhookExternalRequest(BaseModel):
    endpoint_url: HttpUrl
    event_data: Dict[str, Any]
    headers: Optional[Dict[str, str]] = None
    timeout: int = Field(default=30, ge=1, le=300)