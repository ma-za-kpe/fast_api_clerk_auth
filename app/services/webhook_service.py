from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func, update
import structlog
import json
import httpx
import asyncio
from enum import Enum

from app.db.models import WebhookEvent, AuditLog
from app.services.cache_service import cache_service
from app.core.config import settings

logger = structlog.get_logger()


class WebhookStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"
    RETRYING = "retrying"
    ABANDONED = "abandoned"


class WebhookEventType(Enum):
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


class WebhookService:
    """
    Enhanced webhook management service with retry logic and filtering
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.max_retries = getattr(settings, 'WEBHOOK_MAX_RETRIES', 3)
        self.retry_delay_base = getattr(settings, 'WEBHOOK_RETRY_DELAY_BASE', 60)  # seconds
        self.max_retry_delay = getattr(settings, 'WEBHOOK_MAX_RETRY_DELAY', 3600)  # 1 hour
        self.retention_days = getattr(settings, 'WEBHOOK_RETENTION_DAYS', 30)
    
    async def create_webhook_event(
        self,
        event_id: str,
        event_type: str,
        payload: Dict[str, Any],
        priority: int = 0,
        filter_conditions: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a webhook event with enhanced metadata
        """
        try:
            # Check if event should be filtered
            if filter_conditions and not self._should_process_event(event_type, payload, filter_conditions):
                logger.info(f"Event filtered out", event_type=event_type, event_id=event_id)
                return {"filtered": True, "event_id": event_id}
            
            webhook_event = WebhookEvent(
                event_id=event_id,
                event_type=event_type,
                payload=json.dumps(payload),
                status=WebhookStatus.PENDING.value,
                received_at=datetime.utcnow()
            )
            
            self.db.add(webhook_event)
            await self.db.commit()
            
            # Queue for processing
            await self._queue_for_processing(webhook_event, priority)
            
            logger.info(
                f"Webhook event created",
                event_id=event_id,
                event_type=event_type,
                priority=priority
            )
            
            return {
                "created": True,
                "event_id": event_id,
                "status": WebhookStatus.PENDING.value,
                "queued_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to create webhook event: {str(e)}")
            await self.db.rollback()
            return {"created": False, "error": str(e)}
    
    async def process_webhook_queue(self, batch_size: int = 10) -> Dict[str, Any]:
        """
        Process pending webhook events in batches
        """
        try:
            # Get pending events
            query = select(WebhookEvent).where(
                WebhookEvent.status == WebhookStatus.PENDING.value
            ).order_by(WebhookEvent.received_at).limit(batch_size)
            
            result = await self.db.execute(query)
            pending_events = result.scalars().all()
            
            processed_count = 0
            failed_count = 0
            
            for event in pending_events:
                try:
                    # Mark as processing
                    await self._update_event_status(event.id, WebhookStatus.PROCESSING)
                    
                    # Process the event
                    success = await self._process_single_event(event)
                    
                    if success:
                        await self._update_event_status(event.id, WebhookStatus.PROCESSED)
                        processed_count += 1
                    else:
                        await self._handle_processing_failure(event)
                        failed_count += 1
                
                except Exception as e:
                    logger.error(f"Failed to process event {event.event_id}: {str(e)}")
                    await self._handle_processing_failure(event, str(e))
                    failed_count += 1
            
            return {
                "processed": processed_count,
                "failed": failed_count,
                "total": len(pending_events)
            }
        
        except Exception as e:
            logger.error(f"Failed to process webhook queue: {str(e)}")
            return {"error": str(e)}
    
    async def retry_failed_events(self, max_events: int = 50) -> Dict[str, Any]:
        """
        Retry failed webhook events based on retry policy
        """
        try:
            # Get events ready for retry
            current_time = datetime.utcnow()
            
            query = select(WebhookEvent).where(
                and_(
                    WebhookEvent.status == WebhookStatus.FAILED.value,
                    or_(
                        WebhookEvent.processed_at.is_(None),
                        WebhookEvent.processed_at <= current_time - timedelta(seconds=self.retry_delay_base)
                    )
                )
            ).limit(max_events)
            
            result = await self.db.execute(query)
            retry_events = result.scalars().all()
            
            retried_count = 0
            abandoned_count = 0
            
            for event in retry_events:
                retry_count = self._get_retry_count(event)
                
                if retry_count >= self.max_retries:
                    # Abandon event
                    await self._update_event_status(event.id, WebhookStatus.ABANDONED)
                    abandoned_count += 1
                    continue
                
                try:
                    # Calculate retry delay (exponential backoff)
                    delay = min(
                        self.retry_delay_base * (2 ** retry_count),
                        self.max_retry_delay
                    )
                    
                    # Schedule retry
                    await self._schedule_retry(event, delay)
                    retried_count += 1
                
                except Exception as e:
                    logger.error(f"Failed to schedule retry for event {event.event_id}: {str(e)}")
            
            return {
                "retried": retried_count,
                "abandoned": abandoned_count,
                "total_checked": len(retry_events)
            }
        
        except Exception as e:
            logger.error(f"Failed to retry failed events: {str(e)}")
            return {"error": str(e)}
    
    async def get_webhook_events(
        self,
        event_types: Optional[List[str]] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get webhook events with filtering
        """
        try:
            query = select(WebhookEvent)
            
            # Apply filters
            if event_types:
                query = query.where(WebhookEvent.event_type.in_(event_types))
            
            if status:
                query = query.where(WebhookEvent.status == status)
            
            if start_date:
                query = query.where(WebhookEvent.received_at >= start_date)
            
            if end_date:
                query = query.where(WebhookEvent.received_at <= end_date)
            
            # Order and paginate
            query = query.order_by(desc(WebhookEvent.received_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            return [self._format_webhook_event(event) for event in events]
        
        except Exception as e:
            logger.error(f"Failed to get webhook events: {str(e)}")
            return []
    
    async def get_webhook_statistics(
        self,
        days_back: int = 7
    ) -> Dict[str, Any]:
        """
        Get webhook processing statistics
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Get status breakdown
            status_query = select(
                WebhookEvent.status,
                func.count(WebhookEvent.id).label('count')
            ).where(
                WebhookEvent.received_at >= start_date
            ).group_by(WebhookEvent.status)
            
            status_result = await self.db.execute(status_query)
            status_breakdown = dict(status_result.fetchall())
            
            # Get event type breakdown
            type_query = select(
                WebhookEvent.event_type,
                func.count(WebhookEvent.id).label('count')
            ).where(
                WebhookEvent.received_at >= start_date
            ).group_by(WebhookEvent.event_type)
            
            type_result = await self.db.execute(type_query)
            type_breakdown = dict(type_result.fetchall())
            
            # Calculate success rate
            total_events = sum(status_breakdown.values())
            processed_events = status_breakdown.get(WebhookStatus.PROCESSED.value, 0)
            success_rate = (processed_events / total_events * 100) if total_events > 0 else 0
            
            return {
                "period_days": days_back,
                "total_events": total_events,
                "success_rate": round(success_rate, 2),
                "status_breakdown": status_breakdown,
                "event_type_breakdown": type_breakdown,
                "retry_rate": round(
                    (status_breakdown.get(WebhookStatus.RETRYING.value, 0) / total_events * 100) 
                    if total_events > 0 else 0, 2
                ),
                "abandonment_rate": round(
                    (status_breakdown.get(WebhookStatus.ABANDONED.value, 0) / total_events * 100) 
                    if total_events > 0 else 0, 2
                )
            }
        
        except Exception as e:
            logger.error(f"Failed to get webhook statistics: {str(e)}")
            return {}
    
    async def cleanup_old_events(self, days_to_keep: Optional[int] = None) -> Dict[str, Any]:
        """
        Clean up old webhook events
        """
        try:
            retention_days = days_to_keep or self.retention_days
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            # Count events to be deleted
            count_query = select(func.count(WebhookEvent.id)).where(
                WebhookEvent.received_at < cutoff_date
            )
            
            count_result = await self.db.execute(count_query)
            events_to_delete = count_result.scalar()
            
            if events_to_delete > 0:
                # Delete old events
                from sqlalchemy import delete
                delete_query = delete(WebhookEvent).where(
                    WebhookEvent.received_at < cutoff_date
                )
                
                await self.db.execute(delete_query)
                await self.db.commit()
                
                logger.info(
                    f"Cleaned up old webhook events",
                    events_deleted=events_to_delete,
                    retention_days=retention_days
                )
            
            return {
                "events_deleted": events_to_delete,
                "cutoff_date": cutoff_date.isoformat(),
                "retention_days": retention_days
            }
        
        except Exception as e:
            logger.error(f"Failed to cleanup old events: {str(e)}")
            await self.db.rollback()
            return {"error": "Failed to cleanup events"}
    
    async def configure_webhook_endpoint(
        self,
        endpoint_url: str,
        event_types: List[str],
        enabled: bool = True,
        retry_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Configure webhook endpoint settings
        """
        try:
            config_key = f"webhook_endpoint_config"
            
            config = {
                "endpoint_url": endpoint_url,
                "event_types": event_types,
                "enabled": enabled,
                "retry_config": retry_config or {
                    "max_retries": self.max_retries,
                    "base_delay": self.retry_delay_base,
                    "max_delay": self.max_retry_delay
                },
                "configured_at": datetime.utcnow().isoformat()
            }
            
            await cache_service.set(config_key, config)
            
            logger.info(f"Webhook endpoint configured", endpoint_url=endpoint_url)
            
            return {
                "configured": True,
                "endpoint_url": endpoint_url,
                "event_types": event_types,
                "enabled": enabled
            }
        
        except Exception as e:
            logger.error(f"Failed to configure webhook endpoint: {str(e)}")
            return {"configured": False, "error": str(e)}
    
    async def send_webhook_to_external_endpoint(
        self,
        endpoint_url: str,
        event_data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Send webhook to external endpoint
        """
        try:
            default_headers = {
                "Content-Type": "application/json",
                "User-Agent": f"FastAPI-Webhook/1.0"
            }
            
            if headers:
                default_headers.update(headers)
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    endpoint_url,
                    json=event_data,
                    headers=default_headers,
                    timeout=timeout
                )
                
                response.raise_for_status()
                
                return {
                    "sent": True,
                    "status_code": response.status_code,
                    "response_time_ms": int(response.elapsed.total_seconds() * 1000)
                }
        
        except httpx.TimeoutException:
            return {"sent": False, "error": "Request timeout"}
        except httpx.HTTPError as e:
            return {"sent": False, "error": f"HTTP error: {str(e)}"}
        except Exception as e:
            return {"sent": False, "error": str(e)}
    
    # ============= Helper Methods =============
    
    def _should_process_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        filter_conditions: Dict[str, Any]
    ) -> bool:
        """Check if event should be processed based on filters"""
        # Event type filtering
        if "allowed_event_types" in filter_conditions:
            if event_type not in filter_conditions["allowed_event_types"]:
                return False
        
        if "blocked_event_types" in filter_conditions:
            if event_type in filter_conditions["blocked_event_types"]:
                return False
        
        # User filtering
        if "user_filter" in filter_conditions:
            user_id = payload.get("data", {}).get("id")
            user_filter = filter_conditions["user_filter"]
            
            if "allowed_users" in user_filter and user_id not in user_filter["allowed_users"]:
                return False
            
            if "blocked_users" in user_filter and user_id in user_filter["blocked_users"]:
                return False
        
        return True
    
    async def _queue_for_processing(self, event: WebhookEvent, priority: int = 0):
        """Queue event for processing"""
        queue_data = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "priority": priority,
            "queued_at": datetime.utcnow().isoformat()
        }
        
        queue_key = f"webhook_queue:{priority}:{event.id}"
        await cache_service.set(queue_key, queue_data, expire=86400)  # 24 hours
    
    async def _process_single_event(self, event: WebhookEvent) -> bool:
        """Process a single webhook event"""
        try:
            from app.services.webhook_handler import WebhookHandler
            
            handler = WebhookHandler(self.db)
            payload = json.loads(event.payload)
            
            # Route to appropriate handler
            handler_method = self._get_handler_method(handler, event.event_type)
            
            if handler_method:
                await handler_method(payload.get("data", {}))
                return True
            else:
                logger.warning(f"No handler for event type: {event.event_type}")
                return False
        
        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {str(e)}")
            return False
    
    def _get_handler_method(self, handler, event_type: str):
        """Get the appropriate handler method for event type"""
        handler_map = {
            "user.created": handler.handle_user_created,
            "user.updated": handler.handle_user_updated,
            "user.deleted": handler.handle_user_deleted,
            "session.created": handler.handle_session_created,
            "session.ended": handler.handle_session_ended,
            "session.removed": handler.handle_session_removed,
            "organization.created": handler.handle_organization_created,
            "organization.updated": handler.handle_organization_updated,
            "organization.deleted": handler.handle_organization_deleted,
            "organizationMembership.created": handler.handle_membership_created,
            "organizationMembership.updated": handler.handle_membership_updated,
            "organizationMembership.deleted": handler.handle_membership_deleted,
            "organizationInvitation.created": handler.handle_invitation_created,
            "organizationInvitation.accepted": handler.handle_invitation_accepted,
            "organizationInvitation.revoked": handler.handle_invitation_revoked,
            "email.created": handler.handle_email_created,
            "sms.created": handler.handle_sms_created
        }
        
        return handler_map.get(event_type)
    
    async def _update_event_status(
        self,
        event_id: int,
        status: WebhookStatus,
        error: Optional[str] = None
    ):
        """Update webhook event status"""
        update_data = {
            "status": status.value,
            "processed_at": datetime.utcnow()
        }
        
        if error:
            update_data["error"] = error
        
        query = update(WebhookEvent).where(
            WebhookEvent.id == event_id
        ).values(**update_data)
        
        await self.db.execute(query)
        await self.db.commit()
    
    async def _handle_processing_failure(
        self,
        event: WebhookEvent,
        error: Optional[str] = None
    ):
        """Handle webhook processing failure"""
        retry_count = self._get_retry_count(event)
        
        if retry_count < self.max_retries:
            await self._update_event_status(event.id, WebhookStatus.FAILED, error)
        else:
            await self._update_event_status(event.id, WebhookStatus.ABANDONED, error)
    
    def _get_retry_count(self, event: WebhookEvent) -> int:
        """Get current retry count for event"""
        # This would be stored in event metadata or calculated from processing history
        # For now, return 0 (simplified)
        return 0
    
    async def _schedule_retry(self, event: WebhookEvent, delay_seconds: int):
        """Schedule event for retry"""
        retry_time = datetime.utcnow() + timedelta(seconds=delay_seconds)
        
        retry_data = {
            "event_id": event.event_id,
            "retry_at": retry_time.isoformat(),
            "delay_seconds": delay_seconds
        }
        
        retry_key = f"webhook_retry:{event.id}"
        await cache_service.set(retry_key, retry_data, expire=delay_seconds + 3600)
        
        await self._update_event_status(event.id, WebhookStatus.RETRYING)
    
    def _format_webhook_event(self, event: WebhookEvent) -> Dict[str, Any]:
        """Format webhook event for API response"""
        return {
            "id": event.id,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "status": event.status,
            "received_at": event.received_at.isoformat(),
            "processed_at": event.processed_at.isoformat() if event.processed_at else None,
            "error": event.error,
            "payload_size": len(event.payload) if event.payload else 0
        }


# Factory function
def get_webhook_service(db: AsyncSession) -> WebhookService:
    return WebhookService(db)