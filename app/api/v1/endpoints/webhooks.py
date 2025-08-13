from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException, Header, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
import hmac
import hashlib
import json
from datetime import datetime
import structlog

from app.core.config import settings
from app.core.clerk import get_clerk_client
from app.core.exceptions import WebhookError
from app.services.webhook_handler import WebhookHandler
from app.services.webhook_service import get_webhook_service
from app.db.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()
logger = structlog.get_logger()


def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str
) -> bool:
    """
    Verify Clerk webhook signature using HMAC-SHA256
    """
    try:
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        logger.error("Failed to verify webhook signature", error=str(e))
        return False


@router.post("/clerk")
async def handle_clerk_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    svix_id: Optional[str] = Header(None),
    svix_timestamp: Optional[str] = Header(None),
    svix_signature: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Handle Clerk webhook events with signature verification
    """
    try:
        # Get raw body
        body = await request.body()
        
        # Verify webhook signature if secret is configured
        if settings.CLERK_WEBHOOK_SECRET:
            if not svix_signature:
                raise WebhookError("Missing webhook signature")
            
            # Clerk uses Svix for webhooks
            # Construct the signed content
            signed_content = f"{svix_id}.{svix_timestamp}.{body.decode('utf-8')}"
            
            # Verify signature
            is_valid = verify_webhook_signature(
                signed_content.encode('utf-8'),
                svix_signature.split(' ')[-1],  # Extract signature from "v1,signature" format
                settings.CLERK_WEBHOOK_SECRET
            )
            
            if not is_valid:
                logger.warning("Invalid webhook signature")
                raise WebhookError("Invalid webhook signature")
        
        # Parse webhook payload
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise WebhookError("Invalid JSON payload")
        
        # Extract event data
        event_type = payload.get("type")
        event_data = payload.get("data")
        event_id = payload.get("id") or svix_id
        
        logger.info(
            "Webhook received",
            event_type=event_type,
            event_id=event_id
        )
        
        # Initialize services
        handler = WebhookHandler(db)
        webhook_service = get_webhook_service(db)
        
        # Create webhook event with enhanced service
        await webhook_service.create_webhook_event(
            event_id=event_id,
            event_type=event_type,
            payload=payload,
            priority=1 if event_type in ["user.created", "organization.created"] else 0
        )
        
        # Process webhook based on event type using background tasks
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
        
        handler_func = handler_map.get(event_type)
        if handler_func:
            background_tasks.add_task(handler_func, event_data)
        else:
            logger.warning(f"Unhandled webhook event type: {event_type}")
        
        return JSONResponse(
            status_code=200,
            content={"status": "received", "event_id": event_id}
        )
    
    except WebhookError as e:
        logger.error("Webhook validation failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.error("Webhook processing failed", error=str(e))
        
        # Store failed webhook for retry using enhanced service
        if 'webhook_service' in locals() and 'event_id' in locals():
            await webhook_service.create_webhook_event(
                event_id=f"failed_{event_id}",
                event_type=event_type if 'event_type' in locals() else "unknown",
                payload=payload if 'payload' in locals() else {}
            )
        
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/clerk/events")
async def list_webhook_events(
    limit: int = 20,
    offset: int = 0,
    status: Optional[str] = None,
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List webhook events for debugging and monitoring
    """
    try:
        handler = WebhookHandler(db)
        events = await handler.list_webhook_events(
            limit=limit,
            offset=offset,
            status=status,
            event_type=event_type
        )
        
        return {
            "events": events,
            "total": len(events),
            "limit": limit,
            "offset": offset
        }
    
    except Exception as e:
        logger.error("Failed to list webhook events", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list events")


@router.post("/clerk/events/{event_id}/retry")
async def retry_webhook_event(
    event_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Retry a failed webhook event
    """
    try:
        handler = WebhookHandler(db)
        event = await handler.get_webhook_event(event_id)
        
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        
        if event.get("status") != "failed":
            raise HTTPException(status_code=400, detail="Can only retry failed events")
        
        # Re-process the event
        event_type = event.get("event_type")
        event_data = event.get("payload", {}).get("data")
        
        # Add processing task
        background_tasks.add_task(
            handler.process_webhook_retry,
            event_id,
            event_type,
            event_data
        )
        
        return {"message": "Event retry initiated", "event_id": event_id}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retry webhook event {event_id}", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retry event")


@router.post("/test")
async def test_webhook(
    event_type: str,
    user_id: Optional[str] = None,
    org_id: Optional[str] = None
):
    """
    Test webhook endpoint for development
    """
    if not settings.DEBUG:
        raise HTTPException(status_code=403, detail="Test endpoint only available in debug mode")
    
    test_payload = {
        "id": f"test_{datetime.utcnow().isoformat()}",
        "type": event_type,
        "data": {
            "id": user_id or org_id or "test_id",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
    }
    
    logger.info("Test webhook triggered", event_type=event_type)
    
    return {
        "message": "Test webhook sent",
        "payload": test_payload
    }


@router.get("/config")
async def get_webhook_config():
    """
    Get webhook configuration status
    """
    return {
        "webhook_secret_configured": bool(settings.CLERK_WEBHOOK_SECRET),
        "webhooks_enabled": settings.ENABLE_WEBHOOKS,
        "supported_events": [
            "user.created",
            "user.updated", 
            "user.deleted",
            "session.created",
            "session.ended",
            "session.removed",
            "organization.created",
            "organization.updated",
            "organization.deleted",
            "organizationMembership.created",
            "organizationMembership.updated",
            "organizationMembership.deleted",
            "organizationInvitation.created",
            "organizationInvitation.accepted",
            "organizationInvitation.revoked",
            "email.created",
            "sms.created"
        ]
    }