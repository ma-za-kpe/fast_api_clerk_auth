from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import structlog

from app.db.database import get_db
from app.services.webhook_service import get_webhook_service
from app.schemas.webhook import (
    WebhookConfigRequest,
    WebhookEventResponse,
    WebhookStatsResponse,
    WebhookEndpointRequest
)

router = APIRouter()
logger = structlog.get_logger()


@router.post("/process-queue")
async def process_webhook_queue(
    batch_size: int = Query(default=10, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    """
    Process pending webhook events in batches
    """
    try:
        webhook_service = get_webhook_service(db)
        result = await webhook_service.process_webhook_queue(batch_size)
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": f"Processed {result['processed']} events",
                **result
            }
        )
    
    except Exception as e:
        logger.error(f"Failed to process webhook queue: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process queue")


@router.post("/retry-failed")
async def retry_failed_webhooks(
    max_events: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db)
):
    """
    Retry failed webhook events
    """
    try:
        webhook_service = get_webhook_service(db)
        result = await webhook_service.retry_failed_events(max_events)
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": f"Retried {result['retried']} events, abandoned {result['abandoned']} events",
                **result
            }
        )
    
    except Exception as e:
        logger.error(f"Failed to retry failed webhooks: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retry events")


@router.get("/events")
async def get_webhook_events(
    event_types: Optional[List[str]] = Query(None),
    status: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Get webhook events with filtering
    """
    try:
        webhook_service = get_webhook_service(db)
        events = await webhook_service.get_webhook_events(
            event_types=event_types,
            status=status,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset
        )
        
        return {
            "events": events,
            "count": len(events),
            "limit": limit,
            "offset": offset
        }
    
    except Exception as e:
        logger.error(f"Failed to get webhook events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get events")


@router.get("/statistics")
async def get_webhook_statistics(
    days_back: int = Query(default=7, ge=1, le=90),
    db: AsyncSession = Depends(get_db)
):
    """
    Get webhook processing statistics
    """
    try:
        webhook_service = get_webhook_service(db)
        stats = await webhook_service.get_webhook_statistics(days_back)
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "statistics": stats
            }
        )
    
    except Exception as e:
        logger.error(f"Failed to get webhook statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")


@router.post("/cleanup")
async def cleanup_old_events(
    days_to_keep: Optional[int] = Query(None, ge=1, le=365),
    db: AsyncSession = Depends(get_db)
):
    """
    Clean up old webhook events
    """
    try:
        webhook_service = get_webhook_service(db)
        result = await webhook_service.cleanup_old_events(days_to_keep)
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": f"Cleaned up {result['events_deleted']} old events",
                **result
            }
        )
    
    except Exception as e:
        logger.error(f"Failed to cleanup old events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup events")


@router.post("/configure-endpoint")
async def configure_webhook_endpoint(
    request: WebhookEndpointRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Configure webhook endpoint settings
    """
    try:
        webhook_service = get_webhook_service(db)
        result = await webhook_service.configure_webhook_endpoint(
            endpoint_url=request.endpoint_url,
            event_types=request.event_types,
            enabled=request.enabled,
            retry_config=request.retry_config
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Webhook endpoint configured successfully",
                **result
            }
        )
    
    except Exception as e:
        logger.error(f"Failed to configure webhook endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to configure endpoint")


@router.post("/send-to-external")
async def send_webhook_to_external(
    endpoint_url: str,
    event_data: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: int = Query(default=30, ge=1, le=300),
    db: AsyncSession = Depends(get_db)
):
    """
    Send webhook to external endpoint for testing
    """
    try:
        webhook_service = get_webhook_service(db)
        result = await webhook_service.send_webhook_to_external_endpoint(
            endpoint_url=endpoint_url,
            event_data=event_data,
            headers=headers,
            timeout=timeout
        )
        
        if result.get("sent"):
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "Webhook sent successfully",
                    **result
                }
            )
        else:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": "Failed to send webhook",
                    "error": result.get("error")
                }
            )
    
    except Exception as e:
        logger.error(f"Failed to send webhook to external endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send webhook")


@router.get("/health")
async def webhook_service_health(
    db: AsyncSession = Depends(get_db)
):
    """
    Check webhook service health
    """
    try:
        webhook_service = get_webhook_service(db)
        
        # Get recent statistics for health check
        stats = await webhook_service.get_webhook_statistics(1)  # Last 24 hours
        
        # Determine health status
        total_events = stats.get("total_events", 0)
        success_rate = stats.get("success_rate", 100)
        
        health_status = "healthy"
        if total_events > 0:
            if success_rate < 50:
                health_status = "critical"
            elif success_rate < 80:
                health_status = "degraded"
        
        return {
            "status": health_status,
            "webhook_processing": {
                "total_events_24h": total_events,
                "success_rate": success_rate,
                "retry_rate": stats.get("retry_rate", 0),
                "abandonment_rate": stats.get("abandonment_rate", 0)
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to check webhook service health: {str(e)}")
        return {
            "status": "unhealthy",
            "error": "Failed to check service health",
            "timestamp": datetime.utcnow().isoformat()
        }


@router.post("/events/{event_id}/requeue")
async def requeue_webhook_event(
    event_id: str,
    priority: int = Query(default=0, ge=0, le=10),
    db: AsyncSession = Depends(get_db)
):
    """
    Requeue a specific webhook event for processing
    """
    try:
        webhook_service = get_webhook_service(db)
        
        # Create a new webhook event for reprocessing
        # This is a simplified approach - in practice you'd get the original event
        result = await webhook_service.create_webhook_event(
            event_id=f"requeue_{event_id}",
            event_type="requeue.event",
            payload={"original_event_id": event_id},
            priority=priority
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": f"Event {event_id} requeued for processing",
                "new_event_id": result.get("event_id")
            }
        )
    
    except Exception as e:
        logger.error(f"Failed to requeue webhook event {event_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to requeue event")