from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.exceptions import AuthorizationError
from app.api.v1.deps import get_current_user
from app.services.audit_service import get_audit_service, AuditService, AuditSeverity
from app.db.database import get_db

router = APIRouter()
logger = structlog.get_logger()


@router.get("/user/{user_id}")
async def get_user_audit_events(
    user_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_types: Optional[str] = Query(None, description="Comma-separated event types"),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    severity: Optional[str] = Query(None, description="low, medium, high, critical"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Get audit events for a specific user
    """
    try:
        # Check permissions - users can only see their own events unless admin
        if user_id != current_user.get("user_id") and not current_user.get("is_admin"):
            raise AuthorizationError("Insufficient permissions to view audit events")
        
        # Parse parameters
        event_type_list = event_types.split(",") if event_types else None
        severity_enum = AuditSeverity(severity) if severity else None
        
        events = await audit_service.get_user_events(
            user_id=user_id,
            limit=limit,
            offset=offset,
            event_types=event_type_list,
            start_date=start_date,
            end_date=end_date,
            severity=severity_enum
        )
        
        return {
            "events": events,
            "total": len(events),
            "limit": limit,
            "offset": offset,
            "user_id": user_id
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid parameter: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to get user audit events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit events")


@router.get("/organization/{org_id}")
async def get_organization_audit_events(
    org_id: str,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_types: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Get audit events for an organization (admin only)
    """
    try:
        # Check admin permissions for organization
        if not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        event_type_list = event_types.split(",") if event_types else None
        
        events = await audit_service.get_organization_events(
            organization_id=org_id,
            limit=limit,
            offset=offset,
            event_types=event_type_list,
            start_date=start_date,
            end_date=end_date
        )
        
        return {
            "events": events,
            "total": len(events),
            "limit": limit,
            "offset": offset,
            "organization_id": org_id
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get organization audit events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit events")


@router.get("/security")
async def get_security_events(
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    hours_back: int = Query(24, ge=1, le=168),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Get security-related audit events (admin only)
    """
    try:
        if not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        severity_enum = AuditSeverity(severity) if severity else None
        
        events = await audit_service.get_security_events(
            limit=limit,
            offset=offset,
            severity=severity_enum,
            hours_back=hours_back
        )
        
        return {
            "events": events,
            "total": len(events),
            "limit": limit,
            "offset": offset,
            "hours_back": hours_back,
            "severity_filter": severity
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to get security events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve security events")


@router.get("/statistics")
async def get_audit_statistics(
    user_id: Optional[str] = Query(None),
    organization_id: Optional[str] = Query(None),
    days_back: int = Query(30, ge=1, le=365),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Get audit event statistics
    """
    try:
        # Check permissions
        if user_id and user_id != current_user.get("user_id") and not current_user.get("is_admin"):
            raise AuthorizationError("Insufficient permissions")
        
        if organization_id and not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required for organization statistics")
        
        # Default to current user if no specific user requested
        if not user_id and not organization_id:
            user_id = current_user.get("user_id")
        
        stats = await audit_service.get_event_statistics(
            user_id=user_id,
            organization_id=organization_id,
            days_back=days_back
        )
        
        return stats
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get audit statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.get("/search")
async def search_audit_events(
    q: str = Query(..., description="Search term"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user_id: Optional[str] = Query(None),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Search audit events by content
    """
    try:
        # Check permissions
        if user_id and user_id != current_user.get("user_id") and not current_user.get("is_admin"):
            raise AuthorizationError("Insufficient permissions")
        
        if organization_id and not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        # Default to current user if no scope specified
        if not user_id and not organization_id and not current_user.get("is_admin"):
            user_id = current_user.get("user_id")
        
        events = await audit_service.search_events(
            search_term=q,
            limit=limit,
            offset=offset,
            user_id=user_id,
            organization_id=organization_id
        )
        
        return {
            "events": events,
            "total": len(events),
            "search_term": q,
            "limit": limit,
            "offset": offset
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to search audit events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to search events")


@router.post("/export")
async def export_audit_events(
    user_id: Optional[str] = Body(None),
    organization_id: Optional[str] = Body(None),
    start_date: Optional[datetime] = Body(None),
    end_date: Optional[datetime] = Body(None),
    format: str = Body("json", description="json or csv"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Export audit events for compliance/backup
    """
    try:
        # Check permissions
        if user_id and user_id != current_user.get("user_id") and not current_user.get("is_admin"):
            raise AuthorizationError("Insufficient permissions")
        
        if organization_id and not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        if format not in ["json", "csv"]:
            raise HTTPException(status_code=400, detail="Format must be 'json' or 'csv'")
        
        # Default to current user if no scope specified
        if not user_id and not organization_id and not current_user.get("is_admin"):
            user_id = current_user.get("user_id")
        
        export_data = await audit_service.export_events(
            user_id=user_id,
            organization_id=organization_id,
            start_date=start_date,
            end_date=end_date,
            format=format
        )
        
        # Log export action
        await audit_service.log_event(
            event_type="data_export_requested",
            user_id=current_user.get("user_id"),
            details={
                "export_type": "audit_events",
                "target_user_id": user_id,
                "target_organization_id": organization_id,
                "format": format,
                "date_range": {
                    "start": start_date.isoformat() if start_date else None,
                    "end": end_date.isoformat() if end_date else None
                }
            }
        )
        
        return export_data
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to export audit events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to export events")


@router.post("/log")
async def log_custom_event(
    event_type: str = Body(...),
    details: Optional[Dict[str, Any]] = Body(None),
    severity: str = Body("low"),
    resource_type: Optional[str] = Body(None),
    resource_id: Optional[str] = Body(None),
    action: Optional[str] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Log a custom audit event (for application integration)
    """
    try:
        severity_enum = AuditSeverity(severity)
        
        result = await audit_service.log_event(
            event_type=event_type,
            user_id=current_user.get("user_id"),
            details=details,
            severity=severity_enum,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action
        )
        
        return result
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid parameter: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to log custom event: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to log event")


@router.get("/recent")
async def get_recent_events(
    limit: int = Query(20, ge=1, le=50),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Get recent audit events for current user (cached for performance)
    """
    try:
        from app.services.cache_service import cache_service
        
        user_id = current_user.get("user_id")
        cache_key = f"recent_events:{user_id}"
        
        # Try cache first
        recent_events = await cache_service.get(cache_key)
        
        if recent_events:
            return {
                "events": recent_events[:limit],
                "cached": True,
                "limit": limit
            }
        
        # Fallback to database
        events = await audit_service.get_user_events(
            user_id=user_id,
            limit=limit,
            offset=0
        )
        
        return {
            "events": events,
            "cached": False,
            "limit": limit
        }
    
    except Exception as e:
        logger.error(f"Failed to get recent events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve recent events")


@router.delete("/cleanup")
async def cleanup_old_audit_events(
    days_to_keep: Optional[int] = Body(None, ge=30, le=3650),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service)
):
    """
    Clean up old audit events (admin only)
    """
    try:
        if not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        result = await audit_service.cleanup_old_events(days_to_keep)
        
        # Log cleanup action
        await audit_service.log_event(
            event_type="admin_action",
            user_id=current_user.get("user_id"),
            details={
                "action": "audit_cleanup",
                "events_deleted": result.get("events_deleted", 0),
                "retention_days": result.get("retention_days")
            },
            severity=AuditSeverity.MEDIUM
        )
        
        return result
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to cleanup audit events: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup events")


@router.get("/event-types")
async def get_event_types():
    """
    Get list of available event types
    """
    from app.services.audit_service import AuditEventType
    
    event_types = [
        {
            "value": event.value,
            "name": event.name,
            "category": event.value.split("_")[0] if "_" in event.value else "other"
        }
        for event in AuditEventType
    ]
    
    # Group by category
    categories = {}
    for event_type in event_types:
        category = event_type["category"]
        if category not in categories:
            categories[category] = []
        categories[category].append(event_type)
    
    return {
        "event_types": event_types,
        "categories": categories,
        "total": len(event_types)
    }


@router.get("/severity-levels")
async def get_severity_levels():
    """
    Get list of available severity levels
    """
    return {
        "severity_levels": [
            {
                "value": severity.value,
                "name": severity.name,
                "description": {
                    "low": "Routine operations and informational events",
                    "medium": "Important events that should be monitored", 
                    "high": "Significant events requiring attention",
                    "critical": "Critical security or system events"
                }.get(severity.value, "")
            }
            for severity in AuditSeverity
        ]
    }