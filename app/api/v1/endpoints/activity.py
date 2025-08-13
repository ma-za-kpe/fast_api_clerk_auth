from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Body, Query, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.exceptions import AuthorizationError
from app.api.v1.deps import get_current_user
from app.services.activity_service import get_activity_service, ActivityService, ActivityType
from app.db.database import get_db

router = APIRouter()
logger = structlog.get_logger()


def get_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent")
    }


@router.post("/track")
async def track_activity(
    activity_type: str = Body(...),
    resource_type: Optional[str] = Body(None),
    resource_id: Optional[str] = Body(None),
    details: Optional[Dict[str, Any]] = Body(None),
    duration_ms: Optional[int] = Body(None),
    success: bool = Body(True),
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Track user activity
    """
    try:
        client_info = get_client_info(request)
        
        result = await activity_service.track_activity(
            user_id=current_user.get("user_id"),
            activity_type=activity_type,
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            session_id=current_user.get("session_id"),
            organization_id=current_user.get("organization_id"),
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            duration_ms=duration_ms,
            success=success
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Failed to track activity: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to track activity")


@router.post("/session/start")
async def start_session(
    device_info: Optional[Dict[str, Any]] = Body(None),
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Start a new user session
    """
    try:
        client_info = get_client_info(request)
        
        result = await activity_service.start_session(
            user_id=current_user.get("user_id"),
            session_id=current_user.get("session_id", "unknown"),
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            organization_id=current_user.get("organization_id"),
            device_info=device_info
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Failed to start session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start session")


@router.post("/session/end")
async def end_session(
    reason: str = Body("logout"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    End current user session
    """
    try:
        result = await activity_service.end_session(
            session_id=current_user.get("session_id", "unknown"),
            user_id=current_user.get("user_id"),
            reason=reason
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Failed to end session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to end session")


@router.get("/history")
async def get_activity_history(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    activity_types: Optional[str] = Query(None, description="Comma-separated activity types"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Get user activity history
    """
    try:
        activity_type_list = activity_types.split(",") if activity_types else None
        
        activities = await activity_service.get_user_activity(
            user_id=current_user.get("user_id"),
            start_date=start_date,
            end_date=end_date,
            activity_types=activity_type_list,
            limit=limit,
            offset=offset
        )
        
        return {
            "activities": activities,
            "total": len(activities),
            "limit": limit,
            "offset": offset,
            "filters": {
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
                "activity_types": activity_type_list
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to get activity history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve activity history")


@router.get("/sessions")
async def get_user_sessions(
    active_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Get user session history
    """
    try:
        sessions = await activity_service.get_user_sessions(
            user_id=current_user.get("user_id"),
            active_only=active_only,
            limit=limit,
            offset=offset
        )
        
        return {
            "sessions": sessions,
            "total": len(sessions),
            "active_only": active_only,
            "limit": limit,
            "offset": offset
        }
    
    except Exception as e:
        logger.error(f"Failed to get user sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve sessions")


@router.get("/summary")
async def get_activity_summary(
    days_back: int = Query(30, ge=1, le=365),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Get user activity summary and insights
    """
    try:
        summary = await activity_service.get_activity_summary(
            user_id=current_user.get("user_id"),
            days_back=days_back
        )
        
        return summary
    
    except Exception as e:
        logger.error(f"Failed to get activity summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve activity summary")


@router.get("/organization/{org_id}")
async def get_organization_activity(
    org_id: str,
    days_back: int = Query(30, ge=1, le=365),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Get organization-wide activity insights (admin only)
    """
    try:
        if not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        activity_data = await activity_service.get_organization_activity(
            organization_id=org_id,
            days_back=days_back
        )
        
        return activity_data
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get organization activity: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve organization activity")


@router.get("/recent")
async def get_recent_activity(
    limit: int = Query(20, ge=1, le=50),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get recent activity from cache (for dashboard/real-time updates)
    """
    try:
        from app.services.cache_service import cache_service
        
        user_id = current_user.get("user_id")
        cache_key = f"recent_activity:{user_id}"
        
        recent_activities = await cache_service.get(cache_key) or []
        
        return {
            "recent_activities": recent_activities[:limit],
            "cached": True,
            "limit": limit,
            "last_updated": recent_activities[0]["timestamp"] if recent_activities else None
        }
    
    except Exception as e:
        logger.error(f"Failed to get recent activity: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve recent activity")


@router.get("/metrics/daily")
async def get_daily_metrics(
    days_back: int = Query(7, ge=1, le=30),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get daily activity metrics from cache
    """
    try:
        from app.services.cache_service import cache_service
        
        user_id = current_user.get("user_id")
        metrics = []
        
        for i in range(days_back):
            date = (datetime.utcnow() - timedelta(days=i)).date().isoformat()
            daily_key = f"activity_metrics:user:{user_id}:{date}"
            
            daily_metrics = await cache_service.get(daily_key) or {}
            metrics.append({
                "date": date,
                "total_activities": daily_metrics.get("total", 0),
                "breakdown": {
                    k: v for k, v in daily_metrics.items() 
                    if k != "total"
                }
            })
        
        return {
            "daily_metrics": metrics,
            "days_back": days_back,
            "user_id": user_id
        }
    
    except Exception as e:
        logger.error(f"Failed to get daily metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve daily metrics")


@router.post("/sessions/cleanup")
async def cleanup_inactive_sessions(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Clean up inactive sessions (admin only)
    """
    try:
        if not current_user.get("is_admin"):
            raise AuthorizationError("Admin privileges required")
        
        result = await activity_service.cleanup_inactive_sessions()
        
        return result
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to cleanup sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup sessions")


@router.get("/analytics/trends")
async def get_activity_trends(
    days_back: int = Query(30, ge=7, le=90),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Get activity trends and patterns
    """
    try:
        # Get activity data for trend analysis
        activities = await activity_service.get_user_activity(
            user_id=current_user.get("user_id"),
            start_date=datetime.utcnow() - timedelta(days=days_back),
            limit=1000
        )
        
        # Analyze trends
        daily_counts = {}
        hourly_patterns = {}
        activity_types = {}
        
        for activity in activities:
            # Parse timestamp
            timestamp = datetime.fromisoformat(activity["timestamp"])
            date_str = timestamp.date().isoformat()
            hour = timestamp.hour
            activity_type = activity["activity_type"]
            
            # Daily counts
            daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
            
            # Hourly patterns
            hourly_patterns[hour] = hourly_patterns.get(hour, 0) + 1
            
            # Activity type breakdown
            activity_types[activity_type] = activity_types.get(activity_type, 0) + 1
        
        # Calculate trends
        daily_values = list(daily_counts.values())
        trend_direction = "stable"
        if len(daily_values) >= 2:
            if daily_values[-1] > daily_values[0]:
                trend_direction = "increasing"
            elif daily_values[-1] < daily_values[0]:
                trend_direction = "decreasing"
        
        # Find peak hours
        peak_hour = max(hourly_patterns, key=hourly_patterns.get) if hourly_patterns else None
        
        return {
            "period_days": days_back,
            "total_activities": len(activities),
            "trend_direction": trend_direction,
            "peak_hour": peak_hour,
            "daily_activity": [
                {"date": date, "count": count}
                for date, count in sorted(daily_counts.items())
            ],
            "hourly_pattern": [
                {"hour": hour, "count": count}
                for hour, count in sorted(hourly_patterns.items())
            ],
            "activity_breakdown": [
                {"type": activity_type, "count": count}
                for activity_type, count in sorted(activity_types.items(), key=lambda x: x[1], reverse=True)
            ]
        }
    
    except Exception as e:
        logger.error(f"Failed to get activity trends: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve activity trends")


@router.get("/types")
async def get_activity_types():
    """
    Get list of available activity types
    """
    activity_types = [
        {
            "value": activity_type.value,
            "name": activity_type.name,
            "description": {
                "login": "User authentication events",
                "logout": "User logout events",
                "page_view": "Page navigation and viewing",
                "api_call": "API endpoint access",
                "feature_use": "Feature interaction and usage",
                "search": "Search and query operations",
                "export": "Data export operations",
                "upload": "File upload operations",
                "download": "File download operations",
                "settings_change": "Configuration changes",
                "profile_update": "Profile modifications"
            }.get(activity_type.value, "")
        }
        for activity_type in ActivityType
    ]
    
    return {
        "activity_types": activity_types,
        "total": len(activity_types)
    }


@router.get("/session/current")
async def get_current_session_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    activity_service: ActivityService = Depends(get_activity_service)
):
    """
    Get information about current session
    """
    try:
        sessions = await activity_service.get_user_sessions(
            user_id=current_user.get("user_id"),
            active_only=True,
            limit=10
        )
        
        # Find current session
        current_session_id = current_user.get("session_id")
        current_session = None
        
        for session in sessions:
            if session["session_id"] == current_session_id:
                current_session = session
                break
        
        return {
            "current_session": current_session,
            "total_active_sessions": len(sessions),
            "all_active_sessions": sessions
        }
    
    except Exception as e:
        logger.error(f"Failed to get current session info: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve session info")