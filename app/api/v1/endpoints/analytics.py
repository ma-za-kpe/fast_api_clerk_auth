from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException, Response
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
import structlog
import json
import io
import csv

from app.core.exceptions import AuthorizationError, ValidationError
from app.api.v1.deps import get_current_user
from app.core.permissions import require_permission
from app.services.analytics_service import get_analytics_service, AnalyticsService
from app.db.database import get_db

router = APIRouter()
logger = structlog.get_logger()


@router.get("/dashboard")
@require_permission("analytics:read")
async def get_analytics_dashboard(
    time_range: str = Query("24h", regex="^(24h|7d|30d|90d)$"),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Get comprehensive analytics dashboard metrics
    """
    try:
        metrics = await analytics_service.get_dashboard_metrics(
            time_range=time_range,
            organization_id=organization_id
        )
        
        return {
            "dashboard": metrics,
            "time_range": time_range,
            "organization_id": organization_id,
            "user_id": current_user["user_id"]
        }
    
    except Exception as e:
        logger.error(f"Failed to get analytics dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analytics dashboard")


@router.get("/users/growth")
@require_permission("analytics:read")
async def get_user_growth_analytics(
    days_back: int = Query(30, ge=1, le=365),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Get detailed user growth analytics
    """
    try:
        growth_data = await analytics_service.get_user_growth_analytics(
            days_back=days_back,
            organization_id=organization_id
        )
        
        return growth_data
    
    except Exception as e:
        logger.error(f"Failed to get user growth analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user growth analytics")


@router.get("/features/usage")
@require_permission("analytics:read")
async def get_feature_usage_analytics(
    days_back: int = Query(30, ge=1, le=90),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Get feature usage analytics and insights
    """
    try:
        usage_data = await analytics_service.get_feature_usage_analytics(
            days_back=days_back,
            organization_id=organization_id
        )
        
        return usage_data
    
    except Exception as e:
        logger.error(f"Failed to get feature usage analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve feature usage analytics")


@router.get("/sessions/analytics")
@require_permission("analytics:read")
async def get_session_analytics(
    days_back: int = Query(30, ge=1, le=90),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Get session analytics and insights
    """
    try:
        session_data = await analytics_service.get_session_analytics(
            days_back=days_back,
            organization_id=organization_id
        )
        
        return session_data
    
    except Exception as e:
        logger.error(f"Failed to get session analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve session analytics")


@router.get("/security/analytics")
@require_permission("analytics:read")
async def get_security_analytics(
    days_back: int = Query(30, ge=1, le=90),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Get security analytics and threat insights
    """
    try:
        security_data = await analytics_service.get_security_analytics(
            days_back=days_back,
            organization_id=organization_id
        )
        
        return security_data
    
    except Exception as e:
        logger.error(f"Failed to get security analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve security analytics")


@router.get("/performance/metrics")
@require_permission("analytics:read")
async def get_performance_metrics(
    days_back: int = Query(7, ge=1, le=30),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Get performance metrics and insights
    """
    try:
        performance_data = await analytics_service.get_performance_metrics(
            days_back=days_back,
            organization_id=organization_id
        )
        
        return performance_data
    
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve performance metrics")


@router.get("/real-time/metrics")
@require_permission("analytics:read")
async def get_real_time_metrics(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get real-time metrics from cache
    """
    try:
        from app.services.cache_service import cache_service
        
        # Get real-time metrics from cache
        current_time = datetime.utcnow()
        
        # Active sessions
        active_sessions_key = "real_time:active_sessions"
        active_sessions = await cache_service.get(active_sessions_key) or 0
        
        # Current hour metrics
        hour_key = f"metrics:hourly:{current_time.strftime('%Y%m%d%H')}"
        hourly_metrics = await cache_service.get(hour_key) or {}
        
        # Recent activities (last 5 minutes)
        recent_activities_key = f"metrics:recent_activities"
        recent_activities = await cache_service.get(recent_activities_key) or []
        
        # System load indicators
        system_metrics = {
            "active_sessions": active_sessions,
            "requests_this_hour": hourly_metrics.get("requests", 0),
            "errors_this_hour": hourly_metrics.get("errors", 0),
            "recent_activities_count": len(recent_activities),
            "timestamp": current_time.isoformat(),
            "uptime_status": "healthy"  # This would be calculated from system checks
        }
        
        return {
            "real_time_metrics": system_metrics,
            "recent_activities": recent_activities[-10:],  # Last 10 activities
            "refresh_interval": 30  # seconds
        }
    
    except Exception as e:
        logger.error(f"Failed to get real-time metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve real-time metrics")


@router.get("/trends/analysis")
@require_permission("analytics:read")
async def get_trends_analysis(
    metric_type: str = Query("user_activity", regex="^(user_activity|feature_usage|session_volume|security_events)$"),
    period: str = Query("daily", regex="^(hourly|daily|weekly)$"),
    days_back: int = Query(30, ge=7, le=90),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get trend analysis for various metrics
    """
    try:
        from sqlalchemy import select, func, text
        from app.db.models import AuditLog, UserSession
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        if metric_type == "user_activity":
            # Activity trends
            if period == "daily":
                query = select(
                    func.date(AuditLog.created_at).label('period'),
                    func.count(AuditLog.id).label('value')
                ).where(
                    AuditLog.created_at.between(start_date, end_date)
                ).group_by(func.date(AuditLog.created_at)).order_by('period')
            else:
                query = select(
                    func.extract('hour', AuditLog.created_at).label('period'),
                    func.count(AuditLog.id).label('value')
                ).where(
                    AuditLog.created_at.between(start_date, end_date)
                ).group_by(func.extract('hour', AuditLog.created_at)).order_by('period')
        
        elif metric_type == "session_volume":
            # Session trends
            if period == "daily":
                query = select(
                    func.date(UserSession.created_at).label('period'),
                    func.count(UserSession.id).label('value')
                ).where(
                    UserSession.created_at.between(start_date, end_date)
                ).group_by(func.date(UserSession.created_at)).order_by('period')
            else:
                query = select(
                    func.extract('hour', UserSession.created_at).label('period'),
                    func.count(UserSession.id).label('value')
                ).where(
                    UserSession.created_at.between(start_date, end_date)
                ).group_by(func.extract('hour', UserSession.created_at)).order_by('period')
        
        if organization_id:
            query = query.where(AuditLog.organization_id == organization_id)
        
        result = await db.execute(query)
        trend_data = [
            {
                "period": str(row.period),
                "value": row.value
            }
            for row in result.fetchall()
        ]
        
        # Calculate trend direction
        if len(trend_data) >= 2:
            recent_avg = sum(item["value"] for item in trend_data[-7:]) / min(7, len(trend_data))
            previous_avg = sum(item["value"] for item in trend_data[-14:-7]) / min(7, len(trend_data[-14:-7]))
            
            if recent_avg > previous_avg * 1.1:
                trend_direction = "increasing"
            elif recent_avg < previous_avg * 0.9:
                trend_direction = "decreasing"
            else:
                trend_direction = "stable"
        else:
            trend_direction = "insufficient_data"
        
        return {
            "metric_type": metric_type,
            "period": period,
            "days_analyzed": days_back,
            "trend_direction": trend_direction,
            "data_points": len(trend_data),
            "trend_data": trend_data,
            "organization_id": organization_id,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get trends analysis: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve trends analysis")


@router.get("/reports/summary")
@require_permission("analytics:read")
async def get_analytics_summary_report(
    report_type: str = Query("executive", regex="^(executive|detailed|security|usage)$"),
    days_back: int = Query(30, ge=7, le=90),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Generate comprehensive analytics summary reports
    """
    try:
        report_data = {
            "report_info": {
                "type": report_type,
                "period_days": days_back,
                "organization_id": organization_id,
                "generated_by": current_user["user_id"],
                "generated_at": datetime.utcnow().isoformat()
            }
        }
        
        if report_type == "executive":
            # High-level metrics for executives
            dashboard_metrics = await analytics_service.get_dashboard_metrics(
                time_range=f"{days_back}d",
                organization_id=organization_id
            )
            
            user_growth = await analytics_service.get_user_growth_analytics(
                days_back=days_back,
                organization_id=organization_id
            )
            
            report_data.update({
                "key_metrics": {
                    "total_users": user_growth.get("total_users", 0),
                    "active_users": user_growth.get("active_users_period", 0),
                    "growth_rate": user_growth.get("growth_rate_7d", 0),
                    "total_sessions": dashboard_metrics.get("total_sessions", 0),
                    "avg_session_duration": dashboard_metrics.get("avg_session_duration_minutes", 0)
                },
                "insights": [
                    f"User base growth rate: {user_growth.get('growth_rate_7d', 0):.1f}%",
                    f"User retention: {user_growth.get('retention_rate', 0):.1f}%",
                    f"Average session duration: {dashboard_metrics.get('avg_session_duration_minutes', 0):.1f} minutes"
                ]
            })
        
        elif report_type == "detailed":
            # Comprehensive analytics
            report_data["user_analytics"] = await analytics_service.get_user_growth_analytics(
                days_back=days_back, organization_id=organization_id
            )
            report_data["feature_analytics"] = await analytics_service.get_feature_usage_analytics(
                days_back=days_back, organization_id=organization_id
            )
            report_data["session_analytics"] = await analytics_service.get_session_analytics(
                days_back=days_back, organization_id=organization_id
            )
        
        elif report_type == "security":
            # Security-focused report
            report_data["security_analytics"] = await analytics_service.get_security_analytics(
                days_back=days_back, organization_id=organization_id
            )
            
            # Add security recommendations
            security_data = report_data["security_analytics"]
            recommendations = []
            
            if security_data.get("login_success_rate", 100) < 95:
                recommendations.append("Consider implementing additional brute force protection")
            
            if security_data.get("failed_login_attempts", 0) > 100:
                recommendations.append("Monitor for suspicious login patterns")
            
            if security_data.get("mfa_adoption", 0) < security_data.get("total_users", 1) * 0.5:
                recommendations.append("Encourage MFA adoption among users")
            
            report_data["recommendations"] = recommendations
        
        elif report_type == "usage":
            # Feature usage focused report
            report_data["feature_usage"] = await analytics_service.get_feature_usage_analytics(
                days_back=days_back, organization_id=organization_id
            )
            report_data["performance_metrics"] = await analytics_service.get_performance_metrics(
                days_back=min(days_back, 7), organization_id=organization_id
            )
        
        return report_data
    
    except Exception as e:
        logger.error(f"Failed to generate analytics summary report: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate analytics report")


@router.get("/export")
@require_permission("analytics:export")
async def export_analytics_data(
    metrics: str = Query(..., description="Comma-separated list of metrics to export"),
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    format: str = Query("json", regex="^(json|csv)$"),
    organization_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service)
):
    """
    Export analytics data in various formats
    """
    try:
        if end_date <= start_date:
            raise HTTPException(status_code=400, detail="End date must be after start date")
        
        if (end_date - start_date).days > 365:
            raise HTTPException(status_code=400, detail="Date range cannot exceed 365 days")
        
        metric_list = [m.strip() for m in metrics.split(",")]
        
        export_data = await analytics_service.export_analytics_data(
            metric_types=metric_list,
            start_date=start_date,
            end_date=end_date,
            format=format,
            organization_id=organization_id
        )
        
        if format == "json":
            return JSONResponse(content=export_data)
        
        elif format == "csv":
            # Convert to CSV format
            output = io.StringIO()
            
            # Write CSV header
            fieldnames = ["metric_type", "date", "value", "additional_data"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write data rows
            for metric_type, data in export_data.get("data", {}).items():
                if isinstance(data, dict) and "daily_growth" in data:
                    for item in data["daily_growth"]:
                        writer.writerow({
                            "metric_type": metric_type,
                            "date": item["date"],
                            "value": item.get("new_users", 0),
                            "additional_data": ""
                        })
            
            output.seek(0)
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode()),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=analytics_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export analytics data: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to export analytics data")


@router.get("/health")
async def get_analytics_health(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get analytics system health status
    """
    try:
        from app.services.cache_service import cache_service
        
        # Check database connectivity
        db_healthy = True
        try:
            # Simple query to test DB
            from app.db.database import get_db
            async for db_session in get_db():
                await db_session.execute(text("SELECT 1"))
                break
        except Exception:
            db_healthy = False
        
        # Check cache connectivity
        cache_healthy = True
        try:
            await cache_service.set("health_check", "ok", expire=10)
            test_value = await cache_service.get("health_check")
            cache_healthy = test_value == "ok"
        except Exception:
            cache_healthy = False
        
        # Get system metrics
        system_status = {
            "database": "healthy" if db_healthy else "unhealthy",
            "cache": "healthy" if cache_healthy else "unhealthy",
            "overall": "healthy" if db_healthy and cache_healthy else "unhealthy",
            "checked_at": datetime.utcnow().isoformat(),
            "metrics_available": db_healthy,
            "real_time_data": cache_healthy
        }
        
        return system_status
    
    except Exception as e:
        logger.error(f"Failed to check analytics health: {str(e)}")
        return {
            "overall": "unhealthy",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


@router.post("/refresh-cache")
@require_permission("analytics:manage")
async def refresh_analytics_cache(
    metric_types: Optional[List[str]] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Manually refresh analytics cache (admin only)
    """
    try:
        from app.services.cache_service import cache_service
        
        if not metric_types:
            metric_types = ["dashboard", "user_growth", "feature_usage", "sessions", "security"]
        
        refreshed_metrics = []
        
        for metric_type in metric_types:
            cache_pattern = f"*{metric_type}*"
            cache_keys = await cache_service.get_pattern(cache_pattern)
            
            for key in cache_keys:
                await cache_service.delete(key)
                refreshed_metrics.append(key)
        
        logger.info(f"Analytics cache refreshed by {current_user['user_id']}", metrics=metric_types)
        
        return {
            "cache_refreshed": True,
            "metric_types": metric_types,
            "keys_cleared": len(refreshed_metrics),
            "refreshed_by": current_user["user_id"],
            "refreshed_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to refresh analytics cache: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to refresh analytics cache")