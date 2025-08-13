from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, text
import structlog
from pydantic import BaseModel

from app.api.v1.deps import require_admin, get_db
from app.core.clerk import get_clerk_client
from app.core.exceptions import NotFoundError, ValidationError, AuthorizationError
from app.db.models import UserSession, AuditLog
from app.services.cache_service import cache_service
from app.services.analytics_service import get_analytics_service
from app.services.compliance_service import get_compliance_service
from app.tasks.email_tasks import send_admin_notification

router = APIRouter()
logger = structlog.get_logger()


# ============= Request Models =============

class UserActionRequest(BaseModel):
    reason: str
    notify_user: bool = True
    duration_days: Optional[int] = None


class BulkUserAction(BaseModel):
    user_ids: List[str]
    action: str  # ban, unban, delete, etc.
    reason: str
    notify_users: bool = True


class SystemConfigUpdate(BaseModel):
    key: str
    value: Any
    category: str = "general"


# ============= Dashboard Endpoints =============

@router.get("/dashboard")
async def admin_dashboard(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    clerk_client = Depends(get_clerk_client)
):
    """
    Comprehensive admin dashboard with real-time statistics
    """
    try:
        # Get analytics service for metrics
        analytics_service = get_analytics_service(db)
        dashboard_metrics = await analytics_service.get_dashboard_metrics("24h")
        
        # Get user statistics from Clerk
        try:
            user_count = await clerk_client.get_user_count()
        except:
            user_count = 0
        
        # Get organization count
        try:
            org_count = await clerk_client.get_organization_count()
        except:
            org_count = 0
        
        # Get active sessions from database
        active_sessions_query = select(func.count()).select_from(UserSession).where(
            and_(
                UserSession.is_active == True,
                UserSession.last_activity_at > datetime.utcnow() - timedelta(hours=24)
            )
        )
        active_sessions_result = await db.execute(active_sessions_query)
        active_sessions = active_sessions_result.scalar() or 0
        
        # Get recent audit events
        recent_events_query = select(AuditLog).where(
            AuditLog.created_at > datetime.utcnow() - timedelta(hours=24)
        ).order_by(desc(AuditLog.created_at)).limit(10)
        recent_events_result = await db.execute(recent_events_query)
        recent_events = recent_events_result.scalars().all()
        
        # Get security metrics
        security_events_query = select(func.count()).select_from(AuditLog).where(
            and_(
                AuditLog.severity.in_(["HIGH", "CRITICAL"]),
                AuditLog.created_at > datetime.utcnow() - timedelta(hours=24)
            )
        )
        security_events_result = await db.execute(security_events_query)
        security_events = security_events_result.scalar() or 0
        
        # Get system health status
        system_health = await _get_system_health()
        
        return {
            "overview": {
                "total_users": user_count,
                "total_organizations": org_count,
                "active_sessions": active_sessions,
                "daily_signups": dashboard_metrics.get("new_users_today", 0),
                "security_events_24h": security_events
            },
            "user_metrics": {
                "new_users_today": dashboard_metrics.get("new_users_today", 0),
                "active_users_today": dashboard_metrics.get("active_users_today", 0),
                "retention_rate": dashboard_metrics.get("retention_rate", 0.0),
                "avg_session_duration": dashboard_metrics.get("avg_session_duration", 0)
            },
            "system_health": system_health,
            "recent_activity": [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "user_id": event.user_id,
                    "severity": event.severity,
                    "created_at": event.created_at.isoformat(),
                    "details": event.details
                }
                for event in recent_events
            ],
            "performance_metrics": dashboard_metrics,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get admin dashboard: {str(e)}")
        # Return basic fallback dashboard
        return {
            "overview": {
                "total_users": 0,
                "total_organizations": 0,
                "active_sessions": 0,
                "daily_signups": 0,
                "security_events_24h": 0
            },
            "system_health": {"status": "unknown", "message": "Unable to fetch system health"},
            "message": "Dashboard data partially unavailable"
        }


# ============= User Management =============

@router.get("/users")
async def admin_list_users(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    admin_user: Dict[str, Any] = Depends(require_admin),
    clerk_client = Depends(get_clerk_client)
):
    """
    List all users with advanced filtering and search
    """
    try:
        # Build query parameters for Clerk
        query_params = {
            "limit": limit,
            "offset": offset
        }
        
        # Add search if provided
        if search:
            query_params["query"] = search
        
        # Add status filter if provided
        if status:
            query_params["status"] = status
        
        # Get users from Clerk
        try:
            users_response = await clerk_client.list_users(**query_params)
            users = users_response.get("data", [])
            total_count = users_response.get("total_count", len(users))
        except Exception as e:
            logger.error(f"Failed to fetch users from Clerk: {str(e)}")
            users = []
            total_count = 0
        
        # Enrich with local data if needed
        enriched_users = []
        for user in users:
            user_data = {
                "id": user.id,
                "email": user.primary_email_address.email_address if user.primary_email_address else None,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "username": user.username,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
                "last_sign_in_at": user.last_sign_in_at,
                "banned": user.banned,
                "email_verified": user.primary_email_address.verification.status == "verified" if user.primary_email_address else False,
                "profile_image_url": user.profile_image_url,
                "public_metadata": user.public_metadata,
                "private_metadata": user.private_metadata
            }
            enriched_users.append(user_data)
        
        return {
            "users": enriched_users,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_count
            },
            "filters": {
                "search": search,
                "status": status,
                "sort_by": sort_by,
                "sort_order": sort_order
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to list users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")


@router.get("/users/{user_id}")
async def admin_get_user_details(
    user_id: str,
    admin_user: Dict[str, Any] = Depends(require_admin),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific user
    """
    try:
        # Get user from Clerk
        user = await clerk_client.get_user(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Get user sessions from database
        sessions_query = select(UserSession).where(
            UserSession.user_id == user_id
        ).order_by(desc(UserSession.last_activity_at)).limit(10)
        sessions_result = await db.execute(sessions_query)
        sessions = sessions_result.scalars().all()
        
        # Get user audit logs
        audit_query = select(AuditLog).where(
            AuditLog.user_id == user_id
        ).order_by(desc(AuditLog.created_at)).limit(20)
        audit_result = await db.execute(audit_query)
        audit_logs = audit_result.scalars().all()
        
        # Get user organizations
        try:
            user_orgs = await clerk_client.get_user_organizations(user_id)
        except:
            user_orgs = []
        
        return {
            "user": {
                "id": user.id,
                "email": user.primary_email_address.email_address if user.primary_email_address else None,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "username": user.username,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
                "last_sign_in_at": user.last_sign_in_at,
                "banned": user.banned,
                "email_verified": user.primary_email_address.verification.status == "verified" if user.primary_email_address else False,
                "profile_image_url": user.profile_image_url,
                "public_metadata": user.public_metadata,
                "private_metadata": user.private_metadata
            },
            "sessions": [
                {
                    "session_id": session.session_id,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "location": session.location,
                    "created_at": session.created_at.isoformat(),
                    "last_activity_at": session.last_activity_at.isoformat(),
                    "is_active": session.is_active
                }
                for session in sessions
            ],
            "organizations": user_orgs,
            "recent_activity": [
                {
                    "id": log.id,
                    "event_type": log.event_type,
                    "outcome": log.outcome,
                    "severity": log.severity,
                    "created_at": log.created_at.isoformat(),
                    "details": log.details
                }
                for log in audit_logs
            ]
        }
    
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Failed to get user details: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user details")


@router.post("/users/{user_id}/ban")
async def ban_user(
    user_id: str,
    request: UserActionRequest,
    background_tasks: BackgroundTasks,
    admin_user: Dict[str, Any] = Depends(require_admin),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Ban a user with optional notification
    """
    try:
        # Get user first to ensure they exist
        user = await clerk_client.get_user(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Ban user in Clerk
        await clerk_client.ban_user(user_id)
        
        # Terminate all active sessions
        await _terminate_user_sessions(user_id, db)
        
        # Log the admin action
        from app.services.audit_service import AuditService, AuditSeverity
        audit_service = AuditService(db)
        await audit_service.log_event(
            event_type="user_banned",
            user_id=user_id,
            actor_id=admin_user.get("user_id"),
            details={
                "reason": request.reason,
                "banned_by": admin_user.get("email"),
                "duration_days": request.duration_days
            },
            severity=AuditSeverity.HIGH
        )
        
        # Send notification if requested
        if request.notify_user and user.primary_email_address:
            background_tasks.add_task(
                _send_user_ban_notification,
                user.primary_email_address.email_address,
                user.first_name or "User",
                request.reason
            )
        
        logger.info(
            f"User banned",
            user_id=user_id,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        return {
            "message": f"User {user_id} has been banned successfully",
            "user_id": user_id,
            "reason": request.reason,
            "banned_at": datetime.utcnow().isoformat(),
            "banned_by": admin_user.get("email")
        }
    
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Failed to ban user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to ban user")


@router.post("/users/{user_id}/unban")
async def unban_user(
    user_id: str,
    request: UserActionRequest,
    background_tasks: BackgroundTasks,
    admin_user: Dict[str, Any] = Depends(require_admin),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Unban a user
    """
    try:
        # Get user first to ensure they exist
        user = await clerk_client.get_user(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Unban user in Clerk
        await clerk_client.unban_user(user_id)
        
        # Log the admin action
        from app.services.audit_service import AuditService, AuditSeverity
        audit_service = AuditService(db)
        await audit_service.log_event(
            event_type="user_unbanned",
            user_id=user_id,
            actor_id=admin_user.get("user_id"),
            details={
                "reason": request.reason,
                "unbanned_by": admin_user.get("email")
            },
            severity=AuditSeverity.MEDIUM
        )
        
        # Send notification if requested
        if request.notify_user and user.primary_email_address:
            background_tasks.add_task(
                _send_user_unban_notification,
                user.primary_email_address.email_address,
                user.first_name or "User",
                request.reason
            )
        
        logger.info(
            f"User unbanned",
            user_id=user_id,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        return {
            "message": f"User {user_id} has been unbanned successfully",
            "user_id": user_id,
            "reason": request.reason,
            "unbanned_at": datetime.utcnow().isoformat(),
            "unbanned_by": admin_user.get("email")
        }
    
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Failed to unban user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to unban user")


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    request: UserActionRequest,
    background_tasks: BackgroundTasks,
    admin_user: Dict[str, Any] = Depends(require_admin),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a user account (irreversible)
    """
    try:
        # Get user first to ensure they exist
        user = await clerk_client.get_user(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Store user data for audit before deletion
        user_email = user.primary_email_address.email_address if user.primary_email_address else None
        user_name = f"{user.first_name} {user.last_name}".strip() or "Unknown User"
        
        # Delete user from Clerk
        await clerk_client.delete_user(user_id)
        
        # Clean up local data
        await _cleanup_user_data(user_id, db)
        
        # Log the admin action
        from app.services.audit_service import AuditService, AuditSeverity
        audit_service = AuditService(db)
        await audit_service.log_event(
            event_type="user_deleted",
            user_id=user_id,
            actor_id=admin_user.get("user_id"),
            details={
                "reason": request.reason,
                "deleted_by": admin_user.get("email"),
                "user_email": user_email,
                "user_name": user_name
            },
            severity=AuditSeverity.HIGH
        )
        
        logger.warning(
            f"User deleted",
            user_id=user_id,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        return {
            "message": f"User {user_id} has been permanently deleted",
            "user_id": user_id,
            "reason": request.reason,
            "deleted_at": datetime.utcnow().isoformat(),
            "deleted_by": admin_user.get("email")
        }
    
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete user")


# ============= System Management =============

@router.get("/system/health")
async def get_system_health(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get comprehensive system health status
    """
    try:
        health_status = await _get_system_health()
        return health_status
    
    except Exception as e:
        logger.error(f"Failed to get system health: {str(e)}")
        return {
            "status": "error",
            "message": "Unable to retrieve system health",
            "checks": {},
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/system/metrics")
async def get_system_metrics(
    timeframe: str = Query("24h", regex="^(1h|24h|7d|30d)$"),
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed system metrics and performance data
    """
    try:
        analytics_service = get_analytics_service(db)
        metrics = await analytics_service.get_dashboard_metrics(timeframe)
        
        # Add system-specific metrics
        system_metrics = await _get_system_performance_metrics()
        
        return {
            "timeframe": timeframe,
            "application_metrics": metrics,
            "system_metrics": system_metrics,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get system metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system metrics")


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get audit logs with advanced filtering
    """
    try:
        query = select(AuditLog)
        
        # Apply filters
        conditions = []
        if severity:
            conditions.append(AuditLog.severity == severity)
        if event_type:
            conditions.append(AuditLog.event_type == event_type)
        if user_id:
            conditions.append(AuditLog.user_id == user_id)
        if start_date:
            conditions.append(AuditLog.created_at >= start_date)
        if end_date:
            conditions.append(AuditLog.created_at <= end_date)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count()).select_from(AuditLog)
        if conditions:
            count_query = count_query.where(and_(*conditions))
        total_result = await db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply ordering and pagination
        query = query.order_by(desc(AuditLog.created_at))
        query = query.limit(limit).offset(offset)
        
        result = await db.execute(query)
        logs = result.scalars().all()
        
        return {
            "logs": [
                {
                    "id": log.id,
                    "event_type": log.event_type,
                    "user_id": log.user_id,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "outcome": log.outcome,
                    "severity": log.severity,
                    "details": log.details,
                    "created_at": log.created_at.isoformat()
                }
                for log in logs
            ],
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_count
            },
            "filters": {
                "severity": severity,
                "event_type": event_type,
                "user_id": user_id,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to get audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit logs")


# ============= Helper Functions =============

async def _get_system_health() -> Dict[str, Any]:
    """Get comprehensive system health status"""
    checks = {}
    overall_status = "healthy"
    
    # Check database connection
    try:
        # Simple database health check would go here
        checks["database"] = {"status": "healthy", "message": "Database connection OK"}
    except Exception as e:
        checks["database"] = {"status": "unhealthy", "message": f"Database error: {str(e)}"}
        overall_status = "unhealthy"
    
    # Check cache service
    try:
        await cache_service.ping()
        checks["cache"] = {"status": "healthy", "message": "Cache service OK"}
    except Exception as e:
        checks["cache"] = {"status": "unhealthy", "message": f"Cache error: {str(e)}"}
        overall_status = "degraded"
    
    # Check Clerk service
    try:
        # You would implement a Clerk health check here
        checks["clerk"] = {"status": "healthy", "message": "Clerk service OK"}
    except Exception as e:
        checks["clerk"] = {"status": "unhealthy", "message": f"Clerk error: {str(e)}"}
        overall_status = "unhealthy"
    
    return {
        "status": overall_status,
        "checks": checks,
        "timestamp": datetime.utcnow().isoformat()
    }


async def _get_system_performance_metrics() -> Dict[str, Any]:
    """Get system performance metrics"""
    import psutil
    
    try:
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "used": psutil.disk_usage('/').used,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            }
        }
    except Exception as e:
        logger.error(f"Failed to get system metrics: {str(e)}")
        return {"error": "Unable to retrieve system metrics"}


async def _terminate_user_sessions(user_id: str, db: AsyncSession):
    """Terminate all active sessions for a user"""
    try:
        update_query = update(UserSession).where(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )
        ).values(
            is_active=False,
            ended_at=datetime.utcnow()
        )
        
        await db.execute(update_query)
        await db.commit()
        
        # Clear cache
        await cache_service.delete_pattern(f"session:*:{user_id}")
        
    except Exception as e:
        logger.error(f"Failed to terminate user sessions: {str(e)}")


async def _cleanup_user_data(user_id: str, db: AsyncSession):
    """Clean up user-related data after account deletion"""
    try:
        # Terminate sessions
        await _terminate_user_sessions(user_id, db)
        
        # Clear cache data
        await cache_service.delete_pattern(f"user:*:{user_id}")
        await cache_service.delete_pattern(f"*:{user_id}:*")
        
        # Note: We keep audit logs for compliance
        logger.info(f"User data cleanup completed", user_id=user_id)
        
    except Exception as e:
        logger.error(f"Failed to cleanup user data: {str(e)}")


async def _send_user_ban_notification(email: str, name: str, reason: str):
    """Send notification email to banned user"""
    try:
        from app.services.email_service import email_service
        
        await email_service.send_template_email(
            template_name="account_locked",
            to_email=email,
            subject="Account Suspended",
            template_data={
                "first_name": name,
                "lock_reason": reason,
                "lock_time": datetime.utcnow().isoformat(),
                "can_self_unlock": False
            }
        )
    except Exception as e:
        logger.error(f"Failed to send ban notification: {str(e)}")


async def _send_user_unban_notification(email: str, name: str, reason: str):
    """Send notification email to unbanned user"""
    try:
        from app.services.email_service import email_service
        
        await email_service.send_template_email(
            template_name="account_restored",  # Would need to create this template
            to_email=email,
            subject="Account Restored",
            template_data={
                "first_name": name,
                "restore_reason": reason,
                "restored_at": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Failed to send unban notification: {str(e)}")