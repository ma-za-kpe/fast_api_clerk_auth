from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func
import structlog
import json
from enum import Enum

from app.db.models import UserSession, AuditLog
from app.services.cache_service import cache_service
from app.services.audit_service import AuditService, AuditEventType, AuditSeverity
from app.core.config import settings

logger = structlog.get_logger()


class ActivityType(Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    PAGE_VIEW = "page_view"
    API_CALL = "api_call"
    FEATURE_USE = "feature_use"
    SEARCH = "search"
    EXPORT = "export"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    SETTINGS_CHANGE = "settings_change"
    PROFILE_UPDATE = "profile_update"


class ActivityService:
    """
    Service for tracking user activity and generating insights
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_service = AuditService(db)
        self.session_timeout_minutes = getattr(settings, 'SESSION_TIMEOUT_MINUTES', 60)
        self.activity_retention_days = getattr(settings, 'ACTIVITY_RETENTION_DAYS', 90)
    
    async def track_activity(
        self,
        user_id: str,
        activity_type: Union[ActivityType, str],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        success: bool = True
    ) -> Dict[str, Any]:
        """
        Track user activity
        """
        try:
            # Convert enum to string if needed
            if isinstance(activity_type, ActivityType):
                activity_type = activity_type.value
            
            activity_details = {
                **(details or {}),
                "activity_type": activity_type,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "duration_ms": duration_ms,
                "success": success,
                "tracked_at": datetime.utcnow().isoformat()
            }
            
            # Update session activity
            if session_id:
                await self._update_session_activity(
                    session_id=session_id,
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            
            # Log as audit event
            audit_result = await self.audit_service.log_event(
                event_type=f"activity_{activity_type}",
                user_id=user_id,
                organization_id=organization_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=activity_details,
                session_id=session_id,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome="success" if success else "failure"
            )
            
            # Track in cache for real-time analytics
            await self._cache_activity(user_id, activity_type, activity_details)
            
            # Update activity metrics
            await self._update_activity_metrics(user_id, organization_id, activity_type)
            
            logger.debug(
                f"Activity tracked",
                user_id=user_id,
                activity_type=activity_type,
                success=success
            )
            
            return {
                "tracked": True,
                "activity_type": activity_type,
                "timestamp": datetime.utcnow().isoformat(),
                "audit_id": audit_result.get("id")
            }
        
        except Exception as e:
            logger.error(f"Failed to track activity: {str(e)}")
            return {"tracked": False, "error": str(e)}
    
    async def start_session(
        self,
        user_id: str,
        session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        organization_id: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Start a new user session
        """
        try:
            # Get location from IP (placeholder for geolocation service)
            location = await self._get_location_from_ip(ip_address) if ip_address else None
            
            # Create session record
            session = UserSession(
                session_id=session_id,
                user_id=user_id,
                organization_id=organization_id,
                ip_address=ip_address,
                user_agent=user_agent,
                location=location,
                device_info=device_info,
                is_active=True,
                created_at=datetime.utcnow(),
                last_activity_at=datetime.utcnow()
            )
            
            self.db.add(session)
            await self.db.commit()
            
            # Track login activity
            await self.track_activity(
                user_id=user_id,
                activity_type=ActivityType.LOGIN,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                organization_id=organization_id,
                details={
                    "location": location,
                    "device_info": device_info
                }
            )
            
            # Cache active session
            await self._cache_active_session(user_id, session_id)
            
            logger.info(
                f"Session started",
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address
            )
            
            return {
                "session_started": True,
                "session_id": session_id,
                "location": location,
                "started_at": session.created_at.isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to start session: {str(e)}")
            await self.db.rollback()
            return {"session_started": False, "error": str(e)}
    
    async def end_session(
        self,
        session_id: str,
        user_id: Optional[str] = None,
        reason: str = "logout"
    ) -> Dict[str, Any]:
        """
        End a user session
        """
        try:
            # Get session
            query = select(UserSession).where(
                and_(
                    UserSession.session_id == session_id,
                    UserSession.is_active == True
                )
            )
            
            if user_id:
                query = query.where(UserSession.user_id == user_id)
            
            result = await self.db.execute(query)
            session = result.scalar_one_or_none()
            
            if not session:
                return {"session_ended": False, "error": "Session not found"}
            
            # Calculate session duration
            duration_seconds = int((datetime.utcnow() - session.created_at).total_seconds())
            
            # Update session
            session.is_active = False
            session.ended_at = datetime.utcnow()
            
            await self.db.commit()
            
            # Track logout activity
            await self.track_activity(
                user_id=session.user_id,
                activity_type=ActivityType.LOGOUT,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                session_id=session_id,
                organization_id=session.organization_id,
                details={
                    "reason": reason,
                    "session_duration_seconds": duration_seconds
                },
                duration_ms=duration_seconds * 1000
            )
            
            # Remove from cache
            await self._remove_active_session(session.user_id, session_id)
            
            logger.info(
                f"Session ended",
                user_id=session.user_id,
                session_id=session_id,
                duration_seconds=duration_seconds
            )
            
            return {
                "session_ended": True,
                "session_id": session_id,
                "duration_seconds": duration_seconds,
                "ended_at": session.ended_at.isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to end session: {str(e)}")
            await self.db.rollback()
            return {"session_ended": False, "error": str(e)}
    
    async def get_user_activity(
        self,
        user_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        activity_types: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get user activity history
        """
        try:
            # Default to last 30 days
            if not start_date:
                start_date = datetime.utcnow() - timedelta(days=30)
            
            if not end_date:
                end_date = datetime.utcnow()
            
            # Get activities from audit logs
            query = select(AuditLog).where(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.created_at <= end_date,
                    AuditLog.event_type.like("activity_%")
                )
            )
            
            if activity_types:
                # Convert activity types to event types
                event_types = [f"activity_{at}" for at in activity_types]
                query = query.where(AuditLog.event_type.in_(event_types))
            
            query = query.order_by(desc(AuditLog.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            activities = result.scalars().all()
            
            return [self._format_activity(activity) for activity in activities]
        
        except Exception as e:
            logger.error(f"Failed to get user activity: {str(e)}")
            return []
    
    async def get_user_sessions(
        self,
        user_id: str,
        active_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get user session history
        """
        try:
            query = select(UserSession).where(UserSession.user_id == user_id)
            
            if active_only:
                query = query.where(UserSession.is_active == True)
            
            query = query.order_by(desc(UserSession.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            sessions = result.scalars().all()
            
            return [self._format_session(session) for session in sessions]
        
        except Exception as e:
            logger.error(f"Failed to get user sessions: {str(e)}")
            return []
    
    async def get_activity_summary(
        self,
        user_id: str,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """
        Get user activity summary and insights
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Get activity counts
            activity_query = select(
                AuditLog.event_type,
                func.count(AuditLog.id).label('count')
            ).where(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.event_type.like("activity_%")
                )
            ).group_by(AuditLog.event_type)
            
            result = await self.db.execute(activity_query)
            activity_counts = dict(result.fetchall())
            
            # Get session stats
            session_query = select(
                func.count(UserSession.id).label('total_sessions'),
                func.avg(
                    func.extract('epoch', UserSession.ended_at - UserSession.created_at)
                ).label('avg_duration_seconds'),
                func.count(
                    func.distinct(UserSession.ip_address)
                ).label('unique_locations')
            ).where(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.created_at >= start_date
                )
            )
            
            session_result = await self.db.execute(session_query)
            session_stats = session_result.first()
            
            # Get most active days
            daily_activity_query = select(
                func.date(AuditLog.created_at).label('date'),
                func.count(AuditLog.id).label('count')
            ).where(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.event_type.like("activity_%")
                )
            ).group_by(func.date(AuditLog.created_at)).order_by(desc('count'))
            
            daily_result = await self.db.execute(daily_activity_query)
            daily_activity = [
                {"date": row.date.isoformat(), "count": row.count}
                for row in daily_result.fetchall()[:7]  # Top 7 days
            ]
            
            # Calculate insights
            total_activities = sum(activity_counts.values())
            login_count = activity_counts.get("activity_login", 0)
            
            return {
                "period_days": days_back,
                "total_activities": total_activities,
                "total_sessions": session_stats.total_sessions or 0,
                "average_session_duration_minutes": int((session_stats.avg_duration_seconds or 0) / 60),
                "unique_locations": session_stats.unique_locations or 0,
                "login_count": login_count,
                "activity_breakdown": {
                    event_type.replace("activity_", ""): count
                    for event_type, count in activity_counts.items()
                },
                "most_active_days": daily_activity,
                "insights": self._generate_activity_insights(
                    total_activities, login_count, session_stats, days_back
                )
            }
        
        except Exception as e:
            logger.error(f"Failed to get activity summary: {str(e)}")
            return {}
    
    async def get_organization_activity(
        self,
        organization_id: str,
        days_back: int = 30,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Get organization-wide activity insights
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Get active users
            active_users_query = select(
                func.count(func.distinct(AuditLog.user_id))
            ).where(
                and_(
                    AuditLog.organization_id == organization_id,
                    AuditLog.created_at >= start_date
                )
            )
            
            active_users_result = await self.db.execute(active_users_query)
            active_users = active_users_result.scalar()
            
            # Get top activities
            top_activities_query = select(
                AuditLog.event_type,
                func.count(AuditLog.id).label('count')
            ).where(
                and_(
                    AuditLog.organization_id == organization_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.event_type.like("activity_%")
                )
            ).group_by(AuditLog.event_type).order_by(desc('count')).limit(10)
            
            top_activities_result = await self.db.execute(top_activities_query)
            top_activities = [
                {
                    "activity_type": row.event_type.replace("activity_", ""),
                    "count": row.count
                }
                for row in top_activities_result.fetchall()
            ]
            
            # Get most active users
            active_users_query = select(
                AuditLog.user_id,
                func.count(AuditLog.id).label('activity_count')
            ).where(
                and_(
                    AuditLog.organization_id == organization_id,
                    AuditLog.created_at >= start_date,
                    AuditLog.event_type.like("activity_%")
                )
            ).group_by(AuditLog.user_id).order_by(desc('activity_count')).limit(10)
            
            active_users_result = await self.db.execute(active_users_query)
            most_active_users = [
                {
                    "user_id": row.user_id,
                    "activity_count": row.activity_count
                }
                for row in active_users_result.fetchall()
            ]
            
            return {
                "organization_id": organization_id,
                "period_days": days_back,
                "active_users_count": active_users,
                "top_activities": top_activities,
                "most_active_users": most_active_users,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get organization activity: {str(e)}")
            return {}
    
    async def cleanup_inactive_sessions(self) -> Dict[str, Any]:
        """
        Clean up inactive sessions based on timeout
        """
        try:
            timeout_cutoff = datetime.utcnow() - timedelta(minutes=self.session_timeout_minutes)
            
            # Find inactive sessions
            inactive_query = select(UserSession).where(
                and_(
                    UserSession.is_active == True,
                    UserSession.last_activity_at < timeout_cutoff
                )
            )
            
            result = await self.db.execute(inactive_query)
            inactive_sessions = result.scalars().all()
            
            cleaned_count = 0
            for session in inactive_sessions:
                session.is_active = False
                session.ended_at = datetime.utcnow()
                cleaned_count += 1
                
                # Track timeout activity
                await self.track_activity(
                    user_id=session.user_id,
                    activity_type=ActivityType.LOGOUT,
                    session_id=session.session_id,
                    details={"reason": "timeout"}
                )
            
            await self.db.commit()
            
            logger.info(f"Cleaned up {cleaned_count} inactive sessions")
            
            return {
                "cleaned_sessions": cleaned_count,
                "timeout_minutes": self.session_timeout_minutes
            }
        
        except Exception as e:
            logger.error(f"Failed to cleanup inactive sessions: {str(e)}")
            await self.db.rollback()
            return {"error": str(e)}
    
    # ============= Helper Methods =============
    
    async def _update_session_activity(
        self,
        session_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Update session last activity time"""
        try:
            query = select(UserSession).where(
                and_(
                    UserSession.session_id == session_id,
                    UserSession.user_id == user_id,
                    UserSession.is_active == True
                )
            )
            
            result = await self.db.execute(query)
            session = result.scalar_one_or_none()
            
            if session:
                session.last_activity_at = datetime.utcnow()
                await self.db.commit()
        
        except Exception as e:
            logger.error(f"Failed to update session activity: {str(e)}")
    
    async def _cache_activity(
        self,
        user_id: str,
        activity_type: str,
        details: Dict[str, Any]
    ):
        """Cache recent activity for real-time access"""
        try:
            cache_key = f"recent_activity:{user_id}"
            recent_activities = await cache_service.get(cache_key) or []
            
            activity_data = {
                "activity_type": activity_type,
                "timestamp": datetime.utcnow().isoformat(),
                "details": details
            }
            
            recent_activities.insert(0, activity_data)
            recent_activities = recent_activities[:50]  # Keep last 50
            
            await cache_service.set(cache_key, recent_activities, expire=3600)
        
        except Exception as e:
            logger.error(f"Failed to cache activity: {str(e)}")
    
    async def _update_activity_metrics(
        self,
        user_id: str,
        organization_id: Optional[str],
        activity_type: str
    ):
        """Update activity metrics counters"""
        try:
            # Daily user metrics
            today = datetime.utcnow().date().isoformat()
            user_daily_key = f"activity_metrics:user:{user_id}:{today}"
            
            metrics = await cache_service.get(user_daily_key) or {}
            metrics[activity_type] = metrics.get(activity_type, 0) + 1
            metrics["total"] = metrics.get("total", 0) + 1
            
            await cache_service.set(user_daily_key, metrics, expire=86400 * 2)
            
            # Organization metrics
            if organization_id:
                org_daily_key = f"activity_metrics:org:{organization_id}:{today}"
                org_metrics = await cache_service.get(org_daily_key) or {}
                org_metrics[activity_type] = org_metrics.get(activity_type, 0) + 1
                org_metrics["total"] = org_metrics.get("total", 0) + 1
                
                await cache_service.set(org_daily_key, org_metrics, expire=86400 * 2)
        
        except Exception as e:
            logger.error(f"Failed to update activity metrics: {str(e)}")
    
    async def _cache_active_session(self, user_id: str, session_id: str):
        """Cache active session for quick lookup"""
        try:
            cache_key = f"active_sessions:{user_id}"
            sessions = await cache_service.get(cache_key) or []
            
            if session_id not in sessions:
                sessions.append(session_id)
                await cache_service.set(cache_key, sessions, expire=3600)
        
        except Exception as e:
            logger.error(f"Failed to cache active session: {str(e)}")
    
    async def _remove_active_session(self, user_id: str, session_id: str):
        """Remove session from active cache"""
        try:
            cache_key = f"active_sessions:{user_id}"
            sessions = await cache_service.get(cache_key) or []
            
            if session_id in sessions:
                sessions.remove(session_id)
                await cache_service.set(cache_key, sessions, expire=3600)
        
        except Exception as e:
            logger.error(f"Failed to remove active session: {str(e)}")
    
    async def _get_location_from_ip(self, ip_address: str) -> Optional[str]:
        """Get location from IP address (placeholder)"""
        # This would integrate with a geolocation service
        # For now, return a placeholder
        if ip_address and ip_address != "127.0.0.1":
            return "Unknown Location"
        return "Local"
    
    def _format_activity(self, activity: AuditLog) -> Dict[str, Any]:
        """Format activity for API response"""
        return {
            "id": activity.id,
            "activity_type": activity.event_type.replace("activity_", ""),
            "timestamp": activity.created_at.isoformat(),
            "ip_address": activity.ip_address,
            "user_agent": activity.user_agent,
            "details": activity.details or {}
        }
    
    def _format_session(self, session: UserSession) -> Dict[str, Any]:
        """Format session for API response"""
        duration_seconds = None
        if session.ended_at and session.created_at:
            duration_seconds = int((session.ended_at - session.created_at).total_seconds())
        elif session.is_active:
            duration_seconds = int((datetime.utcnow() - session.created_at).total_seconds())
        
        return {
            "session_id": session.session_id,
            "ip_address": session.ip_address,
            "location": session.location,
            "device_info": session.device_info,
            "is_active": session.is_active,
            "created_at": session.created_at.isoformat(),
            "last_activity_at": session.last_activity_at.isoformat(),
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "duration_seconds": duration_seconds
        }
    
    def _generate_activity_insights(
        self,
        total_activities: int,
        login_count: int,
        session_stats: Any,
        days_back: int
    ) -> List[str]:
        """Generate activity insights"""
        insights = []
        
        avg_sessions_per_day = (session_stats.total_sessions or 0) / days_back
        if avg_sessions_per_day > 1:
            insights.append(f"High engagement: {avg_sessions_per_day:.1f} sessions per day")
        
        avg_duration_minutes = int((session_stats.avg_duration_seconds or 0) / 60)
        if avg_duration_minutes > 30:
            insights.append(f"Long sessions: {avg_duration_minutes} minutes average")
        
        if (session_stats.unique_locations or 0) > 3:
            insights.append(f"Multi-location access from {session_stats.unique_locations} locations")
        
        if total_activities > days_back * 10:
            insights.append("Very active user with high feature usage")
        
        return insights


# Factory function
def get_activity_service(db: AsyncSession) -> ActivityService:
    return ActivityService(db)