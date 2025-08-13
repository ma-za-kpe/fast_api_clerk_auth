from typing import Dict, Any, Optional, List, Union, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func, distinct, text
import structlog
from dataclasses import dataclass
from enum import Enum
import json

from app.db.models import AuditLog, UserSession
from app.services.cache_service import cache_service
from app.core.config import settings
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class MetricType(Enum):
    USER_GROWTH = "user_growth"
    ACTIVITY_VOLUME = "activity_volume"
    SESSION_METRICS = "session_metrics"
    AUTHENTICATION_METRICS = "auth_metrics"
    FEATURE_USAGE = "feature_usage"
    PERFORMANCE_METRICS = "performance_metrics"
    SECURITY_METRICS = "security_metrics"
    ORGANIZATION_METRICS = "org_metrics"


@dataclass
class MetricDefinition:
    name: str
    type: MetricType
    query: str
    description: str
    unit: str
    aggregation: str = "count"  # count, sum, avg, max, min
    refresh_interval: int = 3600  # seconds


class AnalyticsService:
    """
    Comprehensive analytics and monitoring service
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.clerk_client = None
        self.metric_definitions = self._define_metrics()
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    def _define_metrics(self) -> Dict[str, MetricDefinition]:
        """Define all available metrics"""
        return {
            "total_users": MetricDefinition(
                name="Total Users",
                type=MetricType.USER_GROWTH,
                query="SELECT COUNT(*) FROM users",
                description="Total number of registered users",
                unit="users"
            ),
            "daily_active_users": MetricDefinition(
                name="Daily Active Users",
                type=MetricType.USER_GROWTH,
                query="SELECT COUNT(DISTINCT user_id) FROM user_sessions WHERE DATE(created_at) = CURRENT_DATE",
                description="Unique users who had activity today",
                unit="users"
            ),
            "monthly_active_users": MetricDefinition(
                name="Monthly Active Users",
                type=MetricType.USER_GROWTH,
                query="SELECT COUNT(DISTINCT user_id) FROM user_sessions WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'",
                description="Unique users who had activity in the last 30 days",
                unit="users"
            ),
            "total_sessions": MetricDefinition(
                name="Total Sessions",
                type=MetricType.SESSION_METRICS,
                query="SELECT COUNT(*) FROM user_sessions",
                description="Total number of user sessions",
                unit="sessions"
            ),
            "avg_session_duration": MetricDefinition(
                name="Average Session Duration",
                type=MetricType.SESSION_METRICS,
                query="SELECT AVG(EXTRACT(EPOCH FROM (ended_at - created_at))) FROM user_sessions WHERE ended_at IS NOT NULL",
                description="Average session duration in seconds",
                unit="seconds",
                aggregation="avg"
            ),
            "failed_logins_24h": MetricDefinition(
                name="Failed Logins (24h)",
                type=MetricType.SECURITY_METRICS,
                query="SELECT COUNT(*) FROM audit_logs WHERE event_type LIKE '%login%' AND outcome = 'failure' AND created_at >= NOW() - INTERVAL '24 hours'",
                description="Failed login attempts in the last 24 hours",
                unit="attempts"
            ),
            "api_calls_today": MetricDefinition(
                name="API Calls Today",
                type=MetricType.ACTIVITY_VOLUME,
                query="SELECT COUNT(*) FROM audit_logs WHERE event_type LIKE 'activity_%' AND DATE(created_at) = CURRENT_DATE",
                description="Total API calls made today",
                unit="calls"
            ),
            "top_features_used": MetricDefinition(
                name="Top Features Used",
                type=MetricType.FEATURE_USAGE,
                query="SELECT event_type, COUNT(*) FROM audit_logs WHERE event_type LIKE 'activity_%' AND created_at >= NOW() - INTERVAL '7 days' GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10",
                description="Most used features in the last 7 days",
                unit="usage_count"
            )
        }
    
    # ============= Core Analytics Methods =============
    
    async def get_dashboard_metrics(
        self,
        time_range: str = "24h",
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get key metrics for analytics dashboard
        """
        try:
            # Calculate time boundaries
            end_time = datetime.utcnow()
            
            if time_range == "24h":
                start_time = end_time - timedelta(hours=24)
            elif time_range == "7d":
                start_time = end_time - timedelta(days=7)
            elif time_range == "30d":
                start_time = end_time - timedelta(days=30)
            elif time_range == "90d":
                start_time = end_time - timedelta(days=90)
            else:
                start_time = end_time - timedelta(hours=24)
            
            # Get cached metrics first
            cache_key = f"dashboard_metrics:{time_range}:{organization_id or 'global'}"
            cached_metrics = await cache_service.get(cache_key)
            
            if cached_metrics:
                return cached_metrics
            
            # Calculate fresh metrics
            metrics = {}
            
            # User metrics
            user_metrics = await self._calculate_user_metrics(start_time, end_time, organization_id)
            metrics.update(user_metrics)
            
            # Session metrics
            session_metrics = await self._calculate_session_metrics(start_time, end_time, organization_id)
            metrics.update(session_metrics)
            
            # Activity metrics
            activity_metrics = await self._calculate_activity_metrics(start_time, end_time, organization_id)
            metrics.update(activity_metrics)
            
            # Security metrics
            security_metrics = await self._calculate_security_metrics(start_time, end_time, organization_id)
            metrics.update(security_metrics)
            
            # Add metadata
            metrics.update({
                "time_range": time_range,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "organization_id": organization_id,
                "generated_at": datetime.utcnow().isoformat(),
                "cache_ttl": 300  # 5 minutes
            })
            
            # Cache for 5 minutes
            await cache_service.set(cache_key, metrics, expire=300)
            
            return metrics
        
        except Exception as e:
            logger.error(f"Failed to get dashboard metrics: {str(e)}")
            return {}
    
    async def get_user_growth_analytics(
        self,
        days_back: int = 30,
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get detailed user growth analytics
        """
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            # Get daily new user counts
            daily_query = text("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as new_users
                FROM audit_logs 
                WHERE event_type = 'user_created' 
                AND created_at >= :start_date 
                AND created_at <= :end_date
                """ + (f"AND organization_id = :org_id" if organization_id else "") + """
                GROUP BY DATE(created_at)
                ORDER BY date
            """)
            
            params = {"start_date": start_date, "end_date": end_date}
            if organization_id:
                params["org_id"] = organization_id
            
            result = await self.db.execute(daily_query, params)
            daily_growth = [
                {"date": row.date.isoformat(), "new_users": row.new_users}
                for row in result.fetchall()
            ]
            
            # Calculate growth rate
            if len(daily_growth) >= 2:
                recent_avg = sum(day["new_users"] for day in daily_growth[-7:]) / 7
                previous_avg = sum(day["new_users"] for day in daily_growth[-14:-7]) / 7
                growth_rate = ((recent_avg - previous_avg) / previous_avg * 100) if previous_avg > 0 else 0
            else:
                growth_rate = 0
            
            # Get total users
            total_users_query = select(func.count(distinct(AuditLog.user_id))).where(
                AuditLog.event_type == "user_created"
            )
            if organization_id:
                total_users_query = total_users_query.where(AuditLog.organization_id == organization_id)
            
            total_result = await self.db.execute(total_users_query)
            total_users = total_result.scalar() or 0
            
            # Get active user metrics
            active_users_query = select(func.count(distinct(UserSession.user_id))).where(
                and_(
                    UserSession.created_at >= start_date,
                    UserSession.created_at <= end_date
                )
            )
            if organization_id:
                active_users_query = active_users_query.where(UserSession.organization_id == organization_id)
            
            active_result = await self.db.execute(active_users_query)
            active_users = active_result.scalar() or 0
            
            return {
                "period_days": days_back,
                "total_users": total_users,
                "active_users_period": active_users,
                "growth_rate_7d": round(growth_rate, 2),
                "daily_growth": daily_growth,
                "retention_rate": round((active_users / total_users * 100) if total_users > 0 else 0, 2),
                "organization_id": organization_id,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get user growth analytics: {str(e)}")
            return {}
    
    async def get_feature_usage_analytics(
        self,
        days_back: int = 30,
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get feature usage analytics
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Get feature usage counts
            usage_query = select(
                AuditLog.event_type,
                func.count(AuditLog.id).label('usage_count'),
                func.count(distinct(AuditLog.user_id)).label('unique_users')
            ).where(
                and_(
                    AuditLog.event_type.like('activity_%'),
                    AuditLog.created_at >= start_date
                )
            )
            
            if organization_id:
                usage_query = usage_query.where(AuditLog.organization_id == organization_id)
            
            usage_query = usage_query.group_by(AuditLog.event_type).order_by(desc('usage_count'))
            
            result = await self.db.execute(usage_query)
            feature_usage = [
                {
                    "feature": row.event_type.replace('activity_', ''),
                    "usage_count": row.usage_count,
                    "unique_users": row.unique_users
                }
                for row in result.fetchall()
            ]
            
            # Get daily feature usage trend
            daily_usage_query = select(
                func.date(AuditLog.created_at).label('date'),
                func.count(AuditLog.id).label('total_usage')
            ).where(
                and_(
                    AuditLog.event_type.like('activity_%'),
                    AuditLog.created_at >= start_date
                )
            )
            
            if organization_id:
                daily_usage_query = daily_usage_query.where(AuditLog.organization_id == organization_id)
            
            daily_usage_query = daily_usage_query.group_by(func.date(AuditLog.created_at)).order_by('date')
            
            daily_result = await self.db.execute(daily_usage_query)
            daily_usage = [
                {"date": row.date.isoformat(), "usage_count": row.total_usage}
                for row in daily_result.fetchall()
            ]
            
            # Calculate insights
            total_usage = sum(item["usage_count"] for item in feature_usage)
            most_popular_feature = feature_usage[0] if feature_usage else None
            
            return {
                "period_days": days_back,
                "total_feature_usage": total_usage,
                "unique_features_used": len(feature_usage),
                "most_popular_feature": most_popular_feature,
                "feature_breakdown": feature_usage,
                "daily_usage_trend": daily_usage,
                "organization_id": organization_id,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get feature usage analytics: {str(e)}")
            return {}
    
    async def get_session_analytics(
        self,
        days_back: int = 30,
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get session analytics and insights
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Session metrics query
            session_query = select(
                func.count(UserSession.id).label('total_sessions'),
                func.count(distinct(UserSession.user_id)).label('unique_users'),
                func.avg(
                    func.extract('epoch', UserSession.ended_at - UserSession.created_at)
                ).label('avg_duration_seconds'),
                func.max(
                    func.extract('epoch', UserSession.ended_at - UserSession.created_at)
                ).label('max_duration_seconds'),
                func.count(UserSession.id).filter(UserSession.is_active == True).label('active_sessions')
            ).where(UserSession.created_at >= start_date)
            
            if organization_id:
                session_query = session_query.where(UserSession.organization_id == organization_id)
            
            session_result = await self.db.execute(session_query)
            session_stats = session_result.first()
            
            # Daily session counts
            daily_sessions_query = select(
                func.date(UserSession.created_at).label('date'),
                func.count(UserSession.id).label('session_count'),
                func.count(distinct(UserSession.user_id)).label('unique_users'),
                func.avg(
                    func.extract('epoch', UserSession.ended_at - UserSession.created_at)
                ).label('avg_duration')
            ).where(UserSession.created_at >= start_date)
            
            if organization_id:
                daily_sessions_query = daily_sessions_query.where(UserSession.organization_id == organization_id)
            
            daily_sessions_query = daily_sessions_query.group_by(
                func.date(UserSession.created_at)
            ).order_by('date')
            
            daily_result = await self.db.execute(daily_sessions_query)
            daily_sessions = [
                {
                    "date": row.date.isoformat(),
                    "session_count": row.session_count,
                    "unique_users": row.unique_users,
                    "avg_duration_minutes": round((row.avg_duration or 0) / 60, 1)
                }
                for row in daily_result.fetchall()
            ]
            
            # Device/location breakdown
            device_query = select(
                UserSession.device_info,
                UserSession.location,
                func.count(UserSession.id).label('session_count')
            ).where(UserSession.created_at >= start_date)
            
            if organization_id:
                device_query = device_query.where(UserSession.organization_id == organization_id)
            
            device_query = device_query.group_by(UserSession.device_info, UserSession.location)
            
            device_result = await self.db.execute(device_query)
            device_breakdown = {}
            location_breakdown = {}
            
            for row in device_result.fetchall():
                if row.device_info:
                    device_type = "unknown"
                    # Parse device info if it's JSON
                    try:
                        if isinstance(row.device_info, str):
                            device_data = json.loads(row.device_info)
                            device_type = device_data.get("type", "unknown")
                    except:
                        pass
                    device_breakdown[device_type] = device_breakdown.get(device_type, 0) + row.session_count
                
                if row.location:
                    location_breakdown[row.location] = location_breakdown.get(row.location, 0) + row.session_count
            
            return {
                "period_days": days_back,
                "total_sessions": session_stats.total_sessions or 0,
                "unique_users": session_stats.unique_users or 0,
                "active_sessions": session_stats.active_sessions or 0,
                "avg_duration_minutes": round((session_stats.avg_duration_seconds or 0) / 60, 1),
                "max_duration_minutes": round((session_stats.max_duration_seconds or 0) / 60, 1),
                "daily_sessions": daily_sessions,
                "device_breakdown": device_breakdown,
                "location_breakdown": location_breakdown,
                "organization_id": organization_id,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get session analytics: {str(e)}")
            return {}
    
    async def get_security_analytics(
        self,
        days_back: int = 30,
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get security-related analytics
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Security events query
            security_query = select(
                AuditLog.event_type,
                AuditLog.outcome,
                func.count(AuditLog.id).label('event_count')
            ).where(
                and_(
                    AuditLog.created_at >= start_date,
                    or_(
                        AuditLog.event_type.like('%login%'),
                        AuditLog.event_type.like('%auth%'),
                        AuditLog.event_type.like('%security%'),
                        AuditLog.event_type == 'password_reset',
                        AuditLog.event_type == 'mfa_enabled',
                        AuditLog.event_type == 'mfa_disabled'
                    )
                )
            )
            
            if organization_id:
                security_query = security_query.where(AuditLog.organization_id == organization_id)
            
            security_query = security_query.group_by(AuditLog.event_type, AuditLog.outcome)
            
            security_result = await self.db.execute(security_query)
            security_events = {}
            
            for row in security_result.fetchall():
                event_type = row.event_type
                if event_type not in security_events:
                    security_events[event_type] = {"success": 0, "failure": 0}
                security_events[event_type][row.outcome or "success"] = row.event_count
            
            # Failed login attempts by IP
            failed_logins_query = select(
                AuditLog.ip_address,
                func.count(AuditLog.id).label('failed_attempts')
            ).where(
                and_(
                    AuditLog.event_type.like('%login%'),
                    AuditLog.outcome == 'failure',
                    AuditLog.created_at >= start_date
                )
            )
            
            if organization_id:
                failed_logins_query = failed_logins_query.where(AuditLog.organization_id == organization_id)
            
            failed_logins_query = failed_logins_query.group_by(AuditLog.ip_address).order_by(desc('failed_attempts'))
            
            failed_result = await self.db.execute(failed_logins_query)
            suspicious_ips = [
                {"ip_address": row.ip_address, "failed_attempts": row.failed_attempts}
                for row in failed_result.fetchall()[:10]  # Top 10
            ]
            
            # Calculate security metrics
            total_login_attempts = sum(
                events.get("success", 0) + events.get("failure", 0)
                for event, events in security_events.items()
                if "login" in event
            )
            
            failed_login_attempts = sum(
                events.get("failure", 0)
                for event, events in security_events.items()
                if "login" in event
            )
            
            login_success_rate = (
                ((total_login_attempts - failed_login_attempts) / total_login_attempts * 100)
                if total_login_attempts > 0 else 100
            )
            
            return {
                "period_days": days_back,
                "login_success_rate": round(login_success_rate, 2),
                "total_login_attempts": total_login_attempts,
                "failed_login_attempts": failed_login_attempts,
                "security_events": security_events,
                "suspicious_ips": suspicious_ips,
                "mfa_adoption": security_events.get("mfa_enabled", {}).get("success", 0),
                "password_resets": security_events.get("password_reset", {}).get("success", 0),
                "organization_id": organization_id,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get security analytics: {str(e)}")
            return {}
    
    async def get_performance_metrics(
        self,
        days_back: int = 7,
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get performance metrics and insights
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Get performance data from audit logs (assuming duration is stored in details)
            perf_query = select(
                AuditLog.event_type,
                AuditLog.details,
                AuditLog.created_at
            ).where(
                and_(
                    AuditLog.created_at >= start_date,
                    AuditLog.details.isnot(None)
                )
            )
            
            if organization_id:
                perf_query = perf_query.where(AuditLog.organization_id == organization_id)
            
            perf_result = await self.db.execute(perf_query)
            
            endpoint_metrics = {}
            total_requests = 0
            
            for row in perf_result.fetchall():
                try:
                    details = row.details if isinstance(row.details, dict) else json.loads(row.details or "{}")
                    duration_ms = details.get("duration_ms")
                    
                    if duration_ms:
                        event_type = row.event_type
                        if event_type not in endpoint_metrics:
                            endpoint_metrics[event_type] = {
                                "request_count": 0,
                                "total_duration": 0,
                                "max_duration": 0,
                                "min_duration": float('inf')
                            }
                        
                        metrics = endpoint_metrics[event_type]
                        metrics["request_count"] += 1
                        metrics["total_duration"] += duration_ms
                        metrics["max_duration"] = max(metrics["max_duration"], duration_ms)
                        metrics["min_duration"] = min(metrics["min_duration"], duration_ms)
                        total_requests += 1
                
                except Exception:
                    continue
            
            # Calculate averages
            for event_type, metrics in endpoint_metrics.items():
                if metrics["request_count"] > 0:
                    metrics["avg_duration"] = metrics["total_duration"] / metrics["request_count"]
                    if metrics["min_duration"] == float('inf'):
                        metrics["min_duration"] = 0
            
            # Sort by request count
            sorted_endpoints = sorted(
                endpoint_metrics.items(),
                key=lambda x: x[1]["request_count"],
                reverse=True
            )[:10]
            
            return {
                "period_days": days_back,
                "total_requests": total_requests,
                "endpoints_analyzed": len(endpoint_metrics),
                "top_endpoints": [
                    {
                        "endpoint": endpoint,
                        "request_count": metrics["request_count"],
                        "avg_duration_ms": round(metrics.get("avg_duration", 0), 2),
                        "max_duration_ms": metrics["max_duration"],
                        "min_duration_ms": metrics["min_duration"]
                    }
                    for endpoint, metrics in sorted_endpoints
                ],
                "organization_id": organization_id,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {str(e)}")
            return {}
    
    # ============= Helper Methods =============
    
    async def _calculate_user_metrics(
        self,
        start_time: datetime,
        end_time: datetime,
        organization_id: Optional[str]
    ) -> Dict[str, Any]:
        """Calculate user-related metrics"""
        try:
            # New users in period
            new_users_query = select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.event_type == 'user_created',
                    AuditLog.created_at >= start_time,
                    AuditLog.created_at <= end_time
                )
            )
            if organization_id:
                new_users_query = new_users_query.where(AuditLog.organization_id == organization_id)
            
            new_users_result = await self.db.execute(new_users_query)
            new_users = new_users_result.scalar() or 0
            
            # Active users in period
            active_users_query = select(func.count(distinct(UserSession.user_id))).where(
                and_(
                    UserSession.created_at >= start_time,
                    UserSession.created_at <= end_time
                )
            )
            if organization_id:
                active_users_query = active_users_query.where(UserSession.organization_id == organization_id)
            
            active_users_result = await self.db.execute(active_users_query)
            active_users = active_users_result.scalar() or 0
            
            return {
                "new_users": new_users,
                "active_users": active_users
            }
        
        except Exception as e:
            logger.error(f"Failed to calculate user metrics: {str(e)}")
            return {"new_users": 0, "active_users": 0}
    
    async def _calculate_session_metrics(
        self,
        start_time: datetime,
        end_time: datetime,
        organization_id: Optional[str]
    ) -> Dict[str, Any]:
        """Calculate session-related metrics"""
        try:
            session_query = select(
                func.count(UserSession.id).label('total_sessions'),
                func.avg(
                    func.extract('epoch', UserSession.ended_at - UserSession.created_at)
                ).label('avg_duration_seconds')
            ).where(
                and_(
                    UserSession.created_at >= start_time,
                    UserSession.created_at <= end_time
                )
            )
            
            if organization_id:
                session_query = session_query.where(UserSession.organization_id == organization_id)
            
            session_result = await self.db.execute(session_query)
            session_stats = session_result.first()
            
            return {
                "total_sessions": session_stats.total_sessions or 0,
                "avg_session_duration_minutes": round((session_stats.avg_duration_seconds or 0) / 60, 1)
            }
        
        except Exception as e:
            logger.error(f"Failed to calculate session metrics: {str(e)}")
            return {"total_sessions": 0, "avg_session_duration_minutes": 0}
    
    async def _calculate_activity_metrics(
        self,
        start_time: datetime,
        end_time: datetime,
        organization_id: Optional[str]
    ) -> Dict[str, Any]:
        """Calculate activity-related metrics"""
        try:
            activity_query = select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.event_type.like('activity_%'),
                    AuditLog.created_at >= start_time,
                    AuditLog.created_at <= end_time
                )
            )
            
            if organization_id:
                activity_query = activity_query.where(AuditLog.organization_id == organization_id)
            
            activity_result = await self.db.execute(activity_query)
            total_activities = activity_result.scalar() or 0
            
            return {"total_activities": total_activities}
        
        except Exception as e:
            logger.error(f"Failed to calculate activity metrics: {str(e)}")
            return {"total_activities": 0}
    
    async def _calculate_security_metrics(
        self,
        start_time: datetime,
        end_time: datetime,
        organization_id: Optional[str]
    ) -> Dict[str, Any]:
        """Calculate security-related metrics"""
        try:
            # Failed login attempts
            failed_logins_query = select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.event_type.like('%login%'),
                    AuditLog.outcome == 'failure',
                    AuditLog.created_at >= start_time,
                    AuditLog.created_at <= end_time
                )
            )
            
            if organization_id:
                failed_logins_query = failed_logins_query.where(AuditLog.organization_id == organization_id)
            
            failed_result = await self.db.execute(failed_logins_query)
            failed_logins = failed_result.scalar() or 0
            
            return {"failed_logins": failed_logins}
        
        except Exception as e:
            logger.error(f"Failed to calculate security metrics: {str(e)}")
            return {"failed_logins": 0}
    
    async def export_analytics_data(
        self,
        metric_types: List[str],
        start_date: datetime,
        end_date: datetime,
        format: str = "json",
        organization_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export analytics data in various formats
        """
        try:
            export_data = {
                "export_info": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "organization_id": organization_id,
                    "format": format
                },
                "data": {}
            }
            
            # Collect requested metrics
            for metric_type in metric_types:
                if metric_type == "user_growth":
                    export_data["data"]["user_growth"] = await self.get_user_growth_analytics(
                        days_back=(end_date - start_date).days,
                        organization_id=organization_id
                    )
                elif metric_type == "feature_usage":
                    export_data["data"]["feature_usage"] = await self.get_feature_usage_analytics(
                        days_back=(end_date - start_date).days,
                        organization_id=organization_id
                    )
                elif metric_type == "sessions":
                    export_data["data"]["sessions"] = await self.get_session_analytics(
                        days_back=(end_date - start_date).days,
                        organization_id=organization_id
                    )
                elif metric_type == "security":
                    export_data["data"]["security"] = await self.get_security_analytics(
                        days_back=(end_date - start_date).days,
                        organization_id=organization_id
                    )
            
            return export_data
        
        except Exception as e:
            logger.error(f"Failed to export analytics data: {str(e)}")
            return {}


# Factory function
def get_analytics_service(db: AsyncSession) -> AnalyticsService:
    return AnalyticsService(db)