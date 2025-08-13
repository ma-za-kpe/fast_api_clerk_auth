from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func
import structlog
import json
from enum import Enum

from app.db.models import AuditLog
from app.core.config import settings
from app.services.cache_service import cache_service

logger = structlog.get_logger()


class AuditEventType(Enum):
    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_ENDED = "session_ended"
    
    # Password Events
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    PASSWORD_CHANGE_FAILED = "password_change_failed"
    
    # Email Events
    EMAIL_CHANGE_INITIATED = "email_change_initiated"
    EMAIL_CHANGE_COMPLETED = "email_change_completed"
    EMAIL_VERIFICATION_SENT = "email_verification_sent"
    EMAIL_VERIFIED = "email_verified"
    
    # MFA Events
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"
    
    # Account Events
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_UPDATED = "account_updated"
    ACCOUNT_SUSPENDED = "account_suspended"
    ACCOUNT_UNSUSPENDED = "account_unsuspended"
    ACCOUNT_DELETED = "account_deleted"
    
    # Organization Events
    ORG_CREATED = "org_created"
    ORG_UPDATED = "org_updated"
    ORG_DELETED = "org_deleted"
    ORG_MEMBER_ADDED = "org_member_added"
    ORG_MEMBER_REMOVED = "org_member_removed"
    ORG_ROLE_CHANGED = "org_role_changed"
    
    # Permission Events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    ROLE_CREATED = "role_created"
    ROLE_UPDATED = "role_updated"
    ROLE_DELETED = "role_deleted"
    
    # API Events
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_REVOKED = "api_key_revoked"
    API_REQUEST = "api_request"
    
    # Security Events
    SECURITY_BREACH_DETECTED = "security_breach_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    
    # Data Events
    DATA_EXPORT_REQUESTED = "data_export_requested"
    DATA_EXPORT_COMPLETED = "data_export_completed"
    DATA_IMPORTED = "data_imported"
    DATA_DELETED = "data_deleted"
    
    # Admin Events
    ADMIN_ACTION = "admin_action"
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    BULK_OPERATION = "bulk_operation"


class AuditSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditService:
    """
    Comprehensive audit logging service
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.retention_days = getattr(settings, 'AUDIT_RETENTION_DAYS', 365)
        self.cache_ttl = 300  # 5 minutes
    
    async def log_event(
        self,
        event_type: Union[AuditEventType, str],
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.LOW,
        session_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        outcome: str = "success",
        error_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Log an audit event
        """
        try:
            # Convert enum to string if needed
            if isinstance(event_type, AuditEventType):
                event_type = event_type.value
            
            # Prepare details
            audit_details = {
                **(details or {}),
                "severity": severity.value,
                "session_id": session_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "action": action,
                "outcome": outcome,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if error_message:
                audit_details["error_message"] = error_message
            
            # Create audit log entry
            audit_log = AuditLog(
                event_type=event_type,
                user_id=user_id,
                organization_id=organization_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=audit_details,
                created_at=datetime.utcnow()
            )
            
            self.db.add(audit_log)
            await self.db.commit()
            
            # Cache recent events for quick access
            await self._cache_recent_event(audit_log)
            
            # Check for security patterns
            if severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
                await self._check_security_patterns(audit_log)
            
            logger.info(
                f"Audit event logged",
                event_type=event_type,
                user_id=user_id,
                severity=severity.value,
                outcome=outcome
            )
            
            return {
                "id": audit_log.id,
                "event_type": event_type,
                "logged_at": audit_log.created_at.isoformat(),
                "severity": severity.value
            }
        
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")
            await self.db.rollback()
            # Don't raise exception to avoid breaking main functionality
            return {"error": "Failed to log audit event"}
    
    async def get_user_events(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
        event_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None
    ) -> List[Dict[str, Any]]:
        """
        Get audit events for a specific user
        """
        try:
            query = select(AuditLog).where(AuditLog.user_id == user_id)
            
            # Apply filters
            if event_types:
                query = query.where(AuditLog.event_type.in_(event_types))
            
            if start_date:
                query = query.where(AuditLog.created_at >= start_date)
            
            if end_date:
                query = query.where(AuditLog.created_at <= end_date)
            
            if severity:
                # Filter by severity in details JSON
                query = query.where(
                    AuditLog.details.op('->>')('severity') == severity.value
                )
            
            # Order and paginate
            query = query.order_by(desc(AuditLog.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            return [self._format_audit_log(event) for event in events]
        
        except Exception as e:
            logger.error(f"Failed to get user events: {str(e)}")
            return []
    
    async def get_organization_events(
        self,
        organization_id: str,
        limit: int = 100,
        offset: int = 0,
        event_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get audit events for an organization
        """
        try:
            query = select(AuditLog).where(
                AuditLog.organization_id == organization_id
            )
            
            # Apply filters
            if event_types:
                query = query.where(AuditLog.event_type.in_(event_types))
            
            if start_date:
                query = query.where(AuditLog.created_at >= start_date)
            
            if end_date:
                query = query.where(AuditLog.created_at <= end_date)
            
            # Order and paginate
            query = query.order_by(desc(AuditLog.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            return [self._format_audit_log(event) for event in events]
        
        except Exception as e:
            logger.error(f"Failed to get organization events: {str(e)}")
            return []
    
    async def get_security_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[AuditSeverity] = None,
        hours_back: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Get security-related audit events
        """
        try:
            security_event_types = [
                AuditEventType.LOGIN_FAILED.value,
                AuditEventType.UNAUTHORIZED_ACCESS.value,
                AuditEventType.SECURITY_BREACH_DETECTED.value,
                AuditEventType.SUSPICIOUS_ACTIVITY.value,
                AuditEventType.RATE_LIMIT_EXCEEDED.value,
                AuditEventType.MFA_FAILED.value
            ]
            
            start_time = datetime.utcnow() - timedelta(hours=hours_back)
            
            query = select(AuditLog).where(
                and_(
                    AuditLog.event_type.in_(security_event_types),
                    AuditLog.created_at >= start_time
                )
            )
            
            if severity:
                query = query.where(
                    AuditLog.details.op('->>')('severity') == severity.value
                )
            
            query = query.order_by(desc(AuditLog.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            return [self._format_audit_log(event) for event in events]
        
        except Exception as e:
            logger.error(f"Failed to get security events: {str(e)}")
            return []
    
    async def get_event_statistics(
        self,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """
        Get audit event statistics
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Base query
            query = select(
                AuditLog.event_type,
                func.count(AuditLog.id).label('count')
            ).where(AuditLog.created_at >= start_date)
            
            if user_id:
                query = query.where(AuditLog.user_id == user_id)
            
            if organization_id:
                query = query.where(AuditLog.organization_id == organization_id)
            
            query = query.group_by(AuditLog.event_type)
            
            result = await self.db.execute(query)
            event_counts = dict(result.fetchall())
            
            # Get total count
            total_query = select(func.count(AuditLog.id)).where(
                AuditLog.created_at >= start_date
            )
            
            if user_id:
                total_query = total_query.where(AuditLog.user_id == user_id)
            
            if organization_id:
                total_query = total_query.where(AuditLog.organization_id == organization_id)
            
            total_result = await self.db.execute(total_query)
            total_events = total_result.scalar()
            
            # Get security events count
            security_types = [
                AuditEventType.LOGIN_FAILED.value,
                AuditEventType.UNAUTHORIZED_ACCESS.value,
                AuditEventType.SECURITY_BREACH_DETECTED.value,
                AuditEventType.SUSPICIOUS_ACTIVITY.value
            ]
            
            security_query = select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.created_at >= start_date,
                    AuditLog.event_type.in_(security_types)
                )
            )
            
            if user_id:
                security_query = security_query.where(AuditLog.user_id == user_id)
            
            if organization_id:
                security_query = security_query.where(AuditLog.organization_id == organization_id)
            
            security_result = await self.db.execute(security_query)
            security_events = security_result.scalar()
            
            return {
                "total_events": total_events,
                "security_events": security_events,
                "event_breakdown": event_counts,
                "period_days": days_back,
                "generated_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get event statistics: {str(e)}")
            return {}
    
    async def search_events(
        self,
        search_term: str,
        limit: int = 50,
        offset: int = 0,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search audit events by details content
        """
        try:
            # Base query with text search in details
            query = select(AuditLog).where(
                or_(
                    AuditLog.event_type.contains(search_term),
                    AuditLog.details.op('::text').contains(search_term)
                )
            )
            
            if user_id:
                query = query.where(AuditLog.user_id == user_id)
            
            if organization_id:
                query = query.where(AuditLog.organization_id == organization_id)
            
            query = query.order_by(desc(AuditLog.created_at))
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            return [self._format_audit_log(event) for event in events]
        
        except Exception as e:
            logger.error(f"Failed to search events: {str(e)}")
            return []
    
    async def export_events(
        self,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json"
    ) -> Dict[str, Any]:
        """
        Export audit events for compliance/backup
        """
        try:
            query = select(AuditLog)
            
            if user_id:
                query = query.where(AuditLog.user_id == user_id)
            
            if organization_id:
                query = query.where(AuditLog.organization_id == organization_id)
            
            if start_date:
                query = query.where(AuditLog.created_at >= start_date)
            
            if end_date:
                query = query.where(AuditLog.created_at <= end_date)
            
            query = query.order_by(desc(AuditLog.created_at))
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            formatted_events = [self._format_audit_log(event) for event in events]
            
            if format.lower() == "csv":
                # Convert to CSV format
                import csv
                from io import StringIO
                
                output = StringIO()
                if formatted_events:
                    writer = csv.DictWriter(output, fieldnames=formatted_events[0].keys())
                    writer.writeheader()
                    writer.writerows(formatted_events)
                
                return {
                    "format": "csv",
                    "data": output.getvalue(),
                    "count": len(formatted_events)
                }
            else:
                return {
                    "format": "json",
                    "data": formatted_events,
                    "count": len(formatted_events)
                }
        
        except Exception as e:
            logger.error(f"Failed to export events: {str(e)}")
            return {"error": "Failed to export events"}
    
    async def cleanup_old_events(self, days_to_keep: Optional[int] = None) -> Dict[str, Any]:
        """
        Clean up old audit events based on retention policy
        """
        try:
            retention_days = days_to_keep or self.retention_days
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            # Count events to be deleted
            count_query = select(func.count(AuditLog.id)).where(
                AuditLog.created_at < cutoff_date
            )
            
            count_result = await self.db.execute(count_query)
            events_to_delete = count_result.scalar()
            
            if events_to_delete > 0:
                # Delete old events
                from sqlalchemy import delete
                delete_query = delete(AuditLog).where(
                    AuditLog.created_at < cutoff_date
                )
                
                await self.db.execute(delete_query)
                await self.db.commit()
                
                logger.info(
                    f"Cleaned up old audit events",
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
    
    # ============= Helper Methods =============
    
    def _format_audit_log(self, audit_log: AuditLog) -> Dict[str, Any]:
        """Format audit log for API response"""
        return {
            "id": audit_log.id,
            "event_type": audit_log.event_type,
            "user_id": audit_log.user_id,
            "organization_id": audit_log.organization_id,
            "ip_address": audit_log.ip_address,
            "user_agent": audit_log.user_agent,
            "details": audit_log.details,
            "created_at": audit_log.created_at.isoformat()
        }
    
    async def _cache_recent_event(self, audit_log: AuditLog):
        """Cache recent events for quick access"""
        try:
            if audit_log.user_id:
                cache_key = f"recent_events:{audit_log.user_id}"
                recent_events = await cache_service.get(cache_key) or []
                
                # Add new event
                event_data = self._format_audit_log(audit_log)
                recent_events.insert(0, event_data)
                
                # Keep only last 20 events
                recent_events = recent_events[:20]
                
                await cache_service.set(cache_key, recent_events, expire=self.cache_ttl)
        
        except Exception as e:
            logger.error(f"Failed to cache recent event: {str(e)}")
    
    async def _check_security_patterns(self, audit_log: AuditLog):
        """Check for suspicious security patterns"""
        try:
            # Check for multiple failed login attempts
            if audit_log.event_type == AuditEventType.LOGIN_FAILED.value:
                await self._check_failed_login_pattern(audit_log)
            
            # Check for rapid password changes
            if audit_log.event_type == AuditEventType.PASSWORD_CHANGED.value:
                await self._check_rapid_password_changes(audit_log)
            
            # Check for unusual access patterns
            if audit_log.ip_address:
                await self._check_unusual_ip_access(audit_log)
        
        except Exception as e:
            logger.error(f"Failed to check security patterns: {str(e)}")
    
    async def _check_failed_login_pattern(self, audit_log: AuditLog):
        """Check for suspicious failed login patterns"""
        try:
            if not audit_log.user_id:
                return
            
            # Count recent failed logins
            start_time = datetime.utcnow() - timedelta(hours=1)
            
            query = select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.user_id == audit_log.user_id,
                    AuditLog.event_type == AuditEventType.LOGIN_FAILED.value,
                    AuditLog.created_at >= start_time
                )
            )
            
            result = await self.db.execute(query)
            failed_count = result.scalar()
            
            # Alert if too many failures
            if failed_count >= 5:
                await self.log_event(
                    event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                    user_id=audit_log.user_id,
                    ip_address=audit_log.ip_address,
                    severity=AuditSeverity.HIGH,
                    details={
                        "pattern": "multiple_failed_logins",
                        "failed_attempts": failed_count,
                        "time_window_hours": 1
                    }
                )
        
        except Exception as e:
            logger.error(f"Failed to check failed login pattern: {str(e)}")
    
    async def _check_rapid_password_changes(self, audit_log: AuditLog):
        """Check for rapid password changes"""
        try:
            if not audit_log.user_id:
                return
            
            # Count password changes in last 24 hours
            start_time = datetime.utcnow() - timedelta(hours=24)
            
            query = select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.user_id == audit_log.user_id,
                    AuditLog.event_type == AuditEventType.PASSWORD_CHANGED.value,
                    AuditLog.created_at >= start_time
                )
            )
            
            result = await self.db.execute(query)
            change_count = result.scalar()
            
            if change_count >= 3:
                await self.log_event(
                    event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                    user_id=audit_log.user_id,
                    severity=AuditSeverity.MEDIUM,
                    details={
                        "pattern": "rapid_password_changes",
                        "changes_count": change_count,
                        "time_window_hours": 24
                    }
                )
        
        except Exception as e:
            logger.error(f"Failed to check rapid password changes: {str(e)}")
    
    async def _check_unusual_ip_access(self, audit_log: AuditLog):
        """Check for access from unusual IP addresses"""
        try:
            if not audit_log.user_id or not audit_log.ip_address:
                return
            
            # Get user's recent IP addresses
            start_time = datetime.utcnow() - timedelta(days=30)
            
            query = select(AuditLog.ip_address).where(
                and_(
                    AuditLog.user_id == audit_log.user_id,
                    AuditLog.ip_address.isnot(None),
                    AuditLog.created_at >= start_time
                )
            ).distinct()
            
            result = await self.db.execute(query)
            known_ips = [row[0] for row in result.fetchall()]
            
            # If this is a new IP and user has established patterns
            if len(known_ips) >= 3 and audit_log.ip_address not in known_ips:
                await self.log_event(
                    event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                    user_id=audit_log.user_id,
                    ip_address=audit_log.ip_address,
                    severity=AuditSeverity.MEDIUM,
                    details={
                        "pattern": "unusual_ip_access",
                        "new_ip": audit_log.ip_address,
                        "known_ips_count": len(known_ips)
                    }
                )
        
        except Exception as e:
            logger.error(f"Failed to check unusual IP access: {str(e)}")


# Factory function for dependency injection
def get_audit_service(db: AsyncSession) -> AuditService:
    return AuditService(db)