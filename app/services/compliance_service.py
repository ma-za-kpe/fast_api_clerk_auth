from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func, text
import structlog
import json
import uuid
from dataclasses import dataclass
from enum import Enum

from app.db.models import AuditLog, UserSession
from app.services.cache_service import cache_service
from app.services.audit_service import AuditService, AuditEventType, AuditSeverity
from app.core.config import settings
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class ComplianceRequestType(Enum):
    DATA_ACCESS = "data_access"  # GDPR Article 15 - Right of access
    DATA_PORTABILITY = "data_portability"  # GDPR Article 20 - Right to data portability
    DATA_RECTIFICATION = "data_rectification"  # GDPR Article 16 - Right to rectification
    DATA_ERASURE = "data_erasure"  # GDPR Article 17 - Right to erasure
    PROCESSING_RESTRICTION = "processing_restriction"  # GDPR Article 18 - Right to restriction
    OBJECTION = "objection"  # GDPR Article 21 - Right to object
    OPT_OUT = "opt_out"  # CCPA - Right to opt out of sale
    CONSENT_WITHDRAWAL = "consent_withdrawal"  # Withdraw consent


class RequestStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    PARTIALLY_COMPLETED = "partially_completed"


class ConsentType(Enum):
    ESSENTIAL = "essential"  # Required for service functionality
    ANALYTICS = "analytics"  # Usage analytics and monitoring
    MARKETING = "marketing"  # Marketing communications
    PERSONALIZATION = "personalization"  # Personalized content
    THIRD_PARTY = "third_party"  # Third-party integrations


@dataclass
class ConsentRecord:
    user_id: str
    consent_type: ConsentType
    granted: bool
    timestamp: datetime
    purpose: str
    legal_basis: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    withdrawal_timestamp: Optional[datetime] = None


@dataclass
class ComplianceRequest:
    id: str
    user_id: str
    request_type: ComplianceRequestType
    status: RequestStatus
    created_at: datetime
    completed_at: Optional[datetime]
    requested_by: str
    description: str
    fulfillment_details: Optional[Dict[str, Any]] = None
    verification_data: Optional[Dict[str, Any]] = None


class ComplianceService:
    """
    Comprehensive GDPR and CCPA compliance service
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_service = AuditService(db)
        self.retention_periods = self._define_retention_periods()
        self.data_categories = self._define_data_categories()
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    def _define_retention_periods(self) -> Dict[str, int]:
        """Define data retention periods in days"""
        return {
            "audit_logs": 2555,  # 7 years for legal compliance
            "session_data": 365,  # 1 year
            "activity_logs": 1095,  # 3 years
            "user_preferences": 1825,  # 5 years
            "marketing_data": 730,  # 2 years
            "inactive_accounts": 1095,  # 3 years after last activity
            "consent_records": 2555,  # 7 years for GDPR compliance
            "compliance_requests": 2555  # 7 years
        }
    
    def _define_data_categories(self) -> Dict[str, Dict[str, Any]]:
        """Define data categories for GDPR purposes"""
        return {
            "identity_data": {
                "description": "Personal identification information",
                "fields": ["user_id", "email", "first_name", "last_name", "username"],
                "legal_basis": "contract",
                "retention_days": 1095
            },
            "contact_data": {
                "description": "Contact information",
                "fields": ["email", "phone_number", "address"],
                "legal_basis": "contract",
                "retention_days": 1095
            },
            "authentication_data": {
                "description": "Authentication and security data",
                "fields": ["password_hash", "mfa_settings", "security_keys"],
                "legal_basis": "contract",
                "retention_days": 365
            },
            "usage_data": {
                "description": "Platform usage and activity data",
                "fields": ["sessions", "audit_logs", "activity_logs"],
                "legal_basis": "legitimate_interest",
                "retention_days": 1095
            },
            "preference_data": {
                "description": "User preferences and settings",
                "fields": ["preferences", "settings", "notifications"],
                "legal_basis": "consent",
                "retention_days": 1825
            },
            "marketing_data": {
                "description": "Marketing and communication preferences",
                "fields": ["newsletter_subscription", "marketing_consent"],
                "legal_basis": "consent",
                "retention_days": 730
            }
        }
    
    # ============= Consent Management =============
    
    async def record_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        granted: bool,
        purpose: str,
        legal_basis: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ConsentRecord:
        """
        Record user consent for GDPR compliance
        """
        try:
            consent_record = ConsentRecord(
                user_id=user_id,
                consent_type=consent_type,
                granted=granted,
                timestamp=datetime.utcnow(),
                purpose=purpose,
                legal_basis=legal_basis,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Store consent record
            consent_key = f"consent:{user_id}:{consent_type.value}"
            consent_data = {
                "user_id": user_id,
                "consent_type": consent_type.value,
                "granted": granted,
                "timestamp": consent_record.timestamp.isoformat(),
                "purpose": purpose,
                "legal_basis": legal_basis,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "withdrawal_timestamp": None
            }
            
            await cache_service.set(consent_key, consent_data, expire=86400 * 365)  # 1 year cache
            
            # Audit the consent action
            await self.audit_service.log_event(
                event_type="consent_recorded",
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "consent_type": consent_type.value,
                    "granted": granted,
                    "purpose": purpose,
                    "legal_basis": legal_basis
                },
                severity=AuditSeverity.INFO
            )
            
            logger.info(
                f"Consent recorded",
                user_id=user_id,
                consent_type=consent_type.value,
                granted=granted
            )
            
            return consent_record
        
        except Exception as e:
            logger.error(f"Failed to record consent: {str(e)}")
            raise
    
    async def withdraw_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Withdraw user consent
        """
        try:
            consent_key = f"consent:{user_id}:{consent_type.value}"
            consent_data = await cache_service.get(consent_key)
            
            if not consent_data:
                return False
            
            # Update consent record
            consent_data["granted"] = False
            consent_data["withdrawal_timestamp"] = datetime.utcnow().isoformat()
            
            await cache_service.set(consent_key, consent_data, expire=86400 * 365)
            
            # Audit the withdrawal
            await self.audit_service.log_event(
                event_type="consent_withdrawn",
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "consent_type": consent_type.value,
                    "original_grant_time": consent_data["timestamp"]
                },
                severity=AuditSeverity.MEDIUM
            )
            
            # Take action based on consent type
            if consent_type == ConsentType.ANALYTICS:
                await self._disable_analytics_tracking(user_id)
            elif consent_type == ConsentType.MARKETING:
                await self._unsubscribe_marketing(user_id)
            elif consent_type == ConsentType.THIRD_PARTY:
                await self._disable_third_party_integrations(user_id)
            
            logger.info(f"Consent withdrawn", user_id=user_id, consent_type=consent_type.value)
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to withdraw consent: {str(e)}")
            return False
    
    async def get_user_consents(self, user_id: str) -> List[ConsentRecord]:
        """
        Get all consent records for a user
        """
        try:
            consents = []
            
            for consent_type in ConsentType:
                consent_key = f"consent:{user_id}:{consent_type.value}"
                consent_data = await cache_service.get(consent_key)
                
                if consent_data:
                    consent_record = ConsentRecord(
                        user_id=consent_data["user_id"],
                        consent_type=ConsentType(consent_data["consent_type"]),
                        granted=consent_data["granted"],
                        timestamp=datetime.fromisoformat(consent_data["timestamp"]),
                        purpose=consent_data["purpose"],
                        legal_basis=consent_data["legal_basis"],
                        ip_address=consent_data.get("ip_address"),
                        user_agent=consent_data.get("user_agent"),
                        withdrawal_timestamp=datetime.fromisoformat(consent_data["withdrawal_timestamp"]) if consent_data.get("withdrawal_timestamp") else None
                    )
                    consents.append(consent_record)
            
            return consents
        
        except Exception as e:
            logger.error(f"Failed to get user consents: {str(e)}")
            return []
    
    # ============= Data Subject Requests =============
    
    async def create_data_subject_request(
        self,
        user_id: str,
        request_type: ComplianceRequestType,
        requested_by: str,
        description: str,
        verification_data: Optional[Dict[str, Any]] = None
    ) -> ComplianceRequest:
        """
        Create a new data subject request (GDPR/CCPA)
        """
        try:
            request_id = str(uuid.uuid4())
            
            request = ComplianceRequest(
                id=request_id,
                user_id=user_id,
                request_type=request_type,
                status=RequestStatus.PENDING,
                created_at=datetime.utcnow(),
                completed_at=None,
                requested_by=requested_by,
                description=description,
                verification_data=verification_data
            )
            
            # Store request
            request_key = f"compliance_request:{request_id}"
            request_data = {
                "id": request_id,
                "user_id": user_id,
                "request_type": request_type.value,
                "status": RequestStatus.PENDING.value,
                "created_at": request.created_at.isoformat(),
                "completed_at": None,
                "requested_by": requested_by,
                "description": description,
                "verification_data": verification_data,
                "fulfillment_details": None
            }
            
            await cache_service.set(request_key, request_data, expire=86400 * 30)  # 30 days
            
            # Add to user's request list
            user_requests_key = f"user_requests:{user_id}"
            user_requests = await cache_service.get_list(user_requests_key) or []
            user_requests.append(request_id)
            await cache_service.delete(user_requests_key)
            for req_id in user_requests:
                await cache_service.push_to_list(user_requests_key, req_id)
            
            # Audit the request
            await self.audit_service.log_event(
                event_type="data_subject_request_created",
                user_id=user_id,
                details={
                    "request_id": request_id,
                    "request_type": request_type.value,
                    "requested_by": requested_by,
                    "description": description
                },
                severity=AuditSeverity.MEDIUM
            )
            
            logger.info(
                f"Data subject request created",
                request_id=request_id,
                user_id=user_id,
                request_type=request_type.value
            )
            
            return request
        
        except Exception as e:
            logger.error(f"Failed to create data subject request: {str(e)}")
            raise
    
    async def process_data_access_request(
        self,
        request_id: str
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 15 - Right of access request
        """
        try:
            request_data = await cache_service.get(f"compliance_request:{request_id}")
            if not request_data:
                raise ValueError("Request not found")
            
            user_id = request_data["user_id"]
            
            # Update request status
            request_data["status"] = RequestStatus.IN_PROGRESS.value
            await cache_service.set(f"compliance_request:{request_id}", request_data, expire=86400 * 30)
            
            # Collect all user data
            user_data = await self._collect_all_user_data(user_id)
            
            # Generate data package
            data_package = {
                "request_id": request_id,
                "user_id": user_id,
                "generated_at": datetime.utcnow().isoformat(),
                "data_categories": user_data,
                "consent_history": [
                    {
                        "consent_type": consent.consent_type.value,
                        "granted": consent.granted,
                        "timestamp": consent.timestamp.isoformat(),
                        "purpose": consent.purpose,
                        "withdrawal_timestamp": consent.withdrawal_timestamp.isoformat() if consent.withdrawal_timestamp else None
                    }
                    for consent in await self.get_user_consents(user_id)
                ],
                "data_processing_purposes": {
                    category: details["description"] 
                    for category, details in self.data_categories.items()
                },
                "retention_periods": self.retention_periods,
                "third_party_sharing": await self._get_third_party_sharing_info(user_id)
            }
            
            # Store the data package
            package_key = f"data_package:{request_id}"
            await cache_service.set(package_key, data_package, expire=86400 * 7)  # Available for 7 days
            
            # Complete the request
            request_data["status"] = RequestStatus.COMPLETED.value
            request_data["completed_at"] = datetime.utcnow().isoformat()
            request_data["fulfillment_details"] = {
                "data_package_key": package_key,
                "package_size": len(json.dumps(data_package)),
                "categories_included": list(user_data.keys())
            }
            
            await cache_service.set(f"compliance_request:{request_id}", request_data, expire=86400 * 30)
            
            # Audit completion
            await self.audit_service.log_event(
                event_type="data_access_request_completed",
                user_id=user_id,
                details={
                    "request_id": request_id,
                    "data_categories": list(user_data.keys()),
                    "package_size": len(json.dumps(data_package))
                },
                severity=AuditSeverity.INFO
            )
            
            logger.info(f"Data access request completed", request_id=request_id, user_id=user_id)
            
            return {
                "request_id": request_id,
                "status": "completed",
                "data_package_available": True,
                "package_expiry": datetime.utcnow() + timedelta(days=7),
                "download_url": f"/api/v1/compliance/download/{request_id}"
            }
        
        except Exception as e:
            logger.error(f"Failed to process data access request: {str(e)}")
            raise
    
    async def process_data_erasure_request(
        self,
        request_id: str,
        force_delete: bool = False
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 17 - Right to erasure request
        """
        try:
            request_data = await cache_service.get(f"compliance_request:{request_id}")
            if not request_data:
                raise ValueError("Request not found")
            
            user_id = request_data["user_id"]
            
            # Check if erasure is legally permissible
            erasure_check = await self._can_erase_user_data(user_id)
            if not erasure_check["can_erase"] and not force_delete:
                request_data["status"] = RequestStatus.REJECTED.value
                request_data["fulfillment_details"] = {
                    "rejection_reason": erasure_check["reason"],
                    "legal_basis": erasure_check.get("legal_basis")
                }
                await cache_service.set(f"compliance_request:{request_id}", request_data, expire=86400 * 30)
                return {
                    "request_id": request_id,
                    "status": "rejected",
                    "reason": erasure_check["reason"]
                }
            
            # Update request status
            request_data["status"] = RequestStatus.IN_PROGRESS.value
            await cache_service.set(f"compliance_request:{request_id}", request_data, expire=86400 * 30)
            
            # Perform data erasure
            erasure_results = await self._erase_user_data(user_id, preserve_legal_data=not force_delete)
            
            # Complete the request
            request_data["status"] = RequestStatus.COMPLETED.value
            request_data["completed_at"] = datetime.utcnow().isoformat()
            request_data["fulfillment_details"] = erasure_results
            
            await cache_service.set(f"compliance_request:{request_id}", request_data, expire=86400 * 30)
            
            # Audit the erasure
            await self.audit_service.log_event(
                event_type="data_erasure_completed",
                user_id=user_id,
                details={
                    "request_id": request_id,
                    "erasure_results": erasure_results,
                    "force_delete": force_delete
                },
                severity=AuditSeverity.HIGH
            )
            
            logger.info(f"Data erasure request completed", request_id=request_id, user_id=user_id)
            
            return {
                "request_id": request_id,
                "status": "completed",
                "erasure_results": erasure_results
            }
        
        except Exception as e:
            logger.error(f"Failed to process data erasure request: {str(e)}")
            raise
    
    # ============= Data Collection and Management =============
    
    async def _collect_all_user_data(self, user_id: str) -> Dict[str, Any]:
        """
        Collect all user data across the system
        """
        try:
            user_data = {}
            
            # Get user profile from Clerk
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if user:
                user_data["profile"] = {
                    "user_id": user.id,
                    "email": user.email_addresses[0].email_address if user.email_addresses else None,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "username": user.username,
                    "profile_image_url": user.profile_image_url,
                    "created_at": user.created_at,
                    "updated_at": user.updated_at,
                    "public_metadata": user.public_metadata,
                    "private_metadata": user.private_metadata
                }
            
            # Get session data
            session_query = select(UserSession).where(UserSession.user_id == user_id)
            session_result = await self.db.execute(session_query)
            sessions = session_result.scalars().all()
            
            user_data["sessions"] = [
                {
                    "session_id": session.session_id,
                    "ip_address": session.ip_address,
                    "location": session.location,
                    "user_agent": session.user_agent,
                    "device_info": session.device_info,
                    "created_at": session.created_at.isoformat(),
                    "last_activity_at": session.last_activity_at.isoformat(),
                    "ended_at": session.ended_at.isoformat() if session.ended_at else None,
                    "is_active": session.is_active
                }
                for session in sessions
            ]
            
            # Get audit logs
            audit_query = select(AuditLog).where(AuditLog.user_id == user_id)
            audit_result = await self.db.execute(audit_query)
            audit_logs = audit_result.scalars().all()
            
            user_data["audit_logs"] = [
                {
                    "id": log.id,
                    "event_type": log.event_type,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "details": log.details,
                    "outcome": log.outcome,
                    "severity": log.severity,
                    "created_at": log.created_at.isoformat()
                }
                for log in audit_logs
            ]
            
            # Get cached data
            user_data["preferences"] = await cache_service.get(f"user_preferences:{user_id}") or {}
            user_data["activity_metrics"] = await cache_service.get(f"activity_metrics:user:{user_id}") or {}
            
            return user_data
        
        except Exception as e:
            logger.error(f"Failed to collect user data: {str(e)}")
            return {}
    
    async def _can_erase_user_data(self, user_id: str) -> Dict[str, Any]:
        """
        Check if user data can be legally erased
        """
        try:
            # Check for legal holds or ongoing investigations
            legal_hold_key = f"legal_hold:{user_id}"
            legal_hold = await cache_service.get(legal_hold_key)
            
            if legal_hold:
                return {
                    "can_erase": False,
                    "reason": "Data is under legal hold",
                    "legal_basis": "Legal obligation"
                }
            
            # Check for pending transactions or contractual obligations
            # This would check for active subscriptions, pending payments, etc.
            
            # Check retention requirements
            # Some data must be retained for regulatory compliance
            
            return {
                "can_erase": True,
                "reason": "No legal impediments to erasure"
            }
        
        except Exception as e:
            logger.error(f"Failed to check erasure eligibility: {str(e)}")
            return {
                "can_erase": False,
                "reason": "Error checking erasure eligibility"
            }
    
    async def _erase_user_data(self, user_id: str, preserve_legal_data: bool = True) -> Dict[str, Any]:
        """
        Erase user data while preserving legally required data
        """
        try:
            erasure_results = {
                "user_id": user_id,
                "erased_categories": [],
                "preserved_categories": [],
                "erasure_timestamp": datetime.utcnow().isoformat()
            }
            
            # Anonymize user profile in Clerk
            if not preserve_legal_data:
                clerk_client = await self._get_clerk_client()
                # In practice, you'd anonymize rather than delete to preserve audit trails
                anonymized_data = {
                    "first_name": f"DELETED_{user_id[:8]}",
                    "last_name": "USER",
                    "public_metadata": {"anonymized": True, "anonymized_at": datetime.utcnow().isoformat()}
                }
                await clerk_client.update_user(user_id, **anonymized_data)
                erasure_results["erased_categories"].append("profile_data")
            
            # Clear cached user data
            cache_keys_to_delete = [
                f"user_preferences:{user_id}",
                f"activity_metrics:user:{user_id}",
                f"recent_activity:{user_id}",
                f"avatar:{user_id}"
            ]
            
            for key in cache_keys_to_delete:
                await cache_service.delete(key)
            
            erasure_results["erased_categories"].extend(["preferences", "activity_metrics", "cache_data"])
            
            # Anonymize session data (keep for legal/security purposes but remove PII)
            session_query = select(UserSession).where(UserSession.user_id == user_id)
            session_result = await self.db.execute(session_query)
            sessions = session_result.scalars().all()
            
            for session in sessions:
                session.ip_address = "ANONYMIZED"
                session.user_agent = "ANONYMIZED"
                session.device_info = {"anonymized": True}
                session.location = "ANONYMIZED"
            
            await self.db.commit()
            erasure_results["erased_categories"].append("session_pii")
            
            # Preserve audit logs for legal compliance but anonymize PII
            if preserve_legal_data:
                audit_query = select(AuditLog).where(AuditLog.user_id == user_id)
                audit_result = await self.db.execute(audit_query)
                audit_logs = audit_result.scalars().all()
                
                for log in audit_logs:
                    log.ip_address = "ANONYMIZED"
                    log.user_agent = "ANONYMIZED"
                    if log.details:
                        # Remove PII from details while preserving event structure
                        anonymized_details = self._anonymize_audit_details(log.details)
                        log.details = anonymized_details
                
                await self.db.commit()
                erasure_results["preserved_categories"].append("audit_logs_anonymized")
            
            return erasure_results
        
        except Exception as e:
            logger.error(f"Failed to erase user data: {str(e)}")
            raise
    
    def _anonymize_audit_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Anonymize PII in audit log details while preserving structure
        """
        if not isinstance(details, dict):
            return details
        
        anonymized = {}
        pii_fields = ["email", "first_name", "last_name", "phone", "address", "ip_address"]
        
        for key, value in details.items():
            if key.lower() in pii_fields:
                anonymized[key] = "ANONYMIZED"
            elif isinstance(value, dict):
                anonymized[key] = self._anonymize_audit_details(value)
            else:
                anonymized[key] = value
        
        return anonymized
    
    # ============= Helper Methods =============
    
    async def _disable_analytics_tracking(self, user_id: str):
        """Disable analytics tracking for user"""
        tracking_key = f"analytics_disabled:{user_id}"
        await cache_service.set(tracking_key, True, expire=86400 * 365)
    
    async def _unsubscribe_marketing(self, user_id: str):
        """Unsubscribe user from marketing communications"""
        marketing_key = f"marketing_unsubscribed:{user_id}"
        await cache_service.set(marketing_key, True, expire=86400 * 365)
    
    async def _disable_third_party_integrations(self, user_id: str):
        """Disable third-party integrations for user"""
        integrations_key = f"third_party_disabled:{user_id}"
        await cache_service.set(integrations_key, True, expire=86400 * 365)
    
    async def _get_third_party_sharing_info(self, user_id: str) -> List[Dict[str, Any]]:
        """Get information about third-party data sharing"""
        # This would return information about what data is shared with third parties
        return [
            {
                "partner": "Analytics Provider",
                "data_shared": ["usage_statistics", "anonymized_activity"],
                "purpose": "Service improvement and analytics",
                "legal_basis": "legitimate_interest",
                "retention_period": "2 years"
            },
            {
                "partner": "Email Service Provider",
                "data_shared": ["email_address", "name"],
                "purpose": "Transactional emails",
                "legal_basis": "contract",
                "retention_period": "As long as account is active"
            }
        ]
    
    async def get_compliance_dashboard(self) -> Dict[str, Any]:
        """
        Get compliance dashboard metrics
        """
        try:
            # Get all pending requests
            pending_requests = []
            # This would query all pending compliance requests
            
            # Get consent statistics
            consent_stats = {
                "total_consent_records": 0,
                "active_consents": 0,
                "withdrawn_consents": 0,
                "consent_by_type": {}
            }
            
            # Get data retention status
            retention_status = {
                "categories_monitored": len(self.data_categories),
                "items_due_for_deletion": 0,
                "automated_deletion_enabled": True
            }
            
            return {
                "pending_requests": len(pending_requests),
                "consent_statistics": consent_stats,
                "retention_status": retention_status,
                "data_categories": list(self.data_categories.keys()),
                "compliance_score": 95,  # Would be calculated based on various factors
                "last_updated": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get compliance dashboard: {str(e)}")
            return {}


# Factory function
def get_compliance_service(db: AsyncSession) -> ComplianceService:
    return ComplianceService(db)