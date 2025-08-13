"""
Soft Delete Service
Handles soft deletion with recovery periods for GDPR compliance
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import uuid
import hashlib
import json

from sqlalchemy import select, update, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.cache import cache_service
from app.core.config import settings
from app.services.email_service import email_service
from app.services.audit_service import audit_service
from app.services.activity_service import activity_service
from app.core.exceptions import (
    BadRequestError,
    NotFoundError,
    ForbiddenError
)


class DeletionStatus(str, Enum):
    """Deletion status enum"""
    ACTIVE = "active"
    PENDING_DELETION = "pending_deletion"
    DELETED = "deleted"
    RECOVERED = "recovered"
    PERMANENTLY_DELETED = "permanently_deleted"


class DataCategory(str, Enum):
    """GDPR data categories"""
    PERSONAL_DATA = "personal_data"
    SENSITIVE_DATA = "sensitive_data"
    USAGE_DATA = "usage_data"
    TECHNICAL_DATA = "technical_data"
    MARKETING_DATA = "marketing_data"
    FINANCIAL_DATA = "financial_data"


class SoftDeleteService:
    """Service for managing soft deletion with recovery"""
    
    def __init__(self):
        # Recovery periods (in days)
        self.default_recovery_period = 30
        self.max_recovery_period = 90
        self.min_recovery_period = 7
        
        # Grace period for critical accounts
        self.critical_account_grace_period = 60
        
        # Anonymization settings
        self.anonymize_after_deletion = True
        self.hash_algorithm = "sha256"
    
    async def request_deletion(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        reason: Optional[str] = None,
        recovery_period_days: Optional[int] = None,
        immediate: bool = False,
        data_categories: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Request soft deletion of a resource
        
        Args:
            user_id: User requesting deletion
            resource_type: Type of resource (user, organization, workspace, etc.)
            resource_id: ID of resource to delete
            reason: Reason for deletion (GDPR request, user request, etc.)
            recovery_period_days: Custom recovery period
            immediate: Skip recovery period (requires special permission)
            data_categories: Specific data categories to delete (GDPR)
        """
        # Validate recovery period
        recovery_period = recovery_period_days or self.default_recovery_period
        if recovery_period > self.max_recovery_period:
            recovery_period = self.max_recovery_period
        elif recovery_period < self.min_recovery_period and not immediate:
            recovery_period = self.min_recovery_period
        
        # Check if resource is critical
        is_critical = await self._is_critical_resource(resource_type, resource_id)
        if is_critical and not immediate:
            recovery_period = max(recovery_period, self.critical_account_grace_period)
        
        # Calculate deletion date
        deletion_date = datetime.utcnow() + timedelta(days=recovery_period)
        if immediate:
            deletion_date = datetime.utcnow()
        
        # Create deletion request
        deletion_request = {
            "id": str(uuid.uuid4()),
            "resource_type": resource_type,
            "resource_id": resource_id,
            "user_id": user_id,
            "status": DeletionStatus.PENDING_DELETION if not immediate else DeletionStatus.DELETED,
            "reason": reason,
            "data_categories": data_categories or [DataCategory.PERSONAL_DATA],
            "recovery_period_days": recovery_period,
            "requested_at": datetime.utcnow(),
            "scheduled_deletion_date": deletion_date,
            "is_critical": is_critical,
            "recovery_token": self._generate_recovery_token() if not immediate else None
        }
        
        # Store deletion request
        await self._store_deletion_request(deletion_request)
        
        # Mark resource as pending deletion
        await self._mark_resource_pending_deletion(
            resource_type,
            resource_id,
            deletion_date
        )
        
        # Send notification
        if not immediate:
            await self._send_deletion_notification(
                user_id,
                resource_type,
                resource_id,
                deletion_date,
                deletion_request["recovery_token"]
            )
        
        # Log activity
        await activity_service.log_activity(
            user_id=user_id,
            action=f"{resource_type}.deletion_requested",
            resource_type=resource_type,
            resource_id=resource_id,
            details={
                "reason": reason,
                "recovery_period": recovery_period,
                "immediate": immediate
            }
        )
        
        # If immediate deletion, process now
        if immediate:
            await self._process_deletion(deletion_request)
        
        return {
            "deletion_id": deletion_request["id"],
            "status": deletion_request["status"],
            "scheduled_deletion_date": deletion_date.isoformat(),
            "recovery_token": deletion_request.get("recovery_token"),
            "recovery_period_days": recovery_period
        }
    
    async def cancel_deletion(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        recovery_token: Optional[str] = None
    ) -> Dict[str, str]:
        """Cancel a pending deletion and recover the resource"""
        # Find deletion request
        deletion_request = await self._get_deletion_request(resource_type, resource_id)
        
        if not deletion_request:
            raise NotFoundError("No pending deletion found for this resource")
        
        # Verify ownership or recovery token
        if deletion_request["user_id"] != user_id:
            if not recovery_token or recovery_token != deletion_request.get("recovery_token"):
                raise ForbiddenError("Invalid recovery token or unauthorized")
        
        # Check if already deleted
        if deletion_request["status"] == DeletionStatus.DELETED:
            raise BadRequestError("Resource has already been deleted")
        
        if deletion_request["status"] == DeletionStatus.PERMANENTLY_DELETED:
            raise BadRequestError("Resource has been permanently deleted and cannot be recovered")
        
        # Recover resource
        await self._recover_resource(resource_type, resource_id)
        
        # Update deletion request
        deletion_request["status"] = DeletionStatus.RECOVERED
        deletion_request["recovered_at"] = datetime.utcnow()
        deletion_request["recovered_by"] = user_id
        
        await self._update_deletion_request(deletion_request)
        
        # Send recovery confirmation
        await self._send_recovery_confirmation(user_id, resource_type, resource_id)
        
        # Log activity
        await audit_service.log_audit_event(
            user_id=user_id,
            action=f"{resource_type}.deletion_cancelled",
            resource_type=resource_type,
            resource_id=resource_id,
            details={"recovered_at": datetime.utcnow().isoformat()}
        )
        
        return {"message": "Deletion cancelled and resource recovered successfully"}
    
    async def process_scheduled_deletions(self) -> Dict[str, Any]:
        """Process all scheduled deletions that have passed their recovery period"""
        # Get all pending deletions past their scheduled date
        pending_deletions = await self._get_pending_deletions()
        
        processed = []
        failed = []
        
        for deletion_request in pending_deletions:
            try:
                if deletion_request["scheduled_deletion_date"] <= datetime.utcnow():
                    await self._process_deletion(deletion_request)
                    processed.append(deletion_request["resource_id"])
            except Exception as e:
                failed.append({
                    "resource_id": deletion_request["resource_id"],
                    "error": str(e)
                })
        
        return {
            "processed": len(processed),
            "failed": len(failed),
            "details": {
                "processed_ids": processed,
                "failed_items": failed
            }
        }
    
    async def get_deletion_status(
        self,
        resource_type: str,
        resource_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the deletion status of a resource"""
        deletion_request = await self._get_deletion_request(resource_type, resource_id)
        
        if not deletion_request:
            return None
        
        remaining_days = None
        if deletion_request["status"] == DeletionStatus.PENDING_DELETION:
            remaining = deletion_request["scheduled_deletion_date"] - datetime.utcnow()
            remaining_days = max(0, remaining.days)
        
        return {
            "status": deletion_request["status"],
            "requested_at": deletion_request["requested_at"].isoformat(),
            "scheduled_deletion_date": deletion_request["scheduled_deletion_date"].isoformat(),
            "remaining_days": remaining_days,
            "reason": deletion_request.get("reason"),
            "can_recover": deletion_request["status"] == DeletionStatus.PENDING_DELETION
        }
    
    async def export_data_before_deletion(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str
    ) -> Dict[str, Any]:
        """Export user data before deletion (GDPR right to data portability)"""
        # Collect all data for the resource
        data = await self._collect_resource_data(resource_type, resource_id)
        
        # Generate export
        export_id = str(uuid.uuid4())
        export_data = {
            "export_id": export_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "exported_at": datetime.utcnow().isoformat(),
            "data": data
        }
        
        # Store export temporarily
        cache_key = f"data_export:{export_id}"
        await cache_service.set(cache_key, export_data, ttl=86400)  # 24 hours
        
        # Send export link via email
        await email_service.send_templated_email(
            to_email=user_id,  # Assuming user_id is email
            template="data_export",
            context={
                "export_id": export_id,
                "download_link": f"{settings.FRONTEND_URL}/download-export/{export_id}",
                "expires_in": "24 hours"
            }
        )
        
        # Log activity
        await activity_service.log_activity(
            user_id=user_id,
            action="data.exported",
            resource_type=resource_type,
            resource_id=resource_id,
            details={"export_id": export_id}
        )
        
        return {
            "export_id": export_id,
            "download_url": f"/api/v1/gdpr/download-export/{export_id}",
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
    
    async def anonymize_data(
        self,
        resource_type: str,
        resource_id: str,
        data_categories: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Anonymize specific data categories while keeping the resource"""
        categories = data_categories or [DataCategory.PERSONAL_DATA]
        
        # Get resource data
        data = await self._collect_resource_data(resource_type, resource_id)
        
        # Anonymize specified categories
        anonymized_fields = []
        for category in categories:
            fields = self._get_fields_for_category(resource_type, category)
            for field in fields:
                if field in data:
                    data[field] = self._anonymize_value(data[field], field)
                    anonymized_fields.append(field)
        
        # Update resource with anonymized data
        await self._update_resource_data(resource_type, resource_id, data)
        
        # Log anonymization
        await audit_service.log_audit_event(
            user_id="system",
            action=f"{resource_type}.anonymized",
            resource_type=resource_type,
            resource_id=resource_id,
            details={
                "categories": categories,
                "fields": anonymized_fields
            }
        )
        
        return {
            "anonymized_categories": categories,
            "anonymized_fields": anonymized_fields,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def permanent_deletion(
        self,
        admin_id: str,
        resource_type: str,
        resource_id: str,
        confirmation_code: str
    ) -> Dict[str, str]:
        """Permanently delete a resource (cannot be recovered)"""
        # Verify admin permission
        # This should check actual admin status
        
        # Verify confirmation code
        expected_code = self._generate_confirmation_code(resource_type, resource_id)
        if confirmation_code != expected_code:
            raise BadRequestError("Invalid confirmation code")
        
        # Perform permanent deletion
        await self._permanent_delete_resource(resource_type, resource_id)
        
        # Update deletion request
        deletion_request = await self._get_deletion_request(resource_type, resource_id)
        if deletion_request:
            deletion_request["status"] = DeletionStatus.PERMANENTLY_DELETED
            deletion_request["permanently_deleted_at"] = datetime.utcnow()
            deletion_request["permanently_deleted_by"] = admin_id
            await self._update_deletion_request(deletion_request)
        
        # Log critical action
        await audit_service.log_audit_event(
            user_id=admin_id,
            action=f"{resource_type}.permanently_deleted",
            resource_type=resource_type,
            resource_id=resource_id,
            severity="critical",
            details={"confirmation_code": confirmation_code}
        )
        
        return {"message": "Resource permanently deleted"}
    
    def _generate_recovery_token(self) -> str:
        """Generate a recovery token"""
        return secrets.token_urlsafe(32)
    
    def _generate_confirmation_code(self, resource_type: str, resource_id: str) -> str:
        """Generate confirmation code for permanent deletion"""
        data = f"{resource_type}:{resource_id}:{datetime.utcnow().date()}"
        return hashlib.sha256(data.encode()).hexdigest()[:8].upper()
    
    def _anonymize_value(self, value: Any, field_name: str) -> Any:
        """Anonymize a value based on its type"""
        if isinstance(value, str):
            if "@" in value:  # Email
                return f"anonymized_{hashlib.md5(value.encode()).hexdigest()[:8]}@example.com"
            elif field_name in ["name", "first_name", "last_name"]:
                return f"User_{hashlib.md5(value.encode()).hexdigest()[:8]}"
            else:
                return f"[REDACTED_{field_name.upper()}]"
        elif isinstance(value, (int, float)):
            return 0
        elif isinstance(value, dict):
            return {}
        elif isinstance(value, list):
            return []
        else:
            return None
    
    def _get_fields_for_category(self, resource_type: str, category: str) -> List[str]:
        """Get fields belonging to a data category"""
        category_fields = {
            DataCategory.PERSONAL_DATA: [
                "email", "name", "first_name", "last_name", "phone_number",
                "address", "date_of_birth", "gender"
            ],
            DataCategory.SENSITIVE_DATA: [
                "ssn", "tax_id", "health_data", "biometric_data",
                "political_views", "religious_beliefs"
            ],
            DataCategory.USAGE_DATA: [
                "last_login", "login_count", "activity_logs",
                "search_history", "browsing_data"
            ],
            DataCategory.TECHNICAL_DATA: [
                "ip_address", "user_agent", "device_id",
                "browser_fingerprint", "cookies"
            ],
            DataCategory.MARKETING_DATA: [
                "preferences", "interests", "segments",
                "campaign_interactions", "email_opens"
            ],
            DataCategory.FINANCIAL_DATA: [
                "payment_methods", "transaction_history",
                "billing_address", "credit_score"
            ]
        }
        
        return category_fields.get(category, [])
    
    async def _is_critical_resource(self, resource_type: str, resource_id: str) -> bool:
        """Check if resource is critical (e.g., admin, organization owner)"""
        # This would check actual resource status
        # For now, simplified logic
        return resource_type in ["admin", "organization_owner"]
    
    async def _store_deletion_request(self, deletion_request: Dict[str, Any]):
        """Store deletion request in database"""
        cache_key = f"deletion_request:{deletion_request['resource_type']}:{deletion_request['resource_id']}"
        await cache_service.set(cache_key, deletion_request)
    
    async def _get_deletion_request(
        self,
        resource_type: str,
        resource_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get deletion request from database"""
        cache_key = f"deletion_request:{resource_type}:{resource_id}"
        return await cache_service.get(cache_key)
    
    async def _update_deletion_request(self, deletion_request: Dict[str, Any]):
        """Update deletion request in database"""
        cache_key = f"deletion_request:{deletion_request['resource_type']}:{deletion_request['resource_id']}"
        await cache_service.set(cache_key, deletion_request)
    
    async def _get_pending_deletions(self) -> List[Dict[str, Any]]:
        """Get all pending deletions"""
        # This would query database for pending deletions
        # For now, returning empty list
        return []
    
    async def _mark_resource_pending_deletion(
        self,
        resource_type: str,
        resource_id: str,
        deletion_date: datetime
    ):
        """Mark resource as pending deletion"""
        # Update resource status in database
        pass
    
    async def _recover_resource(self, resource_type: str, resource_id: str):
        """Recover a resource from pending deletion"""
        # Update resource status to active
        pass
    
    async def _process_deletion(self, deletion_request: Dict[str, Any]):
        """Process the actual deletion"""
        # Anonymize or delete data based on settings
        if self.anonymize_after_deletion:
            await self.anonymize_data(
                deletion_request["resource_type"],
                deletion_request["resource_id"],
                deletion_request.get("data_categories")
            )
        else:
            await self._permanent_delete_resource(
                deletion_request["resource_type"],
                deletion_request["resource_id"]
            )
    
    async def _permanent_delete_resource(self, resource_type: str, resource_id: str):
        """Permanently delete resource from database"""
        # Delete from database
        pass
    
    async def _collect_resource_data(
        self,
        resource_type: str,
        resource_id: str
    ) -> Dict[str, Any]:
        """Collect all data for a resource"""
        # Query database for all resource data
        return {}
    
    async def _update_resource_data(
        self,
        resource_type: str,
        resource_id: str,
        data: Dict[str, Any]
    ):
        """Update resource data in database"""
        pass
    
    async def _send_deletion_notification(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        deletion_date: datetime,
        recovery_token: str
    ):
        """Send deletion notification email"""
        await email_service.send_templated_email(
            to_email=user_id,
            template="deletion_scheduled",
            context={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "deletion_date": deletion_date.isoformat(),
                "recovery_link": f"{settings.FRONTEND_URL}/recover/{recovery_token}",
                "days_remaining": (deletion_date - datetime.utcnow()).days
            }
        )
    
    async def _send_recovery_confirmation(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str
    ):
        """Send recovery confirmation email"""
        await email_service.send_templated_email(
            to_email=user_id,
            template="deletion_cancelled",
            context={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "recovered_at": datetime.utcnow().isoformat()
            }
        )


# Create singleton instance
soft_delete_service = SoftDeleteService()