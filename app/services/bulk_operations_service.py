from typing import Dict, Any, Optional, List, BinaryIO
from datetime import datetime, timedelta
import csv
import json
import io
import asyncio
from enum import Enum
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthorizationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client
from app.services.audit_service import AuditService, AuditEventType, AuditSeverity
from app.tasks import user_tasks, export_tasks

logger = structlog.get_logger()


class BulkOperationType(Enum):
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    USER_BAN = "user_ban"
    USER_UNBAN = "user_unban"
    USER_EXPORT = "user_export"
    USER_IMPORT = "user_import"
    ROLE_ASSIGN = "role_assign"
    ROLE_REVOKE = "role_revoke"
    ORG_INVITE = "org_invite"
    ORG_REMOVE = "org_remove"
    SESSION_TERMINATE = "session_terminate"
    PASSWORD_RESET = "password_reset"
    EMAIL_SEND = "email_send"


class BulkOperationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class BulkOperationsService:
    """
    Service for handling bulk operations on users, organizations, and other entities
    """
    
    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db
        self.clerk_client = None
        self.max_batch_size = getattr(settings, 'BULK_MAX_BATCH_SIZE', 1000)
        self.concurrent_limit = getattr(settings, 'BULK_CONCURRENT_LIMIT', 10)
        self.operation_timeout = getattr(settings, 'BULK_OPERATION_TIMEOUT', 3600)  # 1 hour
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    # ============= User Bulk Operations =============
    
    async def bulk_create_users(
        self,
        users_data: List[Dict[str, Any]],
        admin_id: str,
        send_invitations: bool = True,
        validate_only: bool = False
    ) -> Dict[str, Any]:
        """
        Create multiple users in bulk
        """
        operation_id = None
        try:
            # Validate batch size
            if len(users_data) > self.max_batch_size:
                raise ValidationError(f"Maximum batch size is {self.max_batch_size}")
            
            # Create operation tracking
            operation_id = await self._create_operation(
                operation_type=BulkOperationType.USER_CREATE,
                total_items=len(users_data),
                initiated_by=admin_id
            )
            
            # Validate all users first
            validation_results = []
            for idx, user_data in enumerate(users_data):
                validation = await self._validate_user_data(user_data, idx)
                validation_results.append(validation)
            
            # Check for validation errors
            validation_errors = [v for v in validation_results if not v["valid"]]
            if validation_errors:
                if validate_only or len(validation_errors) == len(users_data):
                    await self._update_operation_status(
                        operation_id,
                        BulkOperationStatus.FAILED,
                        errors=validation_errors
                    )
                    return {
                        "operation_id": operation_id,
                        "status": "validation_failed",
                        "errors": validation_errors,
                        "valid_count": len(users_data) - len(validation_errors)
                    }
            
            if validate_only:
                return {
                    "operation_id": operation_id,
                    "status": "validation_successful",
                    "total": len(users_data),
                    "message": "All users passed validation"
                }
            
            # Process user creation in batches
            clerk_client = await self._get_clerk_client()
            created_users = []
            failed_users = []
            
            # Update status to in progress
            await self._update_operation_status(
                operation_id,
                BulkOperationStatus.IN_PROGRESS
            )
            
            # Process concurrently with limit
            semaphore = asyncio.Semaphore(self.concurrent_limit)
            
            async def create_user(user_data: Dict[str, Any], index: int):
                async with semaphore:
                    try:
                        # Create user in Clerk
                        user = await clerk_client.create_user(
                            email_address=user_data.get("email"),
                            password=user_data.get("password"),
                            first_name=user_data.get("first_name"),
                            last_name=user_data.get("last_name"),
                            username=user_data.get("username"),
                            phone_number=user_data.get("phone_number"),
                            public_metadata=user_data.get("public_metadata", {}),
                            private_metadata=user_data.get("private_metadata", {})
                        )
                        
                        created_users.append({
                            "index": index,
                            "user_id": user.id,
                            "email": user_data.get("email"),
                            "status": "created"
                        })
                        
                        # Send invitation if requested
                        if send_invitations and user_data.get("send_invitation", True):
                            # Queue invitation email
                            await self._queue_invitation_email(user.id, user_data.get("email"))
                        
                        # Update progress
                        await self._update_operation_progress(
                            operation_id,
                            len(created_users) + len(failed_users),
                            len(users_data)
                        )
                        
                    except Exception as e:
                        logger.error(f"Failed to create user at index {index}: {str(e)}")
                        failed_users.append({
                            "index": index,
                            "email": user_data.get("email"),
                            "error": str(e)
                        })
            
            # Create all users concurrently
            tasks = [create_user(user_data, idx) for idx, user_data in enumerate(users_data)]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Determine final status
            if len(failed_users) == 0:
                final_status = BulkOperationStatus.COMPLETED
            elif len(created_users) == 0:
                final_status = BulkOperationStatus.FAILED
            else:
                final_status = BulkOperationStatus.PARTIAL
            
            # Update operation status
            await self._update_operation_status(
                operation_id,
                final_status,
                results={
                    "created": created_users,
                    "failed": failed_users
                }
            )
            
            # Log audit event
            if self.db:
                audit_service = AuditService(self.db)
                await audit_service.log_event(
                    event_type=AuditEventType.BULK_OPERATION,
                    user_id=admin_id,
                    details={
                        "operation": "bulk_user_create",
                        "total": len(users_data),
                        "created": len(created_users),
                        "failed": len(failed_users)
                    },
                    severity=AuditSeverity.HIGH
                )
            
            logger.info(
                "Bulk user creation completed",
                operation_id=operation_id,
                total=len(users_data),
                created=len(created_users),
                failed=len(failed_users)
            )
            
            return {
                "operation_id": operation_id,
                "status": final_status.value,
                "total": len(users_data),
                "created": len(created_users),
                "failed": len(failed_users),
                "results": {
                    "created_users": created_users,
                    "failed_users": failed_users
                }
            }
            
        except Exception as e:
            logger.error(f"Bulk user creation failed: {str(e)}")
            if operation_id:
                await self._update_operation_status(
                    operation_id,
                    BulkOperationStatus.FAILED,
                    error=str(e)
                )
            raise ValidationError(f"Bulk operation failed: {str(e)}")
    
    async def bulk_update_users(
        self,
        updates: List[Dict[str, Any]],
        admin_id: str
    ) -> Dict[str, Any]:
        """
        Update multiple users in bulk
        """
        operation_id = None
        try:
            # Validate batch size
            if len(updates) > self.max_batch_size:
                raise ValidationError(f"Maximum batch size is {self.max_batch_size}")
            
            # Create operation tracking
            operation_id = await self._create_operation(
                operation_type=BulkOperationType.USER_UPDATE,
                total_items=len(updates),
                initiated_by=admin_id
            )
            
            clerk_client = await self._get_clerk_client()
            updated_users = []
            failed_updates = []
            
            # Update status to in progress
            await self._update_operation_status(
                operation_id,
                BulkOperationStatus.IN_PROGRESS
            )
            
            # Process updates concurrently
            semaphore = asyncio.Semaphore(self.concurrent_limit)
            
            async def update_user(update_data: Dict[str, Any]):
                async with semaphore:
                    try:
                        user_id = update_data.get("user_id")
                        if not user_id:
                            raise ValidationError("user_id is required")
                        
                        # Remove user_id from update data
                        update_fields = {k: v for k, v in update_data.items() if k != "user_id"}
                        
                        # Update user in Clerk
                        await clerk_client.update_user(
                            user_id=user_id,
                            **update_fields
                        )
                        
                        updated_users.append({
                            "user_id": user_id,
                            "status": "updated",
                            "fields": list(update_fields.keys())
                        })
                        
                    except Exception as e:
                        logger.error(f"Failed to update user {user_id}: {str(e)}")
                        failed_updates.append({
                            "user_id": update_data.get("user_id"),
                            "error": str(e)
                        })
            
            # Update all users concurrently
            tasks = [update_user(update_data) for update_data in updates]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Determine final status
            if len(failed_updates) == 0:
                final_status = BulkOperationStatus.COMPLETED
            elif len(updated_users) == 0:
                final_status = BulkOperationStatus.FAILED
            else:
                final_status = BulkOperationStatus.PARTIAL
            
            # Update operation status
            await self._update_operation_status(
                operation_id,
                final_status,
                results={
                    "updated": updated_users,
                    "failed": failed_updates
                }
            )
            
            return {
                "operation_id": operation_id,
                "status": final_status.value,
                "total": len(updates),
                "updated": len(updated_users),
                "failed": len(failed_updates),
                "results": {
                    "updated_users": updated_users,
                    "failed_updates": failed_updates
                }
            }
            
        except Exception as e:
            logger.error(f"Bulk user update failed: {str(e)}")
            if operation_id:
                await self._update_operation_status(
                    operation_id,
                    BulkOperationStatus.FAILED,
                    error=str(e)
                )
            raise ValidationError(f"Bulk update failed: {str(e)}")
    
    async def bulk_delete_users(
        self,
        user_ids: List[str],
        admin_id: str,
        reason: str,
        hard_delete: bool = False
    ) -> Dict[str, Any]:
        """
        Delete multiple users in bulk
        """
        operation_id = None
        try:
            # Validate batch size
            if len(user_ids) > self.max_batch_size:
                raise ValidationError(f"Maximum batch size is {self.max_batch_size}")
            
            # Create operation tracking
            operation_id = await self._create_operation(
                operation_type=BulkOperationType.USER_DELETE,
                total_items=len(user_ids),
                initiated_by=admin_id,
                metadata={"reason": reason, "hard_delete": hard_delete}
            )
            
            clerk_client = await self._get_clerk_client()
            deleted_users = []
            failed_deletes = []
            
            # Process deletions
            for user_id in user_ids:
                try:
                    await clerk_client.delete_user(user_id)
                    deleted_users.append(user_id)
                except Exception as e:
                    logger.error(f"Failed to delete user {user_id}: {str(e)}")
                    failed_deletes.append({
                        "user_id": user_id,
                        "error": str(e)
                    })
            
            # Update operation status
            final_status = BulkOperationStatus.COMPLETED if len(failed_deletes) == 0 else BulkOperationStatus.PARTIAL
            await self._update_operation_status(
                operation_id,
                final_status,
                results={
                    "deleted": deleted_users,
                    "failed": failed_deletes
                }
            )
            
            return {
                "operation_id": operation_id,
                "status": final_status.value,
                "total": len(user_ids),
                "deleted": len(deleted_users),
                "failed": len(failed_deletes)
            }
            
        except Exception as e:
            logger.error(f"Bulk user deletion failed: {str(e)}")
            if operation_id:
                await self._update_operation_status(
                    operation_id,
                    BulkOperationStatus.FAILED,
                    error=str(e)
                )
            raise ValidationError(f"Bulk deletion failed: {str(e)}")
    
    # ============= Import/Export Operations =============
    
    async def import_users_from_csv(
        self,
        csv_file: BinaryIO,
        admin_id: str,
        send_invitations: bool = True,
        validate_only: bool = False
    ) -> Dict[str, Any]:
        """
        Import users from CSV file
        """
        try:
            # Parse CSV
            csv_content = csv_file.read().decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            
            users_data = []
            for row in csv_reader:
                user_data = {
                    "email": row.get("email"),
                    "first_name": row.get("first_name"),
                    "last_name": row.get("last_name"),
                    "username": row.get("username"),
                    "phone_number": row.get("phone_number"),
                    "role": row.get("role"),
                    "organization": row.get("organization"),
                    "send_invitation": row.get("send_invitation", "true").lower() == "true"
                }
                
                # Parse metadata if provided
                if row.get("metadata"):
                    try:
                        user_data["public_metadata"] = json.loads(row.get("metadata"))
                    except:
                        pass
                
                users_data.append(user_data)
            
            # Use bulk create
            return await self.bulk_create_users(
                users_data=users_data,
                admin_id=admin_id,
                send_invitations=send_invitations,
                validate_only=validate_only
            )
            
        except Exception as e:
            logger.error(f"CSV import failed: {str(e)}")
            raise ValidationError(f"Failed to import CSV: {str(e)}")
    
    async def export_users_to_csv(
        self,
        admin_id: str,
        filters: Optional[Dict[str, Any]] = None,
        fields: Optional[List[str]] = None
    ) -> str:
        """
        Export users to CSV format
        """
        try:
            # Default fields if not specified
            if not fields:
                fields = [
                    "id", "email", "first_name", "last_name",
                    "username", "created_at", "last_sign_in_at",
                    "email_verified", "banned"
                ]
            
            # Get users from Clerk
            clerk_client = await self._get_clerk_client()
            
            # Build query parameters
            query_params = {}
            if filters:
                if filters.get("email"):
                    query_params["email_address"] = filters["email"]
                if filters.get("created_after"):
                    query_params["created_at"] = {"$gte": filters["created_after"]}
            
            # Fetch users (paginated)
            all_users = []
            offset = 0
            limit = 100
            
            while True:
                users_response = await clerk_client.list_users(
                    limit=limit,
                    offset=offset,
                    **query_params
                )
                
                users = users_response.get("data", [])
                if not users:
                    break
                
                all_users.extend(users)
                offset += limit
                
                # Safety limit
                if len(all_users) >= 10000:
                    logger.warning("Export limited to 10000 users")
                    break
            
            # Convert to CSV
            output = io.StringIO()
            csv_writer = csv.DictWriter(output, fieldnames=fields)
            csv_writer.writeheader()
            
            for user in all_users:
                row = {}
                for field in fields:
                    value = getattr(user, field, None)
                    if value is not None:
                        if isinstance(value, datetime):
                            value = value.isoformat()
                        elif isinstance(value, dict):
                            value = json.dumps(value)
                        elif isinstance(value, bool):
                            value = str(value).lower()
                    row[field] = value
                csv_writer.writerow(row)
            
            csv_content = output.getvalue()
            
            # Store export in cache with expiration
            export_id = f"export_{admin_id}_{datetime.utcnow().timestamp()}"
            await cache_service.set(
                f"bulk_export:{export_id}",
                {
                    "content": csv_content,
                    "type": "csv",
                    "created_by": admin_id,
                    "created_at": datetime.utcnow().isoformat(),
                    "row_count": len(all_users)
                },
                expire=3600  # 1 hour
            )
            
            logger.info(
                "User export completed",
                export_id=export_id,
                row_count=len(all_users),
                admin_id=admin_id
            )
            
            return export_id
            
        except Exception as e:
            logger.error(f"User export failed: {str(e)}")
            raise ValidationError(f"Failed to export users: {str(e)}")
    
    # ============= Bulk Action Operations =============
    
    async def bulk_ban_users(
        self,
        user_ids: List[str],
        admin_id: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Ban multiple users
        """
        return await self._bulk_user_action(
            user_ids=user_ids,
            action="ban",
            admin_id=admin_id,
            reason=reason,
            operation_type=BulkOperationType.USER_BAN
        )
    
    async def bulk_unban_users(
        self,
        user_ids: List[str],
        admin_id: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Unban multiple users
        """
        return await self._bulk_user_action(
            user_ids=user_ids,
            action="unban",
            admin_id=admin_id,
            reason=reason,
            operation_type=BulkOperationType.USER_UNBAN
        )
    
    async def bulk_reset_passwords(
        self,
        user_ids: List[str],
        admin_id: str,
        send_email: bool = True
    ) -> Dict[str, Any]:
        """
        Reset passwords for multiple users
        """
        operation_id = None
        try:
            operation_id = await self._create_operation(
                operation_type=BulkOperationType.PASSWORD_RESET,
                total_items=len(user_ids),
                initiated_by=admin_id
            )
            
            reset_count = 0
            failed_resets = []
            
            for user_id in user_ids:
                try:
                    # Queue password reset task
                    user_tasks.reset_user_password.delay(user_id, send_email)
                    reset_count += 1
                except Exception as e:
                    failed_resets.append({
                        "user_id": user_id,
                        "error": str(e)
                    })
            
            final_status = BulkOperationStatus.COMPLETED if len(failed_resets) == 0 else BulkOperationStatus.PARTIAL
            
            await self._update_operation_status(
                operation_id,
                final_status,
                results={
                    "reset": reset_count,
                    "failed": failed_resets
                }
            )
            
            return {
                "operation_id": operation_id,
                "status": final_status.value,
                "total": len(user_ids),
                "reset": reset_count,
                "failed": len(failed_resets)
            }
            
        except Exception as e:
            if operation_id:
                await self._update_operation_status(
                    operation_id,
                    BulkOperationStatus.FAILED,
                    error=str(e)
                )
            raise ValidationError(f"Bulk password reset failed: {str(e)}")
    
    # ============= Helper Methods =============
    
    async def _create_operation(
        self,
        operation_type: BulkOperationType,
        total_items: int,
        initiated_by: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create and track a bulk operation
        """
        operation_id = f"bulk_{operation_type.value}_{datetime.utcnow().timestamp()}"
        
        operation_data = {
            "id": operation_id,
            "type": operation_type.value,
            "status": BulkOperationStatus.PENDING.value,
            "total_items": total_items,
            "processed_items": 0,
            "initiated_by": initiated_by,
            "started_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        
        await cache_service.set(
            f"bulk_operation:{operation_id}",
            operation_data,
            expire=self.operation_timeout
        )
        
        return operation_id
    
    async def _update_operation_status(
        self,
        operation_id: str,
        status: BulkOperationStatus,
        results: Optional[Dict[str, Any]] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
        error: Optional[str] = None
    ):
        """
        Update bulk operation status
        """
        cache_key = f"bulk_operation:{operation_id}"
        operation_data = await cache_service.get(cache_key)
        
        if operation_data:
            operation_data["status"] = status.value
            if status in [BulkOperationStatus.COMPLETED, BulkOperationStatus.FAILED, BulkOperationStatus.PARTIAL]:
                operation_data["completed_at"] = datetime.utcnow().isoformat()
            
            if results:
                operation_data["results"] = results
            if errors:
                operation_data["errors"] = errors
            if error:
                operation_data["error"] = error
            
            await cache_service.set(cache_key, operation_data, expire=self.operation_timeout)
    
    async def _update_operation_progress(
        self,
        operation_id: str,
        processed: int,
        total: int
    ):
        """
        Update operation progress
        """
        cache_key = f"bulk_operation:{operation_id}"
        operation_data = await cache_service.get(cache_key)
        
        if operation_data:
            operation_data["processed_items"] = processed
            operation_data["progress_percentage"] = (processed / total) * 100 if total > 0 else 0
            operation_data["last_updated"] = datetime.utcnow().isoformat()
            
            await cache_service.set(cache_key, operation_data, expire=self.operation_timeout)
    
    async def _validate_user_data(self, user_data: Dict[str, Any], index: int) -> Dict[str, Any]:
        """
        Validate user data before creation
        """
        errors = []
        
        # Required fields
        if not user_data.get("email"):
            errors.append("Email is required")
        
        # Email format validation
        email = user_data.get("email")
        if email and "@" not in email:
            errors.append("Invalid email format")
        
        # Password validation (if provided)
        password = user_data.get("password")
        if password and len(password) < 8:
            errors.append("Password must be at least 8 characters")
        
        return {
            "index": index,
            "valid": len(errors) == 0,
            "errors": errors,
            "email": email
        }
    
    async def _bulk_user_action(
        self,
        user_ids: List[str],
        action: str,
        admin_id: str,
        reason: str,
        operation_type: BulkOperationType
    ) -> Dict[str, Any]:
        """
        Perform bulk action on users
        """
        operation_id = None
        try:
            operation_id = await self._create_operation(
                operation_type=operation_type,
                total_items=len(user_ids),
                initiated_by=admin_id,
                metadata={"reason": reason}
            )
            
            clerk_client = await self._get_clerk_client()
            success_count = 0
            failed_actions = []
            
            for user_id in user_ids:
                try:
                    if action == "ban":
                        await clerk_client.ban_user(user_id)
                    elif action == "unban":
                        await clerk_client.unban_user(user_id)
                    success_count += 1
                except Exception as e:
                    failed_actions.append({
                        "user_id": user_id,
                        "error": str(e)
                    })
            
            final_status = BulkOperationStatus.COMPLETED if len(failed_actions) == 0 else BulkOperationStatus.PARTIAL
            
            await self._update_operation_status(
                operation_id,
                final_status,
                results={
                    "success": success_count,
                    "failed": failed_actions
                }
            )
            
            return {
                "operation_id": operation_id,
                "status": final_status.value,
                "total": len(user_ids),
                "success": success_count,
                "failed": len(failed_actions)
            }
            
        except Exception as e:
            if operation_id:
                await self._update_operation_status(
                    operation_id,
                    BulkOperationStatus.FAILED,
                    error=str(e)
                )
            raise ValidationError(f"Bulk {action} failed: {str(e)}")
    
    async def _queue_invitation_email(self, user_id: str, email: str):
        """
        Queue invitation email for new user
        """
        try:
            # This would queue an email task
            # Implementation depends on your email service
            pass
        except Exception as e:
            logger.error(f"Failed to queue invitation email: {str(e)}")
    
    async def get_operation_status(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a bulk operation
        """
        cache_key = f"bulk_operation:{operation_id}"
        return await cache_service.get(cache_key)
    
    async def cancel_operation(self, operation_id: str) -> bool:
        """
        Cancel a bulk operation
        """
        try:
            await self._update_operation_status(
                operation_id,
                BulkOperationStatus.CANCELLED
            )
            return True
        except:
            return False


# Create service instance
def get_bulk_operations_service(db: Optional[AsyncSession] = None) -> BulkOperationsService:
    return BulkOperationsService(db=db)