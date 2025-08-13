from typing import Dict, Any, Optional, List
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
import structlog
import json

from app.db.models import WebhookEvent, AuditLog
from app.services.email_service import EmailService
from app.services.notification_service import NotificationService
from app.core.config import settings

logger = structlog.get_logger()


class WebhookHandler:
    """
    Service to handle webhook events from Clerk
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.email_service = EmailService()
        self.notification_service = NotificationService()
    
    async def store_webhook_event(
        self,
        event_id: str,
        event_type: str,
        payload: Dict[str, Any],
        status: str = "pending",
        error: Optional[str] = None
    ):
        """
        Store webhook event in database for audit and retry
        """
        try:
            event = WebhookEvent(
                event_id=event_id,
                event_type=event_type,
                payload=json.dumps(payload),
                status=status,
                error=error,
                received_at=datetime.utcnow()
            )
            
            self.db.add(event)
            await self.db.commit()
            
            logger.info(
                "Webhook event stored",
                event_id=event_id,
                event_type=event_type,
                status=status
            )
        
        except Exception as e:
            logger.error("Failed to store webhook event", error=str(e))
            await self.db.rollback()
    
    async def handle_user_created(self, data: Dict[str, Any]):
        """
        Handle user.created webhook event
        """
        try:
            user_id = data.get("id")
            email = data.get("email_addresses", [{}])[0].get("email_address")
            
            logger.info("Processing user.created event", user_id=user_id)
            
            # Send welcome email
            if email and settings.SMTP_HOST:
                await self.email_service.send_welcome_email(email, data)
            
            # Create audit log
            await self.create_audit_log(
                event_type="user.created",
                user_id=user_id,
                details={"email": email}
            )
            
            # Trigger any additional onboarding workflows
            await self.notification_service.notify_admins(
                f"New user registered: {email}"
            )
        
        except Exception as e:
            logger.error("Failed to handle user.created", error=str(e))
            raise
    
    async def handle_user_updated(self, data: Dict[str, Any]):
        """
        Handle user.updated webhook event
        """
        try:
            user_id = data.get("id")
            
            logger.info("Processing user.updated event", user_id=user_id)
            
            # Create audit log
            await self.create_audit_log(
                event_type="user.updated",
                user_id=user_id,
                details=data
            )
            
            # Check for specific updates (e.g., email verified)
            email_addresses = data.get("email_addresses", [])
            for email_obj in email_addresses:
                if email_obj.get("verification", {}).get("status") == "verified":
                    # User verified their email
                    await self.notification_service.notify_user(
                        user_id,
                        "Email verified successfully!"
                    )
        
        except Exception as e:
            logger.error("Failed to handle user.updated", error=str(e))
            raise
    
    async def handle_user_deleted(self, data: Dict[str, Any]):
        """
        Handle user.deleted webhook event
        """
        try:
            user_id = data.get("id")
            
            logger.info("Processing user.deleted event", user_id=user_id)
            
            # Clean up user data
            # This would include removing user-specific data from your database
            
            # Create audit log
            await self.create_audit_log(
                event_type="user.deleted",
                user_id=user_id,
                details={"deleted_at": datetime.utcnow().isoformat()}
            )
            
            # Notify admins
            await self.notification_service.notify_admins(
                f"User {user_id} has been deleted"
            )
        
        except Exception as e:
            logger.error("Failed to handle user.deleted", error=str(e))
            raise
    
    async def handle_session_created(self, data: Dict[str, Any]):
        """
        Handle session.created webhook event
        """
        try:
            session_id = data.get("id")
            user_id = data.get("user_id")
            
            logger.info("Processing session.created event", session_id=session_id)
            
            # Track active session
            await self.create_audit_log(
                event_type="session.created",
                user_id=user_id,
                details={
                    "session_id": session_id,
                    "client_id": data.get("client_id"),
                    "created_at": data.get("created_at")
                }
            )
            
            # Check for suspicious activity
            # e.g., multiple sessions from different locations
        
        except Exception as e:
            logger.error("Failed to handle session.created", error=str(e))
            raise
    
    async def handle_session_ended(self, data: Dict[str, Any]):
        """
        Handle session.ended webhook event
        """
        try:
            session_id = data.get("id")
            user_id = data.get("user_id")
            
            logger.info("Processing session.ended event", session_id=session_id)
            
            await self.create_audit_log(
                event_type="session.ended",
                user_id=user_id,
                details={
                    "session_id": session_id,
                    "ended_at": datetime.utcnow().isoformat()
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle session.ended", error=str(e))
            raise
    
    async def handle_session_removed(self, data: Dict[str, Any]):
        """
        Handle session.removed webhook event
        """
        try:
            session_id = data.get("id")
            user_id = data.get("user_id")
            
            logger.info("Processing session.removed event", session_id=session_id)
            
            await self.create_audit_log(
                event_type="session.removed",
                user_id=user_id,
                details={
                    "session_id": session_id,
                    "removed_at": datetime.utcnow().isoformat()
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle session.removed", error=str(e))
            raise
    
    async def handle_organization_created(self, data: Dict[str, Any]):
        """
        Handle organization.created webhook event
        """
        try:
            org_id = data.get("id")
            org_name = data.get("name")
            created_by = data.get("created_by")
            
            logger.info("Processing organization.created event", org_id=org_id)
            
            # Send notification to organization creator
            if created_by:
                await self.notification_service.notify_user(
                    created_by,
                    f"Organization '{org_name}' created successfully!"
                )
            
            await self.create_audit_log(
                event_type="organization.created",
                user_id=created_by,
                details={
                    "org_id": org_id,
                    "org_name": org_name
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle organization.created", error=str(e))
            raise
    
    async def handle_organization_updated(self, data: Dict[str, Any]):
        """
        Handle organization.updated webhook event
        """
        try:
            org_id = data.get("id")
            
            logger.info("Processing organization.updated event", org_id=org_id)
            
            await self.create_audit_log(
                event_type="organization.updated",
                details={"org_id": org_id, "updates": data}
            )
        
        except Exception as e:
            logger.error("Failed to handle organization.updated", error=str(e))
            raise
    
    async def handle_organization_deleted(self, data: Dict[str, Any]):
        """
        Handle organization.deleted webhook event
        """
        try:
            org_id = data.get("id")
            
            logger.info("Processing organization.deleted event", org_id=org_id)
            
            # Clean up organization data
            
            await self.create_audit_log(
                event_type="organization.deleted",
                details={
                    "org_id": org_id,
                    "deleted_at": datetime.utcnow().isoformat()
                }
            )
            
            # Notify admins
            await self.notification_service.notify_admins(
                f"Organization {org_id} has been deleted"
            )
        
        except Exception as e:
            logger.error("Failed to handle organization.deleted", error=str(e))
            raise
    
    async def handle_membership_created(self, data: Dict[str, Any]):
        """
        Handle organizationMembership.created webhook event
        """
        try:
            user_id = data.get("user_id")
            org_id = data.get("organization_id")
            role = data.get("role")
            
            logger.info(
                "Processing membership.created event",
                user_id=user_id,
                org_id=org_id
            )
            
            # Notify user about membership
            await self.notification_service.notify_user(
                user_id,
                f"You've been added to an organization with role: {role}"
            )
            
            await self.create_audit_log(
                event_type="membership.created",
                user_id=user_id,
                details={
                    "org_id": org_id,
                    "role": role
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle membership.created", error=str(e))
            raise
    
    async def handle_membership_updated(self, data: Dict[str, Any]):
        """
        Handle organizationMembership.updated webhook event
        """
        try:
            user_id = data.get("user_id")
            org_id = data.get("organization_id")
            role = data.get("role")
            
            logger.info(
                "Processing membership.updated event",
                user_id=user_id,
                org_id=org_id
            )
            
            # Notify user about role change
            await self.notification_service.notify_user(
                user_id,
                f"Your organization role has been updated to: {role}"
            )
            
            await self.create_audit_log(
                event_type="membership.updated",
                user_id=user_id,
                details={
                    "org_id": org_id,
                    "new_role": role
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle membership.updated", error=str(e))
            raise
    
    async def handle_membership_deleted(self, data: Dict[str, Any]):
        """
        Handle organizationMembership.deleted webhook event
        """
        try:
            user_id = data.get("user_id")
            org_id = data.get("organization_id")
            
            logger.info(
                "Processing membership.deleted event",
                user_id=user_id,
                org_id=org_id
            )
            
            # Notify user about removal
            await self.notification_service.notify_user(
                user_id,
                "You've been removed from an organization"
            )
            
            await self.create_audit_log(
                event_type="membership.deleted",
                user_id=user_id,
                details={"org_id": org_id}
            )
        
        except Exception as e:
            logger.error("Failed to handle membership.deleted", error=str(e))
            raise
    
    async def handle_invitation_created(self, data: Dict[str, Any]):
        """
        Handle organizationInvitation.created webhook event
        """
        try:
            email = data.get("email_address")
            org_id = data.get("organization_id")
            
            logger.info(
                "Processing invitation.created event",
                email=email,
                org_id=org_id
            )
            
            # Send invitation email (if not handled by Clerk)
            if email and settings.SMTP_HOST:
                await self.email_service.send_invitation_email(email, data)
            
            await self.create_audit_log(
                event_type="invitation.created",
                details={
                    "email": email,
                    "org_id": org_id
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle invitation.created", error=str(e))
            raise
    
    async def handle_invitation_accepted(self, data: Dict[str, Any]):
        """
        Handle organizationInvitation.accepted webhook event
        """
        try:
            email = data.get("email_address")
            org_id = data.get("organization_id")
            
            logger.info(
                "Processing invitation.accepted event",
                email=email,
                org_id=org_id
            )
            
            await self.create_audit_log(
                event_type="invitation.accepted",
                details={
                    "email": email,
                    "org_id": org_id,
                    "accepted_at": datetime.utcnow().isoformat()
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle invitation.accepted", error=str(e))
            raise
    
    async def handle_invitation_revoked(self, data: Dict[str, Any]):
        """
        Handle organizationInvitation.revoked webhook event
        """
        try:
            email = data.get("email_address")
            org_id = data.get("organization_id")
            
            logger.info(
                "Processing invitation.revoked event",
                email=email,
                org_id=org_id
            )
            
            await self.create_audit_log(
                event_type="invitation.revoked",
                details={
                    "email": email,
                    "org_id": org_id,
                    "revoked_at": datetime.utcnow().isoformat()
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle invitation.revoked", error=str(e))
            raise
    
    async def handle_email_created(self, data: Dict[str, Any]):
        """
        Handle email.created webhook event
        """
        try:
            email_id = data.get("id")
            to_email = data.get("to_email_address")
            
            logger.info("Processing email.created event", email_id=email_id)
            
            await self.create_audit_log(
                event_type="email.created",
                details={
                    "email_id": email_id,
                    "to": to_email,
                    "status": data.get("status")
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle email.created", error=str(e))
            raise
    
    async def handle_sms_created(self, data: Dict[str, Any]):
        """
        Handle sms.created webhook event
        """
        try:
            sms_id = data.get("id")
            phone_number = data.get("phone_number")
            
            logger.info("Processing sms.created event", sms_id=sms_id)
            
            await self.create_audit_log(
                event_type="sms.created",
                details={
                    "sms_id": sms_id,
                    "phone": phone_number,
                    "status": data.get("status")
                }
            )
        
        except Exception as e:
            logger.error("Failed to handle sms.created", error=str(e))
            raise
    
    async def create_audit_log(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Create an audit log entry
        """
        try:
            audit_log = AuditLog(
                event_type=event_type,
                user_id=user_id,
                details=json.dumps(details or {}),
                created_at=datetime.utcnow()
            )
            
            self.db.add(audit_log)
            await self.db.commit()
            
            logger.debug("Audit log created", event_type=event_type)
        
        except Exception as e:
            logger.error("Failed to create audit log", error=str(e))
            await self.db.rollback()
    
    async def list_webhook_events(
        self,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List webhook events with filtering
        """
        try:
            query = select(WebhookEvent)
            
            if status:
                query = query.where(WebhookEvent.status == status)
            if event_type:
                query = query.where(WebhookEvent.event_type == event_type)
            
            query = query.order_by(WebhookEvent.received_at.desc())
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            events = result.scalars().all()
            
            return [
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "status": event.status,
                    "received_at": event.received_at.isoformat(),
                    "error": event.error
                }
                for event in events
            ]
        
        except Exception as e:
            logger.error("Failed to list webhook events", error=str(e))
            return []
    
    async def get_webhook_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific webhook event
        """
        try:
            query = select(WebhookEvent).where(WebhookEvent.event_id == event_id)
            result = await self.db.execute(query)
            event = result.scalar_one_or_none()
            
            if event:
                return {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "payload": json.loads(event.payload),
                    "status": event.status,
                    "received_at": event.received_at.isoformat(),
                    "error": event.error
                }
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get webhook event {event_id}", error=str(e))
            return None
    
    async def process_webhook_retry(
        self,
        event_id: str,
        event_type: str,
        event_data: Dict[str, Any]
    ):
        """
        Retry processing a failed webhook event
        """
        try:
            # Process based on event type
            handler_map = {
                "user.created": self.handle_user_created,
                "user.updated": self.handle_user_updated,
                "user.deleted": self.handle_user_deleted,
                "session.created": self.handle_session_created,
                "session.ended": self.handle_session_ended,
                "session.removed": self.handle_session_removed,
                "organization.created": self.handle_organization_created,
                "organization.updated": self.handle_organization_updated,
                "organization.deleted": self.handle_organization_deleted,
                "organizationMembership.created": self.handle_membership_created,
                "organizationMembership.updated": self.handle_membership_updated,
                "organizationMembership.deleted": self.handle_membership_deleted,
                "organizationInvitation.created": self.handle_invitation_created,
                "organizationInvitation.accepted": self.handle_invitation_accepted,
                "organizationInvitation.revoked": self.handle_invitation_revoked,
                "email.created": self.handle_email_created,
                "sms.created": self.handle_sms_created
            }
            
            handler = handler_map.get(event_type)
            if handler:
                await handler(event_data)
                
                # Update event status
                query = update(WebhookEvent).where(
                    WebhookEvent.event_id == event_id
                ).values(status="processed", error=None)
                
                await self.db.execute(query)
                await self.db.commit()
                
                logger.info("Webhook retry successful", event_id=event_id)
            else:
                logger.warning(f"No handler for event type: {event_type}")
        
        except Exception as e:
            logger.error(f"Webhook retry failed", event_id=event_id, error=str(e))
            
            # Update event with error
            query = update(WebhookEvent).where(
                WebhookEvent.event_id == event_id
            ).values(error=str(e))
            
            await self.db.execute(query)
            await self.db.commit()