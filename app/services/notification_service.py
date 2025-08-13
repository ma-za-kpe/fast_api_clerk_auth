from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import structlog
import json

from app.db.models import Notification, UserProfile
from app.services.email_service import EmailService
from app.core.config import settings

logger = structlog.get_logger()


class NotificationService:
    """
    Service for managing user notifications
    """
    
    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db
        self.email_service = EmailService()
    
    async def notify_user(
        self,
        user_id: str,
        message: str,
        title: Optional[str] = None,
        type: str = "info",
        data: Optional[Dict[str, Any]] = None,
        send_email: bool = True
    ):
        """
        Send a notification to a user
        """
        try:
            if self.db:
                # Store notification in database
                notification = Notification(
                    user_id=user_id,
                    type=type,
                    title=title or "Notification",
                    message=message,
                    data=data,
                    created_at=datetime.utcnow()
                )
                
                self.db.add(notification)
                await self.db.commit()
                
                # Check user preferences for email notifications
                if send_email:
                    profile_query = select(UserProfile).where(
                        UserProfile.user_id == user_id
                    )
                    result = await self.db.execute(profile_query)
                    profile = result.scalar_one_or_none()
                    
                    if profile and profile.email_notifications_enabled:
                        # Send email notification
                        # Note: You'd need to fetch user email from Clerk
                        pass
            
            logger.info(
                "Notification sent",
                user_id=user_id,
                type=type,
                title=title
            )
        
        except Exception as e:
            logger.error(
                "Failed to send notification",
                user_id=user_id,
                error=str(e)
            )
            if self.db:
                await self.db.rollback()
    
    async def notify_admins(
        self,
        message: str,
        title: Optional[str] = None,
        type: str = "admin",
        data: Optional[Dict[str, Any]] = None
    ):
        """
        Send a notification to all admins
        """
        try:
            # In a real implementation, you would:
            # 1. Query Clerk for users with admin role
            # 2. Send notifications to each admin
            
            logger.info(
                "Admin notification sent",
                type=type,
                title=title
            )
        
        except Exception as e:
            logger.error(
                "Failed to send admin notification",
                error=str(e)
            )
    
    async def get_user_notifications(
        self,
        user_id: str,
        limit: int = 20,
        offset: int = 0,
        unread_only: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get notifications for a user
        """
        try:
            if not self.db:
                return []
            
            query = select(Notification).where(
                Notification.user_id == user_id
            )
            
            if unread_only:
                query = query.where(Notification.is_read == False)
            
            query = query.order_by(Notification.created_at.desc())
            query = query.limit(limit).offset(offset)
            
            result = await self.db.execute(query)
            notifications = result.scalars().all()
            
            return [
                {
                    "id": n.id,
                    "type": n.type,
                    "title": n.title,
                    "message": n.message,
                    "data": n.data,
                    "is_read": n.is_read,
                    "created_at": n.created_at.isoformat(),
                    "read_at": n.read_at.isoformat() if n.read_at else None
                }
                for n in notifications
            ]
        
        except Exception as e:
            logger.error(
                "Failed to get user notifications",
                user_id=user_id,
                error=str(e)
            )
            return []
    
    async def mark_notification_read(
        self,
        notification_id: int,
        user_id: str
    ) -> bool:
        """
        Mark a notification as read
        """
        try:
            if not self.db:
                return False
            
            query = update(Notification).where(
                Notification.id == notification_id,
                Notification.user_id == user_id
            ).values(
                is_read=True,
                read_at=datetime.utcnow()
            )
            
            result = await self.db.execute(query)
            await self.db.commit()
            
            return result.rowcount > 0
        
        except Exception as e:
            logger.error(
                "Failed to mark notification as read",
                notification_id=notification_id,
                error=str(e)
            )
            await self.db.rollback()
            return False
    
    async def mark_all_read(self, user_id: str) -> int:
        """
        Mark all notifications as read for a user
        """
        try:
            if not self.db:
                return 0
            
            query = update(Notification).where(
                Notification.user_id == user_id,
                Notification.is_read == False
            ).values(
                is_read=True,
                read_at=datetime.utcnow()
            )
            
            result = await self.db.execute(query)
            await self.db.commit()
            
            return result.rowcount
        
        except Exception as e:
            logger.error(
                "Failed to mark all notifications as read",
                user_id=user_id,
                error=str(e)
            )
            await self.db.rollback()
            return 0
    
    async def delete_notification(
        self,
        notification_id: int,
        user_id: str
    ) -> bool:
        """
        Delete a notification
        """
        try:
            if not self.db:
                return False
            
            notification = await self.db.get(Notification, notification_id)
            
            if notification and notification.user_id == user_id:
                await self.db.delete(notification)
                await self.db.commit()
                return True
            
            return False
        
        except Exception as e:
            logger.error(
                "Failed to delete notification",
                notification_id=notification_id,
                error=str(e)
            )
            await self.db.rollback()
            return False
    
    async def get_unread_count(self, user_id: str) -> int:
        """
        Get count of unread notifications for a user
        """
        try:
            if not self.db:
                return 0
            
            query = select(Notification).where(
                Notification.user_id == user_id,
                Notification.is_read == False
            )
            
            result = await self.db.execute(query)
            notifications = result.scalars().all()
            
            return len(notifications)
        
        except Exception as e:
            logger.error(
                "Failed to get unread count",
                user_id=user_id,
                error=str(e)
            )
            return 0
    
    async def create_system_notification(
        self,
        user_id: str,
        event_type: str,
        data: Dict[str, Any]
    ):
        """
        Create a system notification based on event type
        """
        notification_templates = {
            "user.email_verified": {
                "title": "Email Verified",
                "message": "Your email address has been successfully verified.",
                "type": "success"
            },
            "user.phone_verified": {
                "title": "Phone Verified",
                "message": "Your phone number has been successfully verified.",
                "type": "success"
            },
            "user.mfa_enabled": {
                "title": "Two-Factor Authentication Enabled",
                "message": "Your account is now protected with two-factor authentication.",
                "type": "security"
            },
            "user.password_changed": {
                "title": "Password Changed",
                "message": "Your password has been successfully changed.",
                "type": "security"
            },
            "organization.invite_received": {
                "title": "Organization Invitation",
                "message": f"You've been invited to join {data.get('org_name', 'an organization')}.",
                "type": "info"
            },
            "organization.role_changed": {
                "title": "Role Updated",
                "message": f"Your role has been changed to {data.get('new_role', 'member')}.",
                "type": "info"
            },
            "session.suspicious_activity": {
                "title": "Suspicious Activity Detected",
                "message": "We detected an unusual login attempt. Please review your account activity.",
                "type": "warning"
            },
            "account.locked": {
                "title": "Account Locked",
                "message": "Your account has been temporarily locked due to multiple failed login attempts.",
                "type": "error"
            }
        }
        
        template = notification_templates.get(event_type)
        
        if template:
            await self.notify_user(
                user_id=user_id,
                title=template["title"],
                message=template["message"],
                type=template["type"],
                data=data
            )