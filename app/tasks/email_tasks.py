from celery import shared_task
from typing import Dict, Any, List
import structlog

from app.services.email_service import EmailService

logger = structlog.get_logger()


@shared_task(bind=True, max_retries=3)
def send_welcome_email(self, email: str, user_data: Dict[str, Any]):
    """
    Send welcome email to new user
    """
    try:
        import asyncio
        email_service = EmailService()
        result = asyncio.run(email_service.send_welcome_email(email, user_data))
        
        if result:
            logger.info(f"Welcome email sent to {email}")
        else:
            raise Exception("Failed to send email")
        
        return {"status": "sent", "email": email}
    
    except Exception as e:
        logger.error(f"Failed to send welcome email: {str(e)}")
        # Retry with exponential backoff
        self.retry(countdown=2 ** self.request.retries)


@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, email: str, reset_token: str):
    """
    Send password reset email
    """
    try:
        import asyncio
        email_service = EmailService()
        result = asyncio.run(email_service.send_password_reset_email(email, reset_token))
        
        if result:
            logger.info(f"Password reset email sent to {email}")
        else:
            raise Exception("Failed to send email")
        
        return {"status": "sent", "email": email}
    
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        self.retry(countdown=2 ** self.request.retries)


@shared_task(bind=True, max_retries=3)
def send_verification_email(self, email: str, verification_code: str):
    """
    Send email verification code
    """
    try:
        import asyncio
        email_service = EmailService()
        result = asyncio.run(email_service.send_verification_email(email, verification_code))
        
        if result:
            logger.info(f"Verification email sent to {email}")
        else:
            raise Exception("Failed to send email")
        
        return {"status": "sent", "email": email}
    
    except Exception as e:
        logger.error(f"Failed to send verification email: {str(e)}")
        self.retry(countdown=2 ** self.request.retries)


@shared_task(bind=True, max_retries=3)
def send_invitation_email(self, email: str, invitation_data: Dict[str, Any]):
    """
    Send organization invitation email
    """
    try:
        import asyncio
        email_service = EmailService()
        result = asyncio.run(email_service.send_invitation_email(email, invitation_data))
        
        if result:
            logger.info(f"Invitation email sent to {email}")
        else:
            raise Exception("Failed to send email")
        
        return {"status": "sent", "email": email}
    
    except Exception as e:
        logger.error(f"Failed to send invitation email: {str(e)}")
        self.retry(countdown=2 ** self.request.retries)


@shared_task(bind=True, max_retries=3)
def send_mfa_code_email(self, email: str, mfa_code: str):
    """
    Send MFA code via email
    """
    try:
        import asyncio
        email_service = EmailService()
        result = asyncio.run(email_service.send_mfa_code_email(email, mfa_code))
        
        if result:
            logger.info(f"MFA code email sent to {email}")
        else:
            raise Exception("Failed to send email")
        
        return {"status": "sent", "email": email}
    
    except Exception as e:
        logger.error(f"Failed to send MFA code email: {str(e)}")
        self.retry(countdown=2 ** self.request.retries)


@shared_task
def send_bulk_email(
    recipients: List[str],
    subject: str,
    body_html: str,
    body_text: str = None
):
    """
    Send bulk email to multiple recipients
    """
    try:
        email_service = EmailService()
        sent_count = 0
        failed_count = 0
        
        for email in recipients:
            try:
                result = email_service.send_email(
                    email,
                    subject,
                    body_html,
                    body_text
                )
                if result:
                    sent_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                logger.error(f"Failed to send to {email}: {str(e)}")
                failed_count += 1
        
        logger.info(f"Bulk email completed: {sent_count} sent, {failed_count} failed")
        
        return {
            "status": "completed",
            "sent": sent_count,
            "failed": failed_count,
            "total": len(recipients)
        }
    
    except Exception as e:
        logger.error(f"Bulk email task failed: {str(e)}")
        return {
            "status": "failed",
            "error": str(e)
        }


@shared_task
def send_security_alert(user_id: str, alert_type: str, details: Dict[str, Any]):
    """
    Send security alert to user
    """
    try:
        # Get user email from Clerk
        # This would require Clerk client initialization
        
        email_service = EmailService()
        
        subject = f"Security Alert: {alert_type}"
        body_html = f"""
        <html>
        <body>
            <h2>Security Alert</h2>
            <p>We detected unusual activity on your account:</p>
            <p><strong>{alert_type}</strong></p>
            <p>Details: {details}</p>
            <p>If this wasn't you, please secure your account immediately.</p>
        </body>
        </html>
        """
        
        logger.info(f"Security alert sent for user {user_id}")
        
        return {"status": "sent", "user_id": user_id, "alert_type": alert_type}
    
    except Exception as e:
        logger.error(f"Failed to send security alert: {str(e)}")
        return {"status": "failed", "error": str(e)}


@shared_task
def send_magic_link_email(email: str, magic_link: str):
    """
    Send magic link for passwordless authentication
    """
    try:
        email_service = EmailService()
        
        subject = "Your Magic Sign-In Link"
        body_html = f"""
        <html>
        <body>
            <h2>Sign In to Your Account</h2>
            <p>Click the link below to sign in to your account:</p>
            <p><a href="{magic_link}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Sign In</a></p>
            <p>This link will expire in 15 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        
        result = email_service.send_email(email, subject, body_html)
        
        if result:
            logger.info(f"Magic link sent to {email}")
            return {"status": "sent", "email": email}
        else:
            raise Exception("Failed to send email")
    
    except Exception as e:
        logger.error(f"Failed to send magic link: {str(e)}")
        return {"status": "failed", "error": str(e)}