from typing import Dict, Any, List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import aiosmtplib
from jinja2 import Template, Environment, FileSystemLoader
import structlog
from pathlib import Path
import os

from app.core.config import settings

logger = structlog.get_logger()


class EmailService:
    """
    Service for sending emails with templates
    """
    
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
        
        # Setup Jinja2 for email templates
        template_dir = Path(__file__).parent.parent / "templates" / "emails"
        if template_dir.exists():
            self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        else:
            self.env = None
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        body_html: str,
        body_text: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None
    ) -> bool:
        """
        Send an email asynchronously
        """
        if not self.smtp_host:
            logger.warning("SMTP not configured, skipping email send")
            return False
        
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.from_email
            message["To"] = to_email
            
            if cc:
                message["Cc"] = ", ".join(cc)
            if bcc:
                message["Bcc"] = ", ".join(bcc)
            
            # Add text part
            if body_text:
                text_part = MIMEText(body_text, "plain")
                message.attach(text_part)
            
            # Add HTML part
            html_part = MIMEText(body_html, "html")
            message.attach(html_part)
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    self._attach_file(message, attachment)
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}", error=str(e))
            return False
    
    def _attach_file(self, message: MIMEMultipart, attachment: Dict[str, Any]):
        """
        Attach a file to the email
        """
        try:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment["content"])
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {attachment['filename']}"
            )
            message.attach(part)
        except Exception as e:
            logger.error(f"Failed to attach file", error=str(e))
    
    async def send_welcome_email(self, to_email: str, user_data: Dict[str, Any]) -> bool:
        """
        Send welcome email to new user
        """
        subject = f"Welcome to {getattr(settings, 'PLATFORM_NAME', settings.ENVIRONMENT.title())} Platform!"
        
        template_data = {
            "first_name": user_data.get("first_name"),
            "email": to_email,
            "frontend_url": settings.FRONTEND_URL,
            "platform_name": getattr(settings, 'PLATFORM_NAME', settings.ENVIRONMENT.title()),
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "current_year": "2024"
        }
        
        if self.env:
            # Use template files
            html_template = self.env.get_template('welcome.html')
            html_body = html_template.render(**template_data)
            
            try:
                text_template = self.env.get_template('welcome.txt')
                text_body = text_template.render(**template_data)
            except:
                text_body = None
        else:
            # Fallback to inline template
            html_body = f"""
            <h1>Welcome to {template_data['platform_name']}!</h1>
            <p>Hi {template_data['first_name'] or 'there'}!</p>
            <p>Thank you for joining us. Your account has been successfully created.</p>
            <p><a href="{template_data['frontend_url']}/dashboard">Go to Dashboard</a></p>
            """
            text_body = f"Welcome to {template_data['platform_name']}! Visit: {template_data['frontend_url']}/dashboard"
        
        return await self.send_email(to_email, subject, html_body, text_body)
    
    async def send_password_reset_email(self, to_email: str, reset_token: str) -> bool:
        """
        Send password reset email
        """
        subject = "Password Reset Request"
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        
        template_data = {
            "reset_url": reset_url,
            "frontend_url": settings.FRONTEND_URL,
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "current_year": "2024"
        }
        
        if self.env:
            # Use template file
            html_template = self.env.get_template('password_reset.html')
            html_body = html_template.render(**template_data)
        else:
            # Fallback to inline template
            html_body = f"""
            <h1>Password Reset Request</h1>
            <p>Click here to reset your password: <a href="{reset_url}">Reset Password</a></p>
            <p>This link expires in 1 hour.</p>
            """
        
        return await self.send_email(to_email, subject, html_body)
    
    async def send_invitation_email(
        self,
        to_email: str,
        invitation_data: Dict[str, Any]
    ) -> bool:
        """
        Send organization invitation email
        """
        org_name = invitation_data.get("organization_name", "Our Organization")
        inviter_name = invitation_data.get("inviter_name", "Team Admin")
        accept_url = invitation_data.get("accept_url", f"{settings.FRONTEND_URL}/accept-invitation")
        
        subject = f"You're invited to join {org_name}"
        
        template_data = {
            "org_name": org_name,
            "inviter_name": inviter_name,
            "accept_url": accept_url,
            "email": to_email,
            "role": invitation_data.get("role"),
            "invitation_date": invitation_data.get("invitation_date"),
            "frontend_url": settings.FRONTEND_URL,
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "current_year": "2024"
        }
        
        if self.env:
            # Use template file
            html_template = self.env.get_template('invitation.html')
            html_body = html_template.render(**template_data)
        else:
            # Fallback to inline template
            html_body = f"""
            <h1>You're invited to join {org_name}!</h1>
            <p>{inviter_name} has invited you to join {org_name}.</p>
            <p><a href="{accept_url}">Accept Invitation</a></p>
            """
        
        return await self.send_email(to_email, subject, html_body)
    
    async def send_verification_email(self, to_email: str, verification_code: str) -> bool:
        """
        Send email verification code
        """
        subject = "Verify Your Email Address"
        
        template_data = {
            "code": verification_code,
            "email": to_email,
            "frontend_url": settings.FRONTEND_URL,
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "current_year": "2024"
        }
        
        if self.env:
            # Use template file
            html_template = self.env.get_template('verification_code.html')
            html_body = html_template.render(**template_data)
        else:
            # Fallback to inline template
            html_body = f"""
            <h1>Verify Your Email</h1>
            <p>Your verification code is: <strong>{verification_code}</strong></p>
            <p>This code expires in 15 minutes.</p>
            """
        
        return await self.send_email(to_email, subject, html_body)
    
    async def send_mfa_code_email(
        self, 
        to_email: str, 
        mfa_code: str, 
        user_agent: Optional[str] = None, 
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Send MFA code via email
        """
        subject = "Your Two-Factor Authentication Code"
        
        template_data = {
            "code": mfa_code,
            "email": to_email,
            "user_agent": user_agent,
            "ip_address": ip_address,
            "frontend_url": settings.FRONTEND_URL,
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "current_year": "2024"
        }
        
        if self.env:
            # Use template file
            html_template = self.env.get_template('mfa_code.html')
            html_body = html_template.render(**template_data)
        else:
            # Fallback to inline template
            html_body = f"""
            <h1>Two-Factor Authentication</h1>
            <p>Your authentication code is: <strong style="font-size: 24px; letter-spacing: 4px;">{mfa_code}</strong></p>
            <p>This code expires in 5 minutes.</p>
            <p>If you didn't attempt to log in, please secure your account immediately.</p>
            """
        
        return await self.send_email(to_email, subject, html_body)
    
    async def send_security_alert(
        self, 
        to_email: str, 
        alert_data: Dict[str, Any]
    ) -> bool:
        """
        Send security alert email
        """
        alert_type = alert_data.get("alert_type", "Suspicious Activity")
        subject = f"Security Alert: {alert_type}"
        
        template_data = {
            "alert_type": alert_type,
            "alert_description": alert_data.get("description", "Suspicious activity detected"),
            "incident_time": alert_data.get("incident_time"),
            "location": alert_data.get("location"),
            "user_agent": alert_data.get("user_agent"),
            "ip_address": alert_data.get("ip_address"),
            "recommended_actions": alert_data.get("recommended_actions", [
                "Change your password immediately",
                "Review recent account activity", 
                "Enable two-factor authentication",
                "Contact support if you didn't perform this action"
            ]),
            "was_you": alert_data.get("was_you", False),
            "first_name": alert_data.get("first_name"),
            "email": to_email,
            "frontend_url": settings.FRONTEND_URL,
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "company_domain": getattr(settings, 'COMPANY_DOMAIN', 'yourcompany.com'),
            "current_year": "2024"
        }
        
        if self.env:
            html_template = self.env.get_template('security_alert.html')
            html_body = html_template.render(**template_data)
        else:
            html_body = f"""
            <h1>Security Alert: {alert_type}</h1>
            <p><strong>Alert:</strong> {template_data['alert_description']}</p>
            <p>If this wasn't you, please secure your account immediately.</p>
            """
        
        return await self.send_email(to_email, subject, html_body)
    
    async def send_template_email(
        self,
        template_name: str,
        to_email: str,
        subject: str,
        template_data: Dict[str, Any],
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        Generic method to send any template-based email
        """
        # Add common template data
        common_data = {
            "email": to_email,
            "frontend_url": settings.FRONTEND_URL,
            "company_name": getattr(settings, 'COMPANY_NAME', 'Your Company'),
            "company_domain": getattr(settings, 'COMPANY_DOMAIN', 'yourcompany.com'),
            "current_year": "2024",
            "subject": subject,
            **template_data
        }
        
        if self.env:
            try:
                html_template = self.env.get_template(f'{template_name}.html')
                html_body = html_template.render(**common_data)
                
                # Try to get text version
                text_body = None
                try:
                    text_template = self.env.get_template(f'{template_name}.txt')
                    text_body = text_template.render(**common_data)
                except:
                    pass
                
                return await self.send_email(
                    to_email, 
                    subject, 
                    html_body, 
                    text_body, 
                    attachments
                )
            except Exception as e:
                logger.error(f"Failed to render template {template_name}: {str(e)}")
                return False
        else:
            logger.warning(f"Template environment not available, cannot send {template_name} email")
            return False


# Create global email service instance
email_service = EmailService()