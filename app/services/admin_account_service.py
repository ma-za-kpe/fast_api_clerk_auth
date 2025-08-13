from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets
import structlog
from enum import Enum

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthorizationError
from app.services.cache_service import cache_service
from app.services.email_service import EmailService
from app.services.password_validator import password_validator
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class AccountCreationType(Enum):
    ADMIN_CREATED = "admin_created"
    SELF_REGISTERED = "self_registered"
    INVITATION = "invitation"
    SSO = "sso"


class AdminAccountService:
    """
    Service for admin-created user accounts
    """
    
    def __init__(self):
        self.email_service = EmailService()
        self.temp_password_expiry_hours = 24
        self.onboarding_link_expiry_days = 7
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def create_user_account(
        self,
        admin_id: str,
        email: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
        phone_number: Optional[str] = None,
        organization_id: Optional[str] = None,
        role: str = "member",
        send_welcome_email: bool = True,
        require_password_change: bool = True,
        generate_temp_password: bool = True,
        custom_password: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a new user account as an admin
        """
        try:
            # Validate admin permissions
            if not await self._validate_admin_permissions(admin_id, organization_id):
                raise AuthorizationError("Insufficient permissions to create accounts")
            
            # Check if user already exists
            clerk_client = await self._get_clerk_client()
            existing_users = await clerk_client.list_users(email_address=[email])
            
            if existing_users:
                raise ValidationError(f"User with email {email} already exists")
            
            # Generate or validate password
            if generate_temp_password:
                temp_password = self._generate_secure_password()
                password_is_temporary = True
            elif custom_password:
                # Validate custom password
                is_valid, errors = password_validator.validate_password(
                    custom_password,
                    email=email
                )
                if not is_valid:
                    raise ValidationError(f"Password validation failed: {', '.join(errors)}")
                temp_password = custom_password
                password_is_temporary = False
            else:
                # No password method - user will set up during onboarding
                temp_password = None
                password_is_temporary = False
            
            # Create user data
            user_data = {
                "email_address": [email],
                "first_name": first_name,
                "last_name": last_name,
                "username": username,
                "phone_number": [phone_number] if phone_number else None,
                "password": temp_password,
                "skip_password_checks": True,  # We've already validated
                "public_metadata": {
                    "created_by": "admin",
                    "admin_id": admin_id,
                    "creation_type": AccountCreationType.ADMIN_CREATED.value,
                    "created_at": datetime.utcnow().isoformat()
                },
                "private_metadata": metadata or {},
                "unsafe_metadata": {
                    "require_password_change": require_password_change and password_is_temporary,
                    "password_is_temporary": password_is_temporary,
                    "onboarding_required": True
                }
            }
            
            # Remove None values
            user_data = {k: v for k, v in user_data.items() if v is not None}
            
            # Create user in Clerk
            user = await clerk_client.create_user(**user_data)
            
            # Add to organization if specified
            if organization_id:
                await clerk_client.create_organization_membership(
                    organization_id=organization_id,
                    user_id=user.id,
                    role=role
                )
            
            # Generate onboarding token
            onboarding_token = secrets.token_urlsafe(32)
            onboarding_data = {
                "user_id": user.id,
                "email": email,
                "admin_id": admin_id,
                "require_password_change": require_password_change and password_is_temporary,
                "organization_id": organization_id,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(days=self.onboarding_link_expiry_days)).isoformat()
            }
            
            # Store onboarding data
            onboarding_key = f"onboarding:{onboarding_token}"
            await cache_service.set(
                onboarding_key,
                onboarding_data,
                expire=self.onboarding_link_expiry_days * 86400
            )
            
            # Store temporary password if generated
            if temp_password and password_is_temporary:
                temp_pass_key = f"temp_password:{user.id}"
                await cache_service.set(
                    temp_pass_key,
                    {
                        "password": temp_password,
                        "created_at": datetime.utcnow().isoformat(),
                        "expires_at": (datetime.utcnow() + timedelta(hours=self.temp_password_expiry_hours)).isoformat(),
                        "used": False
                    },
                    expire=self.temp_password_expiry_hours * 3600
                )
            
            # Send welcome email
            if send_welcome_email:
                await self._send_admin_created_welcome_email(
                    email=email,
                    user_id=user.id,
                    first_name=first_name,
                    temp_password=temp_password if password_is_temporary else None,
                    onboarding_token=onboarding_token,
                    organization_name=await self._get_organization_name(organization_id) if organization_id else None
                )
            
            # Log account creation
            await self._log_account_creation(
                admin_id=admin_id,
                user_id=user.id,
                email=email,
                organization_id=organization_id
            )
            
            logger.info(
                f"Admin created user account",
                admin_id=admin_id,
                user_id=user.id,
                email=email,
                organization_id=organization_id
            )
            
            return {
                "user_id": user.id,
                "email": email,
                "username": username,
                "temporary_password": temp_password if password_is_temporary and not send_welcome_email else None,
                "onboarding_url": self._generate_onboarding_url(onboarding_token),
                "password_expires_at": (datetime.utcnow() + timedelta(hours=self.temp_password_expiry_hours)).isoformat() if password_is_temporary else None,
                "require_password_change": require_password_change and password_is_temporary,
                "organization_id": organization_id,
                "created_by": admin_id,
                "welcome_email_sent": send_welcome_email
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to create admin account: {str(e)}")
            raise ValidationError("Failed to create user account")
    
    async def create_bulk_accounts(
        self,
        admin_id: str,
        accounts: List[Dict[str, Any]],
        organization_id: Optional[str] = None,
        default_role: str = "member",
        send_welcome_emails: bool = True
    ) -> Dict[str, Any]:
        """
        Create multiple user accounts in bulk
        """
        try:
            # Validate admin permissions
            if not await self._validate_admin_permissions(admin_id, organization_id):
                raise AuthorizationError("Insufficient permissions for bulk account creation")
            
            # Limit bulk creation
            max_bulk_accounts = 100
            if len(accounts) > max_bulk_accounts:
                raise ValidationError(f"Maximum {max_bulk_accounts} accounts can be created at once")
            
            successful = []
            failed = []
            
            for account_data in accounts:
                try:
                    # Extract account details
                    email = account_data.get("email")
                    if not email:
                        raise ValidationError("Email is required")
                    
                    result = await self.create_user_account(
                        admin_id=admin_id,
                        email=email,
                        first_name=account_data.get("first_name"),
                        last_name=account_data.get("last_name"),
                        username=account_data.get("username"),
                        phone_number=account_data.get("phone_number"),
                        organization_id=organization_id or account_data.get("organization_id"),
                        role=account_data.get("role", default_role),
                        send_welcome_email=send_welcome_emails,
                        metadata=account_data.get("metadata")
                    )
                    
                    successful.append({
                        "email": email,
                        "user_id": result["user_id"],
                        "onboarding_url": result["onboarding_url"]
                    })
                
                except Exception as e:
                    failed.append({
                        "email": account_data.get("email", "unknown"),
                        "error": str(e)
                    })
            
            logger.info(
                f"Bulk account creation completed",
                admin_id=admin_id,
                successful_count=len(successful),
                failed_count=len(failed)
            )
            
            return {
                "successful": successful,
                "failed": failed,
                "total_processed": len(accounts),
                "success_count": len(successful),
                "failure_count": len(failed)
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed bulk account creation: {str(e)}")
            raise ValidationError("Failed to create bulk accounts")
    
    async def reset_user_password(
        self,
        admin_id: str,
        user_id: str,
        new_password: Optional[str] = None,
        generate_temp: bool = True,
        send_notification: bool = True
    ) -> Dict[str, Any]:
        """
        Admin reset of user password
        """
        try:
            # Validate admin permissions
            if not await self._validate_admin_permissions(admin_id):
                raise AuthorizationError("Insufficient permissions to reset passwords")
            
            # Get user details
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise ValidationError("User not found")
            
            # Generate or validate new password
            if generate_temp:
                new_password = self._generate_secure_password()
                is_temporary = True
            elif new_password:
                # Validate provided password
                email = user.email_addresses[0].email_address if user.email_addresses else None
                is_valid, errors = password_validator.validate_password(
                    new_password,
                    email=email
                )
                if not is_valid:
                    raise ValidationError(f"Password validation failed: {', '.join(errors)}")
                is_temporary = False
            else:
                raise ValidationError("Password must be provided or generated")
            
            # Update user password in Clerk
            await clerk_client.update_user(
                user_id,
                password=new_password,
                skip_password_checks=True
            )
            
            # Update user metadata to require password change
            if is_temporary:
                await clerk_client.update_user(
                    user_id,
                    unsafe_metadata={
                        "require_password_change": True,
                        "password_reset_by_admin": admin_id,
                        "password_reset_at": datetime.utcnow().isoformat()
                    }
                )
            
            # Store temporary password details
            if is_temporary:
                temp_pass_key = f"admin_reset_password:{user_id}"
                await cache_service.set(
                    temp_pass_key,
                    {
                        "admin_id": admin_id,
                        "reset_at": datetime.utcnow().isoformat(),
                        "expires_at": (datetime.utcnow() + timedelta(hours=self.temp_password_expiry_hours)).isoformat()
                    },
                    expire=self.temp_password_expiry_hours * 3600
                )
            
            # Send notification
            if send_notification and user.email_addresses:
                email = user.email_addresses[0].email_address
                await self._send_password_reset_notification(
                    email=email,
                    user_id=user_id,
                    temp_password=new_password if is_temporary else None,
                    admin_id=admin_id
                )
            
            # Log password reset
            await self._log_password_reset(
                admin_id=admin_id,
                user_id=user_id,
                is_temporary=is_temporary
            )
            
            logger.info(
                f"Admin reset user password",
                admin_id=admin_id,
                user_id=user_id,
                is_temporary=is_temporary
            )
            
            return {
                "user_id": user_id,
                "password_reset": True,
                "temporary_password": new_password if is_temporary and not send_notification else None,
                "is_temporary": is_temporary,
                "expires_at": (datetime.utcnow() + timedelta(hours=self.temp_password_expiry_hours)).isoformat() if is_temporary else None,
                "notification_sent": send_notification,
                "reset_by": admin_id
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to reset user password: {str(e)}")
            raise ValidationError("Failed to reset password")
    
    async def suspend_user_account(
        self,
        admin_id: str,
        user_id: str,
        reason: str,
        duration_hours: Optional[int] = None,
        notify_user: bool = True
    ) -> Dict[str, Any]:
        """
        Suspend a user account
        """
        try:
            # Validate admin permissions
            if not await self._validate_admin_permissions(admin_id):
                raise AuthorizationError("Insufficient permissions to suspend accounts")
            
            # Get user details
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise ValidationError("User not found")
            
            # Calculate suspension end time
            suspension_end = None
            if duration_hours:
                suspension_end = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
            
            # Update user to suspended state
            await clerk_client.update_user(
                user_id,
                banned=True,
                public_metadata={
                    **user.public_metadata,
                    "suspended": True,
                    "suspended_by": admin_id,
                    "suspended_at": datetime.utcnow().isoformat(),
                    "suspension_reason": reason,
                    "suspension_end": suspension_end
                }
            )
            
            # Store suspension details
            suspension_key = f"suspension:{user_id}"
            suspension_data = {
                "user_id": user_id,
                "admin_id": admin_id,
                "reason": reason,
                "suspended_at": datetime.utcnow().isoformat(),
                "suspension_end": suspension_end,
                "duration_hours": duration_hours
            }
            
            if duration_hours:
                await cache_service.set(
                    suspension_key,
                    suspension_data,
                    expire=duration_hours * 3600
                )
            else:
                await cache_service.set(suspension_key, suspension_data)
            
            # Revoke all active sessions
            await self._revoke_user_sessions(user_id)
            
            # Send notification
            if notify_user and user.email_addresses:
                email = user.email_addresses[0].email_address
                await self._send_suspension_notification(
                    email=email,
                    user_id=user_id,
                    reason=reason,
                    duration_hours=duration_hours,
                    admin_id=admin_id
                )
            
            # Log suspension
            await self._log_account_suspension(
                admin_id=admin_id,
                user_id=user_id,
                reason=reason,
                duration_hours=duration_hours
            )
            
            logger.info(
                f"User account suspended",
                admin_id=admin_id,
                user_id=user_id,
                reason=reason,
                duration_hours=duration_hours
            )
            
            return {
                "user_id": user_id,
                "suspended": True,
                "reason": reason,
                "suspended_by": admin_id,
                "suspended_at": datetime.utcnow().isoformat(),
                "suspension_end": suspension_end,
                "duration_hours": duration_hours,
                "notification_sent": notify_user
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to suspend user account: {str(e)}")
            raise ValidationError("Failed to suspend account")
    
    async def unsuspend_user_account(
        self,
        admin_id: str,
        user_id: str,
        reason: str,
        notify_user: bool = True
    ) -> Dict[str, Any]:
        """
        Unsuspend a user account
        """
        try:
            # Validate admin permissions
            if not await self._validate_admin_permissions(admin_id):
                raise AuthorizationError("Insufficient permissions to unsuspend accounts")
            
            # Get user details
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if not user:
                raise ValidationError("User not found")
            
            # Update user to active state
            await clerk_client.update_user(
                user_id,
                banned=False,
                public_metadata={
                    **user.public_metadata,
                    "suspended": False,
                    "unsuspended_by": admin_id,
                    "unsuspended_at": datetime.utcnow().isoformat(),
                    "unsuspension_reason": reason
                }
            )
            
            # Remove suspension data
            suspension_key = f"suspension:{user_id}"
            await cache_service.delete(suspension_key)
            
            # Send notification
            if notify_user and user.email_addresses:
                email = user.email_addresses[0].email_address
                await self._send_unsuspension_notification(
                    email=email,
                    user_id=user_id,
                    reason=reason,
                    admin_id=admin_id
                )
            
            # Log unsuspension
            await self._log_account_unsuspension(
                admin_id=admin_id,
                user_id=user_id,
                reason=reason
            )
            
            logger.info(
                f"User account unsuspended",
                admin_id=admin_id,
                user_id=user_id,
                reason=reason
            )
            
            return {
                "user_id": user_id,
                "suspended": False,
                "unsuspended_by": admin_id,
                "unsuspended_at": datetime.utcnow().isoformat(),
                "reason": reason,
                "notification_sent": notify_user
            }
        
        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Failed to unsuspend user account: {str(e)}")
            raise ValidationError("Failed to unsuspend account")
    
    async def get_admin_created_accounts(
        self,
        admin_id: str,
        organization_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get list of accounts created by an admin
        """
        try:
            # Validate admin permissions
            if not await self._validate_admin_permissions(admin_id, organization_id):
                raise AuthorizationError("Insufficient permissions to view admin-created accounts")
            
            clerk_client = await self._get_clerk_client()
            
            # Query users with admin_created metadata
            users = await clerk_client.list_users(
                limit=limit,
                offset=offset,
                order_by="-created_at"
            )
            
            admin_created_users = []
            for user in users:
                public_metadata = user.public_metadata or {}
                if (public_metadata.get("created_by") == "admin" and 
                    public_metadata.get("admin_id") == admin_id):
                    
                    # Check organization membership if specified
                    if organization_id:
                        memberships = await clerk_client.list_organization_memberships(
                            user_id=user.id,
                            organization_id=organization_id
                        )
                        if not memberships:
                            continue
                    
                    admin_created_users.append({
                        "user_id": user.id,
                        "email": user.email_addresses[0].email_address if user.email_addresses else None,
                        "username": user.username,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "created_at": public_metadata.get("created_at"),
                        "creation_type": public_metadata.get("creation_type"),
                        "onboarding_complete": not user.unsafe_metadata.get("onboarding_required", False),
                        "suspended": public_metadata.get("suspended", False)
                    })
            
            return admin_created_users
        
        except AuthorizationError:
            raise
        except Exception as e:
            logger.error(f"Failed to get admin-created accounts: {str(e)}")
            return []
    
    # ============= Helper Methods =============
    
    async def _validate_admin_permissions(
        self,
        admin_id: str,
        organization_id: Optional[str] = None
    ) -> bool:
        """Validate if user has admin permissions"""
        try:
            clerk_client = await self._get_clerk_client()
            admin_user = await clerk_client.get_user(admin_id)
            
            if not admin_user:
                return False
            
            # Check if super admin
            if admin_user.public_metadata.get("is_super_admin"):
                return True
            
            # Check organization admin role
            if organization_id:
                memberships = await clerk_client.list_organization_memberships(
                    user_id=admin_id,
                    organization_id=organization_id
                )
                
                if memberships:
                    membership = memberships[0]
                    return membership.role in ["admin", "owner"]
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to validate admin permissions: {str(e)}")
            return False
    
    def _generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure temporary password"""
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Ensure password has at least one of each type
        while not (any(c.islower() for c in password) and
                   any(c.isupper() for c in password) and
                   any(c.isdigit() for c in password) and
                   any(c in "!@#$%^&*" for c in password)):
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        return password
    
    def _generate_onboarding_url(self, token: str) -> str:
        """Generate onboarding URL for new user"""
        base_url = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:3000"
        return f"{base_url}/onboarding?token={token}"
    
    async def _get_organization_name(self, org_id: str) -> Optional[str]:
        """Get organization name"""
        try:
            clerk_client = await self._get_clerk_client()
            org = await clerk_client.get_organization(org_id)
            return org.name if org else None
        except:
            return None
    
    async def _revoke_user_sessions(self, user_id: str):
        """Revoke all active sessions for a user"""
        try:
            clerk_client = await self._get_clerk_client()
            sessions = await clerk_client.list_sessions(user_id=user_id)
            
            for session in sessions:
                if session.status == "active":
                    await clerk_client.revoke_session(session.id)
        
        except Exception as e:
            logger.error(f"Failed to revoke user sessions: {str(e)}")
    
    async def _send_admin_created_welcome_email(
        self,
        email: str,
        user_id: str,
        first_name: Optional[str],
        temp_password: Optional[str],
        onboarding_token: str,
        organization_name: Optional[str]
    ):
        """Send welcome email for admin-created account"""
        try:
            email_data = {
                "first_name": first_name or "User",
                "temporary_password": temp_password,
                "onboarding_url": self._generate_onboarding_url(onboarding_token),
                "organization_name": organization_name,
                "password_expiry_hours": self.temp_password_expiry_hours
            }
            
            await self.email_service.send_admin_account_created_email(email, email_data)
        
        except Exception as e:
            logger.error(f"Failed to send welcome email: {str(e)}")
    
    async def _send_password_reset_notification(
        self,
        email: str,
        user_id: str,
        temp_password: Optional[str],
        admin_id: str
    ):
        """Send password reset notification"""
        try:
            email_data = {
                "temporary_password": temp_password,
                "password_expiry_hours": self.temp_password_expiry_hours,
                "reset_by_admin": True
            }
            
            await self.email_service.send_password_reset_email(email, email_data)
        
        except Exception as e:
            logger.error(f"Failed to send password reset notification: {str(e)}")
    
    async def _send_suspension_notification(
        self,
        email: str,
        user_id: str,
        reason: str,
        duration_hours: Optional[int],
        admin_id: str
    ):
        """Send account suspension notification"""
        try:
            email_data = {
                "reason": reason,
                "duration_hours": duration_hours,
                "suspension_end": (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat() if duration_hours else None
            }
            
            await self.email_service.send_account_suspension_email(email, email_data)
        
        except Exception as e:
            logger.error(f"Failed to send suspension notification: {str(e)}")
    
    async def _send_unsuspension_notification(
        self,
        email: str,
        user_id: str,
        reason: str,
        admin_id: str
    ):
        """Send account unsuspension notification"""
        try:
            email_data = {
                "reason": reason,
                "unsuspended_at": datetime.utcnow().isoformat()
            }
            
            await self.email_service.send_account_unsuspension_email(email, email_data)
        
        except Exception as e:
            logger.error(f"Failed to send unsuspension notification: {str(e)}")
    
    async def _log_account_creation(
        self,
        admin_id: str,
        user_id: str,
        email: str,
        organization_id: Optional[str]
    ):
        """Log admin account creation"""
        log_key = f"admin_action:account_created:{user_id}"
        log_data = {
            "action": "account_created",
            "admin_id": admin_id,
            "user_id": user_id,
            "email": email,
            "organization_id": organization_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        await cache_service.set(log_key, log_data, expire=30 * 86400)  # Keep for 30 days
    
    async def _log_password_reset(
        self,
        admin_id: str,
        user_id: str,
        is_temporary: bool
    ):
        """Log admin password reset"""
        log_key = f"admin_action:password_reset:{user_id}:{datetime.utcnow().timestamp()}"
        log_data = {
            "action": "password_reset",
            "admin_id": admin_id,
            "user_id": user_id,
            "is_temporary": is_temporary,
            "timestamp": datetime.utcnow().isoformat()
        }
        await cache_service.set(log_key, log_data, expire=30 * 86400)
    
    async def _log_account_suspension(
        self,
        admin_id: str,
        user_id: str,
        reason: str,
        duration_hours: Optional[int]
    ):
        """Log account suspension"""
        log_key = f"admin_action:suspension:{user_id}:{datetime.utcnow().timestamp()}"
        log_data = {
            "action": "account_suspended",
            "admin_id": admin_id,
            "user_id": user_id,
            "reason": reason,
            "duration_hours": duration_hours,
            "timestamp": datetime.utcnow().isoformat()
        }
        await cache_service.set(log_key, log_data, expire=30 * 86400)
    
    async def _log_account_unsuspension(
        self,
        admin_id: str,
        user_id: str,
        reason: str
    ):
        """Log account unsuspension"""
        log_key = f"admin_action:unsuspension:{user_id}:{datetime.utcnow().timestamp()}"
        log_data = {
            "action": "account_unsuspended",
            "admin_id": admin_id,
            "user_id": user_id,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        await cache_service.set(log_key, log_data, expire=30 * 86400)


# Singleton instance
admin_account_service = AdminAccountService()