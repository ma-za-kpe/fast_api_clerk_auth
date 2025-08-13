from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    users,
    organizations,
    sessions,
    admin,
    webhooks,
    webhook_management,
    health,
    passwordless,
    oauth,
    mfa,
    devices,
    api_keys,
    invitations,
    domains,
    admin_accounts,
    email_change,
    password_change,
    audit,
    activity,
    rbac,
    avatar_management,
    enterprise_sso,
    analytics,
    compliance,
    bot_protection,
    email_security,
    bulk_operations,
    geolocation,
    workspaces
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(sessions.router, prefix="/sessions", tags=["Sessions"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
api_router.include_router(webhook_management.router, prefix="/webhook-management", tags=["Webhook Management"])
api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(passwordless.router, prefix="/passwordless", tags=["Passwordless"])
api_router.include_router(oauth.router, prefix="/oauth", tags=["OAuth"])
api_router.include_router(mfa.router, prefix="/mfa", tags=["Multi-Factor Authentication"])
api_router.include_router(devices.router, prefix="/devices", tags=["Device Management"])
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["API Key Management"])
api_router.include_router(invitations.router, prefix="/invitations", tags=["Organization Invitations"])
api_router.include_router(domains.router, prefix="/domains", tags=["Domain Management"])
api_router.include_router(admin_accounts.router, prefix="/admin-accounts", tags=["Admin Account Management"])
api_router.include_router(email_change.router, prefix="/email-change", tags=["Email Address Change"])
api_router.include_router(password_change.router, prefix="/password-change", tags=["Password Management"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Logging"])
api_router.include_router(activity.router, prefix="/activity", tags=["Activity Tracking"])
api_router.include_router(rbac.router, prefix="/rbac", tags=["Role-Based Access Control"])
api_router.include_router(avatar_management.router, prefix="/avatar-management", tags=["Avatar Management"])
api_router.include_router(enterprise_sso.router, prefix="/sso", tags=["Enterprise SSO"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics & Monitoring"])
api_router.include_router(compliance.router, prefix="/compliance", tags=["GDPR/CCPA Compliance"])
api_router.include_router(bot_protection.router, prefix="/bot-protection", tags=["Bot Protection"])
api_router.include_router(email_security.router, prefix="/email-security", tags=["Email Security"])
api_router.include_router(bulk_operations.router, prefix="/bulk", tags=["Bulk Operations"])
api_router.include_router(geolocation.router, prefix="/geolocation", tags=["Geolocation"])
api_router.include_router(workspaces.router, prefix="/workspaces", tags=["Workspaces/Teams"])