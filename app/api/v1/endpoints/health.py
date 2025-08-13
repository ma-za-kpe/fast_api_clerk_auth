from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()


@router.get("/status")
async def health_status():
    """Get application health status"""
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "features": {
            "social_auth": settings.ENABLE_SOCIAL_AUTH,
            "mfa": settings.ENABLE_MFA,
            "organizations": settings.ENABLE_ORGANIZATIONS,
            "webhooks": settings.ENABLE_WEBHOOKS,
            "admin_panel": settings.ENABLE_ADMIN_PANEL
        }
    }


@router.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe"""
    return {"ready": True}


@router.get("/live")
async def liveness_check():
    """Kubernetes liveness probe"""
    return {"alive": True}