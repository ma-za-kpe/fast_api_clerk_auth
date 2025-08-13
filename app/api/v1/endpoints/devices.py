from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, Body, HTTPException, Request, Header
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, RateLimitError
from app.api.v1.deps import get_current_user
from app.services.device_service import device_service
from app.schemas.auth import DeviceVerificationRequest, DeviceTrustRequest

router = APIRouter()
logger = structlog.get_logger()


@router.get("/")
async def get_user_devices(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all devices for the current user
    """
    try:
        user_id = current_user.get("user_id")
        devices = await device_service.get_user_devices(user_id)
        
        return {
            "devices": devices,
            "count": len(devices),
            "limit": device_service.device_limit_per_user
        }
    
    except Exception as e:
        logger.error(f"Failed to get user devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve devices")


@router.get("/current")
async def get_current_device(
    request: Request,
    user_agent: str = Header(None, alias="User-Agent"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get information about the current device
    """
    try:
        user_id = current_user.get("user_id")
        client_ip = request.client.host
        
        # Generate device ID for current request
        device_id = device_service._generate_device_id(
            user_id, 
            user_agent or "", 
            client_ip,
            None
        )
        
        # Get device info
        device = await device_service.get_device(user_id, device_id)
        
        if not device:
            # Register the device if it doesn't exist
            device = await device_service.register_device(
                user_id=user_id,
                user_agent=user_agent or "",
                ip_address=client_ip
            )
        
        return device
    
    except Exception as e:
        logger.error(f"Failed to get current device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve device information")


@router.post("/register")
async def register_device(
    request: Request,
    fingerprint: Optional[str] = Body(None, embed=True),
    user_agent: str = Header(None, alias="User-Agent"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Register a new device
    """
    try:
        user_id = current_user.get("user_id")
        client_ip = request.client.host
        
        # Register device
        result = await device_service.register_device(
            user_id=user_id,
            user_agent=user_agent or "",
            ip_address=client_ip,
            fingerprint=fingerprint
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to register device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to register device")


@router.get("/{device_id}")
async def get_device(
    device_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get specific device information
    """
    try:
        user_id = current_user.get("user_id")
        device = await device_service.get_device(user_id, device_id)
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return device
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve device")


@router.post("/{device_id}/verify")
async def verify_device(
    device_id: str,
    request: DeviceVerificationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify a device with a code
    """
    try:
        user_id = current_user.get("user_id")
        
        # Verify device
        result = await device_service.verify_device(
            user_id=user_id,
            device_id=device_id,
            verification_code=request.code
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify device")


@router.post("/{device_id}/send-verification")
async def send_device_verification(
    device_id: str,
    method: str = Body("email", embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Send verification code for a device
    """
    try:
        user_id = current_user.get("user_id")
        
        # Send verification code
        result = await device_service.send_device_verification_code(
            user_id=user_id,
            device_id=device_id,
            method=method
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to send verification code: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send verification code")


@router.post("/{device_id}/trust")
async def trust_device(
    device_id: str,
    request: DeviceTrustRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Mark a device as trusted
    """
    try:
        user_id = current_user.get("user_id")
        
        # Trust device
        result = await device_service.trust_device(
            user_id=user_id,
            device_id=device_id,
            duration_days=request.duration_days
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to trust device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to trust device")


@router.post("/{device_id}/untrust")
async def untrust_device(
    device_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove trust from a device
    """
    try:
        user_id = current_user.get("user_id")
        
        # Untrust device
        result = await device_service.untrust_device(
            user_id=user_id,
            device_id=device_id
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to untrust device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to untrust device")


@router.delete("/{device_id}")
async def remove_device(
    device_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove a device
    """
    try:
        user_id = current_user.get("user_id")
        
        # Remove device
        result = await device_service.remove_device(
            user_id=user_id,
            device_id=device_id
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to remove device: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to remove device")


@router.get("/{device_id}/sessions")
async def get_device_sessions(
    device_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all sessions for a device
    """
    try:
        user_id = current_user.get("user_id")
        sessions = await device_service.get_device_sessions(user_id, device_id)
        
        return {
            "device_id": device_id,
            "sessions": sessions,
            "count": len(sessions)
        }
    
    except Exception as e:
        logger.error(f"Failed to get device sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve sessions")


@router.get("/{device_id}/trust-status")
async def check_device_trust(
    device_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Check if a device is trusted
    """
    try:
        user_id = current_user.get("user_id")
        is_trusted, reason = await device_service.check_device_trust(user_id, device_id)
        
        return {
            "device_id": device_id,
            "trusted": is_trusted,
            "reason": reason
        }
    
    except Exception as e:
        logger.error(f"Failed to check device trust: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check trust status")


@router.post("/check-current")
async def check_current_device_trust(
    request: Request,
    user_agent: str = Header(None, alias="User-Agent"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Check if current device is trusted
    """
    try:
        user_id = current_user.get("user_id")
        client_ip = request.client.host
        
        # Generate device ID for current request
        device_id = device_service._generate_device_id(
            user_id,
            user_agent or "",
            client_ip,
            None
        )
        
        # Check trust status
        is_trusted, reason = await device_service.check_device_trust(user_id, device_id)
        
        return {
            "device_id": device_id,
            "trusted": is_trusted,
            "reason": reason,
            "requires_mfa": not is_trusted  # Require MFA if device is not trusted
        }
    
    except Exception as e:
        logger.error(f"Failed to check current device trust: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check device trust")


@router.get("/analytics/summary")
async def get_device_analytics(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get device analytics for the current user
    """
    try:
        user_id = current_user.get("user_id")
        analytics = await device_service.get_device_analytics(user_id)
        
        return analytics
    
    except Exception as e:
        logger.error(f"Failed to get device analytics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve analytics")


@router.post("/cleanup")
async def cleanup_old_devices(
    days_inactive: int = Body(90, embed=True, description="Remove devices inactive for this many days"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove devices that haven't been used in specified days
    """
    try:
        user_id = current_user.get("user_id")
        devices = await device_service.get_user_devices(user_id)
        
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
        removed_count = 0
        
        for device in devices:
            last_seen = device.get("last_seen")
            if last_seen:
                last_seen_date = datetime.fromisoformat(last_seen)
                if last_seen_date < cutoff_date:
                    await device_service.remove_device(user_id, device["device_id"])
                    removed_count += 1
        
        return {
            "removed": removed_count,
            "message": f"Removed {removed_count} inactive devices"
        }
    
    except Exception as e:
        logger.error(f"Failed to cleanup devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup devices")


@router.post("/remove-all-except-current")
async def remove_all_except_current(
    request: Request,
    user_agent: str = Header(None, alias="User-Agent"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove all devices except the current one
    """
    try:
        user_id = current_user.get("user_id")
        client_ip = request.client.host
        
        # Generate current device ID
        current_device_id = device_service._generate_device_id(
            user_id,
            user_agent or "",
            client_ip,
            None
        )
        
        # Get all devices
        devices = await device_service.get_user_devices(user_id)
        removed_count = 0
        
        for device in devices:
            if device["device_id"] != current_device_id:
                await device_service.remove_device(user_id, device["device_id"])
                removed_count += 1
        
        return {
            "removed": removed_count,
            "kept_device_id": current_device_id,
            "message": f"Removed {removed_count} devices, kept current device"
        }
    
    except Exception as e:
        logger.error(f"Failed to remove devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to remove devices")