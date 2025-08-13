from fastapi import APIRouter, Depends, HTTPException, Request, Query, Body
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.geolocation_service import get_geolocation_service, GeoLocation
from app.core.exceptions import ValidationError, SecurityError
from app.api.v1.deps import get_optional_current_user, require_admin, get_db

router = APIRouter()
logger = structlog.get_logger()


# ============= Request Models =============

class IPLookupRequest(BaseModel):
    ip_address: str


class CountryBlockRequest(BaseModel):
    country_code: str
    reason: Optional[str] = None


class LocationCheckRequest(BaseModel):
    user_id: Optional[str] = None
    ip_address: str


# ============= Public Endpoints =============

@router.get("/my-location")
async def get_my_location(
    request: Request,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get geolocation for current request
    """
    try:
        # Get client IP
        client_ip = request.client.host if request.client else None
        
        # Try to get real IP from headers (for proxied requests)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP from the chain
            client_ip = forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            client_ip = real_ip
        
        if not client_ip:
            raise ValidationError("Unable to determine IP address")
        
        # Get geolocation
        geo_service = get_geolocation_service(db)
        location = await geo_service.get_location(client_ip)
        
        # Check for anomalies if user is authenticated
        anomaly_check = None
        if current_user:
            anomaly_check = await geo_service.check_location_anomaly(
                user_id=current_user.get("user_id"),
                current_location=location
            )
        
        # Log the location access
        logger.info(
            "Location retrieved",
            ip=client_ip,
            country=location.country,
            city=location.city,
            user_id=current_user.get("user_id") if current_user else None
        )
        
        # Build response
        response = {
            "ip": location.ip,
            "country": location.country,
            "country_code": location.country_code,
            "region": location.region,
            "city": location.city,
            "timezone": location.timezone,
            "is_vpn": location.is_vpn,
            "is_proxy": location.is_proxy,
            "threat_level": location.threat_level
        }
        
        # Add coordinates only for authenticated users
        if current_user:
            response["latitude"] = location.latitude
            response["longitude"] = location.longitude
            
            if anomaly_check:
                response["security_check"] = {
                    "has_anomalies": anomaly_check["has_anomalies"],
                    "risk_score": anomaly_check["risk_score"],
                    "action": anomaly_check["action"]
                }
        
        return response
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Failed to get location: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve location")


@router.post("/lookup")
async def lookup_ip_location(
    request: IPLookupRequest,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Look up geolocation for a specific IP address
    """
    try:
        # Rate limiting for non-authenticated users
        if not current_user:
            # Simple rate limiting (would use slowapi in production)
            from app.services.cache_service import cache_service
            rate_key = f"geo_lookup_rate:{request.ip_address}"
            attempts = await cache_service.get(rate_key) or 0
            if attempts >= 10:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            await cache_service.set(rate_key, attempts + 1, expire=3600)
        
        geo_service = get_geolocation_service(db)
        location = await geo_service.get_location(request.ip_address)
        
        # Log the lookup
        logger.info(
            "IP lookup performed",
            lookup_ip=request.ip_address,
            country=location.country,
            user_id=current_user.get("user_id") if current_user else None
        )
        
        # Basic response for non-authenticated users
        if not current_user:
            return {
                "ip": location.ip,
                "country": location.country,
                "country_code": location.country_code,
                "city": location.city,
                "threat_level": location.threat_level
            }
        
        # Full response for authenticated users
        return {
            "ip": location.ip,
            "country": location.country,
            "country_code": location.country_code,
            "region": location.region,
            "city": location.city,
            "latitude": location.latitude,
            "longitude": location.longitude,
            "timezone": location.timezone,
            "isp": location.isp,
            "organization": location.organization,
            "is_vpn": location.is_vpn,
            "is_proxy": location.is_proxy,
            "is_tor": location.is_tor,
            "is_hosting": location.is_hosting,
            "threat_level": location.threat_level,
            "accuracy_radius": location.accuracy_radius
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"IP lookup failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Lookup failed")


@router.get("/my-history")
async def get_location_history(
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get location history for current user
    """
    try:
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        geo_service = get_geolocation_service(db)
        
        # Get location statistics
        stats = await geo_service.get_location_stats(
            user_id=current_user.get("user_id")
        )
        
        # Get recent locations
        from app.services.cache_service import cache_service
        cache_key = f"user_locations:{current_user.get('user_id')}"
        recent_locations = await cache_service.get(cache_key) or []
        
        return {
            "statistics": stats,
            "recent_locations": recent_locations[:10],  # Last 10 locations
            "user_id": current_user.get("user_id")
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get location history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve history")


# ============= Security Endpoints =============

@router.post("/check-anomaly")
async def check_location_anomaly(
    request: LocationCheckRequest,
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check for location-based anomalies
    """
    try:
        # Determine user_id
        user_id = request.user_id
        if not user_id and current_user:
            user_id = current_user.get("user_id")
        
        if not user_id:
            raise ValidationError("User ID required")
        
        # Only allow checking own anomalies or admin
        if current_user:
            is_admin = current_user.get("is_admin", False)
            if not is_admin and user_id != current_user.get("user_id"):
                raise HTTPException(status_code=403, detail="Access denied")
        
        geo_service = get_geolocation_service(db)
        
        # Get location for IP
        location = await geo_service.get_location(request.ip_address)
        
        # Check for anomalies
        anomaly_result = await geo_service.check_location_anomaly(
            user_id=user_id,
            current_location=location
        )
        
        # Log if anomalies detected
        if anomaly_result["has_anomalies"]:
            logger.warning(
                "Location anomalies detected",
                user_id=user_id,
                ip=request.ip_address,
                anomalies=anomaly_result["anomalies"],
                risk_score=anomaly_result["risk_score"]
            )
        
        return anomaly_result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Anomaly check failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Anomaly check failed")


# ============= Admin Endpoints =============

@router.get("/blocked-countries")
async def get_blocked_countries(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get list of blocked countries (admin only)
    """
    try:
        geo_service = get_geolocation_service(db)
        blocked = await geo_service.get_blocked_countries()
        
        # Get country names for codes
        country_names = {
            "KP": "North Korea",
            "IR": "Iran",
            "SY": "Syria",
            "CU": "Cuba",
            "SD": "Sudan",
            # Add more as needed
        }
        
        return {
            "blocked_countries": [
                {
                    "code": code,
                    "name": country_names.get(code, code)
                }
                for code in blocked
            ],
            "total": len(blocked)
        }
    
    except Exception as e:
        logger.error(f"Failed to get blocked countries: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve blocked countries")


@router.post("/blocked-countries")
async def add_blocked_country(
    request: CountryBlockRequest,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Add country to blocked list (admin only)
    """
    try:
        # Validate country code (should be 2-letter ISO code)
        if len(request.country_code) != 2:
            raise ValidationError("Country code must be 2-letter ISO code")
        
        geo_service = get_geolocation_service(db)
        await geo_service.add_blocked_country(request.country_code.upper())
        
        logger.warning(
            "Country added to blocklist",
            country_code=request.country_code,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        return {
            "message": f"Country {request.country_code} added to blocklist",
            "country_code": request.country_code.upper(),
            "reason": request.reason
        }
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to add blocked country: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add country")


@router.delete("/blocked-countries/{country_code}")
async def remove_blocked_country(
    country_code: str,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Remove country from blocked list (admin only)
    """
    try:
        geo_service = get_geolocation_service(db)
        await geo_service.remove_blocked_country(country_code.upper())
        
        logger.info(
            "Country removed from blocklist",
            country_code=country_code,
            admin_id=admin_user.get("user_id")
        )
        
        return {
            "message": f"Country {country_code} removed from blocklist",
            "country_code": country_code.upper()
        }
    
    except Exception as e:
        logger.error(f"Failed to remove blocked country: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to remove country")


@router.get("/user/{user_id}/locations")
async def get_user_locations(
    user_id: str,
    limit: int = Query(10, ge=1, le=50),
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get location history for a specific user (admin only)
    """
    try:
        geo_service = get_geolocation_service(db)
        
        # Get location statistics
        stats = await geo_service.get_location_stats(user_id)
        
        # Get recent locations
        from app.services.cache_service import cache_service
        cache_key = f"user_locations:{user_id}"
        recent_locations = await cache_service.get(cache_key) or []
        
        return {
            "user_id": user_id,
            "statistics": stats,
            "recent_locations": recent_locations[:limit],
            "total_locations": len(recent_locations)
        }
    
    except Exception as e:
        logger.error(f"Failed to get user locations: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user locations")


@router.get("/stats")
async def get_geolocation_stats(
    timeframe: str = Query("24h", regex="^(1h|24h|7d|30d)$"),
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get geolocation statistics (admin only)
    """
    try:
        # This would aggregate location data from sessions
        # Placeholder implementation
        stats = {
            "timeframe": timeframe,
            "unique_countries": 0,
            "unique_cities": 0,
            "vpn_detections": 0,
            "proxy_detections": 0,
            "anomalies_detected": 0,
            "blocked_attempts": 0,
            "top_countries": [],
            "top_cities": [],
            "threat_distribution": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "blocked": 0
            }
        }
        
        return stats
    
    except Exception as e:
        logger.error(f"Failed to get geolocation stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")