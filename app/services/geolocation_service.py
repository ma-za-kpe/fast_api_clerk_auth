from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import httpx
import ipaddress
import structlog
from dataclasses import dataclass
import math
import hashlib
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from app.core.config import settings
from app.core.exceptions import ValidationError, SecurityError
from app.services.cache_service import cache_service
from app.db.models import UserSession, AuditLog

logger = structlog.get_logger()


@dataclass
class GeoLocation:
    """Geolocation data structure"""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    threat_level: str = "low"  # low, medium, high
    accuracy_radius: Optional[int] = None  # in kilometers


class GeolocationService:
    """
    Service for IP geolocation and location-based security features
    """
    
    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db
        
        # API configuration (multiple providers for redundancy)
        self.ipapi_key = getattr(settings, 'IPAPI_KEY', None)
        self.ipstack_key = getattr(settings, 'IPSTACK_KEY', None)
        self.ipgeolocation_key = getattr(settings, 'IPGEOLOCATION_KEY', None)
        self.maxmind_account_id = getattr(settings, 'MAXMIND_ACCOUNT_ID', None)
        self.maxmind_license_key = getattr(settings, 'MAXMIND_LICENSE_KEY', None)
        
        # Cache configuration
        self.cache_ttl = 86400  # 24 hours
        self.location_cache_ttl = 3600  # 1 hour for user location history
        
        # Security thresholds
        self.max_distance_threshold_km = 1000  # Alert if login from > 1000km away
        self.impossible_travel_speed_kmh = 900  # Commercial flight speed
        self.suspicious_countries = self._load_suspicious_countries()
        self.blocked_countries = self._load_blocked_countries()
    
    def _load_suspicious_countries(self) -> set:
        """Load list of countries with higher risk scores"""
        # Countries often associated with higher cybercrime rates
        # This is for demonstration - in production, use a more nuanced approach
        return {
            'KP', 'IR', 'SY', 'CU', 'SD',  # Sanctioned countries
            'NG', 'PK', 'VN', 'CN', 'RU',  # Higher cybercrime rates (example)
        }
    
    def _load_blocked_countries(self) -> set:
        """Load list of completely blocked countries"""
        # Get from settings or return empty set
        blocked = getattr(settings, 'BLOCKED_COUNTRIES', '')
        if blocked:
            return set(blocked.split(','))
        return set()
    
    async def get_location(self, ip_address: str) -> GeoLocation:
        """
        Get geolocation data for an IP address
        """
        try:
            # Validate IP address
            if not self._is_valid_ip(ip_address):
                logger.warning(f"Invalid IP address: {ip_address}")
                return GeoLocation(ip=ip_address, threat_level="unknown")
            
            # Check if it's a private IP
            if self._is_private_ip(ip_address):
                return GeoLocation(
                    ip=ip_address,
                    country="Private Network",
                    country_code="XX",
                    threat_level="low"
                )
            
            # Check cache first
            cache_key = f"geo:{hashlib.md5(ip_address.encode()).hexdigest()}"
            cached_data = await cache_service.get(cache_key)
            if cached_data:
                return GeoLocation(**cached_data)
            
            # Try multiple providers in order of preference
            location = None
            
            if self.ipstack_key:
                location = await self._get_location_ipstack(ip_address)
            
            if not location and self.ipapi_key:
                location = await self._get_location_ipapi(ip_address)
            
            if not location and self.ipgeolocation_key:
                location = await self._get_location_ipgeolocation(ip_address)
            
            if not location:
                # Fallback to free service
                location = await self._get_location_free(ip_address)
            
            if location:
                # Assess threat level
                location.threat_level = self._assess_threat_level(location)
                
                # Cache the result
                location_dict = {
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
                await cache_service.set(cache_key, location_dict, expire=self.cache_ttl)
                
                return location
            
            # Return basic info if all providers fail
            return GeoLocation(ip=ip_address, threat_level="unknown")
            
        except Exception as e:
            logger.error(f"Geolocation lookup failed: {str(e)}")
            return GeoLocation(ip=ip_address, threat_level="unknown")
    
    async def _get_location_ipstack(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location using IPStack API"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://api.ipstack.com/{ip_address}",
                    params={
                        "access_key": self.ipstack_key,
                        "security": 1,  # Include security module
                        "hostname": 1   # Include hostname
                    },
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    security = data.get("security", {})
                    
                    return GeoLocation(
                        ip=ip_address,
                        country=data.get("country_name"),
                        country_code=data.get("country_code"),
                        region=data.get("region_name"),
                        city=data.get("city"),
                        latitude=data.get("latitude"),
                        longitude=data.get("longitude"),
                        timezone=data.get("time_zone", {}).get("id"),
                        is_vpn=security.get("is_vpn", False),
                        is_proxy=security.get("is_proxy", False),
                        is_tor=security.get("is_tor", False),
                        is_hosting=security.get("is_hosting", False)
                    )
        except Exception as e:
            logger.error(f"IPStack API error: {str(e)}")
        return None
    
    async def _get_location_ipapi(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location using IP-API.com"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://ip-api.com/json/{ip_address}",
                    params={
                        "fields": "status,country,countryCode,region,city,lat,lon,timezone,isp,org,proxy,hosting,query"
                    },
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("status") == "success":
                        return GeoLocation(
                            ip=ip_address,
                            country=data.get("country"),
                            country_code=data.get("countryCode"),
                            region=data.get("region"),
                            city=data.get("city"),
                            latitude=data.get("lat"),
                            longitude=data.get("lon"),
                            timezone=data.get("timezone"),
                            isp=data.get("isp"),
                            organization=data.get("org"),
                            is_proxy=data.get("proxy", False),
                            is_hosting=data.get("hosting", False)
                        )
        except Exception as e:
            logger.error(f"IP-API error: {str(e)}")
        return None
    
    async def _get_location_ipgeolocation(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location using IPGeolocation.io"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.ipgeolocation.io/ipgeo",
                    params={
                        "apiKey": self.ipgeolocation_key,
                        "ip": ip_address,
                        "include": "security"
                    },
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    security = data.get("security", {})
                    
                    return GeoLocation(
                        ip=ip_address,
                        country=data.get("country_name"),
                        country_code=data.get("country_code2"),
                        region=data.get("state_prov"),
                        city=data.get("city"),
                        latitude=float(data.get("latitude", 0)),
                        longitude=float(data.get("longitude", 0)),
                        timezone=data.get("time_zone", {}).get("name"),
                        isp=data.get("isp"),
                        organization=data.get("organization"),
                        is_vpn=security.get("is_vpn", False),
                        is_proxy=security.get("is_proxy", False),
                        is_tor=security.get("is_tor", False),
                        threat_level=security.get("threat_level", "low")
                    )
        except Exception as e:
            logger.error(f"IPGeolocation API error: {str(e)}")
        return None
    
    async def _get_location_free(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location using free ipapi.co service"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://ipapi.co/{ip_address}/json/",
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    return GeoLocation(
                        ip=ip_address,
                        country=data.get("country_name"),
                        country_code=data.get("country_code"),
                        region=data.get("region"),
                        city=data.get("city"),
                        latitude=data.get("latitude"),
                        longitude=data.get("longitude"),
                        timezone=data.get("timezone"),
                        organization=data.get("org")
                    )
        except Exception as e:
            logger.error(f"Free geolocation API error: {str(e)}")
        return None
    
    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    def _assess_threat_level(self, location: GeoLocation) -> str:
        """Assess threat level based on location data"""
        threat_score = 0
        
        # Check if country is blocked
        if location.country_code in self.blocked_countries:
            return "blocked"
        
        # Suspicious country
        if location.country_code in self.suspicious_countries:
            threat_score += 40
        
        # VPN/Proxy/Tor usage
        if location.is_vpn:
            threat_score += 20
        if location.is_proxy:
            threat_score += 25
        if location.is_tor:
            threat_score += 35
        if location.is_hosting:
            threat_score += 15
        
        # Determine threat level
        if threat_score >= 60:
            return "high"
        elif threat_score >= 30:
            return "medium"
        else:
            return "low"
    
    async def check_location_anomaly(
        self,
        user_id: str,
        current_location: GeoLocation
    ) -> Dict[str, Any]:
        """
        Check for location-based anomalies
        """
        try:
            anomalies = []
            risk_score = 0
            
            # Get user's recent locations
            recent_locations = await self._get_recent_locations(user_id)
            
            if recent_locations:
                # Check for impossible travel
                for prev_location in recent_locations:
                    travel_anomaly = self._check_impossible_travel(
                        prev_location,
                        current_location
                    )
                    if travel_anomaly:
                        anomalies.append(travel_anomaly)
                        risk_score += travel_anomaly["risk_score"]
                
                # Check for new country
                previous_countries = {loc["country_code"] for loc in recent_locations if loc.get("country_code")}
                if current_location.country_code and current_location.country_code not in previous_countries:
                    anomalies.append({
                        "type": "new_country",
                        "description": f"Login from new country: {current_location.country}",
                        "risk_score": 30
                    })
                    risk_score += 30
            
            # Check threat level
            if current_location.threat_level == "high":
                anomalies.append({
                    "type": "high_risk_location",
                    "description": f"Login from high-risk location",
                    "risk_score": 40
                })
                risk_score += 40
            elif current_location.threat_level == "blocked":
                anomalies.append({
                    "type": "blocked_location",
                    "description": f"Login from blocked country: {current_location.country}",
                    "risk_score": 100
                })
                risk_score += 100
            
            # VPN/Proxy detection
            if current_location.is_vpn or current_location.is_proxy:
                anomalies.append({
                    "type": "anonymizer_detected",
                    "description": "VPN or proxy detected",
                    "risk_score": 25
                })
                risk_score += 25
            
            # Store current location for future checks
            await self._store_user_location(user_id, current_location)
            
            return {
                "has_anomalies": len(anomalies) > 0,
                "anomalies": anomalies,
                "risk_score": min(risk_score, 100),
                "action": self._determine_action(risk_score),
                "location": {
                    "country": current_location.country,
                    "city": current_location.city,
                    "is_vpn": current_location.is_vpn,
                    "threat_level": current_location.threat_level
                }
            }
            
        except Exception as e:
            logger.error(f"Location anomaly check failed: {str(e)}")
            return {
                "has_anomalies": False,
                "anomalies": [],
                "risk_score": 0,
                "action": "allow"
            }
    
    def _check_impossible_travel(
        self,
        previous_location: Dict[str, Any],
        current_location: GeoLocation
    ) -> Optional[Dict[str, Any]]:
        """
        Check for impossible travel between two locations
        """
        try:
            # Get coordinates
            prev_lat = previous_location.get("latitude")
            prev_lon = previous_location.get("longitude")
            curr_lat = current_location.latitude
            curr_lon = current_location.longitude
            
            if not all([prev_lat, prev_lon, curr_lat, curr_lon]):
                return None
            
            # Calculate distance
            distance_km = self._calculate_distance(
                prev_lat, prev_lon,
                curr_lat, curr_lon
            )
            
            # Calculate time difference
            prev_time = datetime.fromisoformat(previous_location["timestamp"])
            time_diff_hours = (datetime.utcnow() - prev_time).total_seconds() / 3600
            
            if time_diff_hours <= 0:
                return None
            
            # Calculate required speed
            required_speed_kmh = distance_km / time_diff_hours
            
            # Check for impossible travel
            if required_speed_kmh > self.impossible_travel_speed_kmh:
                return {
                    "type": "impossible_travel",
                    "description": f"Impossible travel detected: {distance_km:.0f}km in {time_diff_hours:.1f}hours",
                    "risk_score": 50,
                    "details": {
                        "distance_km": distance_km,
                        "time_hours": time_diff_hours,
                        "required_speed_kmh": required_speed_kmh,
                        "from_location": f"{previous_location.get('city')}, {previous_location.get('country')}",
                        "to_location": f"{current_location.city}, {current_location.country}"
                    }
                }
            
            # Check for suspicious rapid travel
            elif distance_km > self.max_distance_threshold_km and time_diff_hours < 24:
                return {
                    "type": "rapid_location_change",
                    "description": f"Rapid location change: {distance_km:.0f}km",
                    "risk_score": 20,
                    "details": {
                        "distance_km": distance_km,
                        "time_hours": time_diff_hours
                    }
                }
            
        except Exception as e:
            logger.error(f"Impossible travel check failed: {str(e)}")
        
        return None
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate distance between two coordinates using Haversine formula
        Returns distance in kilometers
        """
        R = 6371  # Earth's radius in kilometers
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c
    
    def _determine_action(self, risk_score: int) -> str:
        """Determine action based on risk score"""
        if risk_score >= 80:
            return "block"
        elif risk_score >= 50:
            return "require_mfa"
        elif risk_score >= 30:
            return "alert"
        else:
            return "allow"
    
    async def _get_recent_locations(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get user's recent location history"""
        try:
            cache_key = f"user_locations:{user_id}"
            locations = await cache_service.get(cache_key) or []
            
            # Also get from database if available
            if self.db:
                query = select(UserSession).where(
                    and_(
                        UserSession.user_id == user_id,
                        UserSession.created_at > datetime.utcnow() - timedelta(days=30)
                    )
                ).order_by(UserSession.created_at.desc()).limit(limit)
                
                result = await self.db.execute(query)
                sessions = result.scalars().all()
                
                for session in sessions:
                    if session.location:
                        # Parse location string if needed
                        locations.append({
                            "country": session.location.split(",")[0] if "," in session.location else session.location,
                            "timestamp": session.created_at.isoformat()
                        })
            
            return locations[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get recent locations: {str(e)}")
            return []
    
    async def _store_user_location(self, user_id: str, location: GeoLocation):
        """Store user location for future checks"""
        try:
            cache_key = f"user_locations:{user_id}"
            locations = await cache_service.get(cache_key) or []
            
            # Add new location
            location_data = {
                "country": location.country,
                "country_code": location.country_code,
                "city": location.city,
                "latitude": location.latitude,
                "longitude": location.longitude,
                "timestamp": datetime.utcnow().isoformat(),
                "is_vpn": location.is_vpn,
                "threat_level": location.threat_level
            }
            
            locations.insert(0, location_data)
            
            # Keep only recent locations
            locations = locations[:20]
            
            # Store in cache
            await cache_service.set(cache_key, locations, expire=self.location_cache_ttl)
            
        except Exception as e:
            logger.error(f"Failed to store user location: {str(e)}")
    
    async def get_location_stats(self, user_id: str) -> Dict[str, Any]:
        """Get location statistics for a user"""
        try:
            locations = await self._get_recent_locations(user_id, limit=50)
            
            if not locations:
                return {
                    "total_locations": 0,
                    "countries": [],
                    "cities": [],
                    "most_common_country": None
                }
            
            countries = {}
            cities = {}
            
            for loc in locations:
                country = loc.get("country")
                city = loc.get("city")
                
                if country:
                    countries[country] = countries.get(country, 0) + 1
                if city:
                    cities[city] = cities.get(city, 0) + 1
            
            return {
                "total_locations": len(locations),
                "unique_countries": len(countries),
                "unique_cities": len(cities),
                "countries": sorted(countries.keys()),
                "cities": sorted(cities.keys())[:10],  # Top 10 cities
                "most_common_country": max(countries, key=countries.get) if countries else None
            }
            
        except Exception as e:
            logger.error(f"Failed to get location stats: {str(e)}")
            return {}
    
    async def is_country_blocked(self, country_code: str) -> bool:
        """Check if country is blocked"""
        return country_code in self.blocked_countries
    
    async def add_blocked_country(self, country_code: str):
        """Add country to blocked list"""
        self.blocked_countries.add(country_code)
        # Store in cache for persistence
        cache_key = "geolocation:blocked_countries"
        await cache_service.set(cache_key, list(self.blocked_countries))
    
    async def remove_blocked_country(self, country_code: str):
        """Remove country from blocked list"""
        self.blocked_countries.discard(country_code)
        # Update cache
        cache_key = "geolocation:blocked_countries"
        await cache_service.set(cache_key, list(self.blocked_countries))
    
    async def get_blocked_countries(self) -> List[str]:
        """Get list of blocked countries"""
        return list(self.blocked_countries)


# Create service instance
def get_geolocation_service(db: Optional[AsyncSession] = None) -> GeolocationService:
    return GeolocationService(db=db)