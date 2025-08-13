from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import hashlib
import secrets
from user_agents import parse
import structlog
import httpx
from ipaddress import ip_address, ip_network

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthenticationError, RateLimitError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class DeviceService:
    """
    Device management service for tracking and managing user devices
    """
    
    def __init__(self):
        self.trusted_device_expiry = 30 * 24 * 3600  # 30 days
        self.device_limit_per_user = 10
        self.suspicious_activity_threshold = 5
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def register_device(
        self,
        user_id: str,
        user_agent: str,
        ip_address: str,
        fingerprint: Optional[str] = None,
        location_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Register a new device for a user
        """
        try:
            # Parse user agent
            ua = parse(user_agent)
            
            # Generate device ID
            device_id = self._generate_device_id(user_id, user_agent, ip_address, fingerprint)
            
            # Check if device already exists
            existing_device = await self.get_device(user_id, device_id)
            if existing_device:
                # Update last seen
                return await self.update_device_activity(user_id, device_id, ip_address)
            
            # Check device limit
            user_devices = await self.get_user_devices(user_id)
            if len(user_devices) >= self.device_limit_per_user:
                # Remove oldest device
                oldest_device = min(user_devices, key=lambda d: d.get("last_seen", datetime.min.isoformat()))
                await self.remove_device(user_id, oldest_device["device_id"])
            
            # Get location from IP if not provided
            if not location_data:
                location_data = await self._get_location_from_ip(ip_address)
            
            # Create device record
            device_data = {
                "device_id": device_id,
                "user_id": user_id,
                "name": self._generate_device_name(ua),
                "type": self._get_device_type(ua),
                "browser": {
                    "name": ua.browser.family,
                    "version": ua.browser.version_string
                },
                "os": {
                    "name": ua.os.family,
                    "version": ua.os.version_string
                },
                "user_agent": user_agent,
                "fingerprint": fingerprint,
                "ip_address": ip_address,
                "location": location_data,
                "trusted": False,
                "verified": False,
                "created_at": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat(),
                "login_count": 1,
                "suspicious_activity_count": 0
            }
            
            # Store device data
            device_key = f"device:{user_id}:{device_id}"
            await cache_service.set(device_key, device_data, expire=self.trusted_device_expiry)
            
            # Add to user's device list
            user_devices_key = f"user_devices:{user_id}"
            await cache_service.add_to_set(user_devices_key, device_id)
            
            # Log device registration
            logger.info(
                f"Device registered for user {user_id}",
                device_id=device_id,
                device_type=device_data["type"],
                ip_address=ip_address
            )
            
            # Check for suspicious activity
            await self._check_suspicious_device_activity(user_id, device_data)
            
            return {
                "device_id": device_id,
                "name": device_data["name"],
                "type": device_data["type"],
                "browser": device_data["browser"],
                "os": device_data["os"],
                "location": device_data["location"],
                "trusted": device_data["trusted"],
                "verified": device_data["verified"],
                "created_at": device_data["created_at"],
                "requires_verification": not device_data["verified"]
            }
        
        except Exception as e:
            logger.error(f"Failed to register device: {str(e)}")
            raise ValidationError("Failed to register device")
    
    async def verify_device(
        self,
        user_id: str,
        device_id: str,
        verification_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify a device (mark as trusted)
        """
        try:
            # Get device data
            device = await self.get_device(user_id, device_id)
            if not device:
                raise ValidationError("Device not found")
            
            # If verification code provided, validate it
            if verification_code:
                verification_key = f"device_verification:{user_id}:{device_id}"
                stored_code = await cache_service.get(verification_key)
                
                if not stored_code or stored_code != verification_code:
                    raise ValidationError("Invalid verification code")
                
                # Clear verification code
                await cache_service.delete(verification_key)
            
            # Update device as verified and trusted
            device["verified"] = True
            device["trusted"] = True
            device["verified_at"] = datetime.utcnow().isoformat()
            
            # Save updated device
            device_key = f"device:{user_id}:{device_id}"
            await cache_service.set(device_key, device, expire=self.trusted_device_expiry)
            
            logger.info(f"Device verified for user {user_id}", device_id=device_id)
            
            return {
                "device_id": device_id,
                "verified": True,
                "trusted": True,
                "message": "Device successfully verified and trusted"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to verify device: {str(e)}")
            raise ValidationError("Failed to verify device")
    
    async def trust_device(
        self,
        user_id: str,
        device_id: str,
        duration_days: int = 30
    ) -> Dict[str, Any]:
        """
        Mark a device as trusted for a specified duration
        """
        try:
            # Get device data
            device = await self.get_device(user_id, device_id)
            if not device:
                raise ValidationError("Device not found")
            
            # Update trust status
            device["trusted"] = True
            device["trusted_until"] = (
                datetime.utcnow() + timedelta(days=duration_days)
            ).isoformat()
            
            # Save updated device
            device_key = f"device:{user_id}:{device_id}"
            expiry = duration_days * 24 * 3600
            await cache_service.set(device_key, device, expire=expiry)
            
            logger.info(
                f"Device trusted for user {user_id}",
                device_id=device_id,
                duration_days=duration_days
            )
            
            return {
                "device_id": device_id,
                "trusted": True,
                "trusted_until": device["trusted_until"],
                "message": f"Device trusted for {duration_days} days"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to trust device: {str(e)}")
            raise ValidationError("Failed to trust device")
    
    async def untrust_device(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """
        Remove trust from a device
        """
        try:
            # Get device data
            device = await self.get_device(user_id, device_id)
            if not device:
                raise ValidationError("Device not found")
            
            # Update trust status
            device["trusted"] = False
            device.pop("trusted_until", None)
            
            # Save updated device
            device_key = f"device:{user_id}:{device_id}"
            await cache_service.set(device_key, device, expire=self.trusted_device_expiry)
            
            logger.info(f"Device untrusted for user {user_id}", device_id=device_id)
            
            return {
                "device_id": device_id,
                "trusted": False,
                "message": "Device trust removed"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to untrust device: {str(e)}")
            raise ValidationError("Failed to untrust device")
    
    async def remove_device(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """
        Remove a device from user's device list
        """
        try:
            # Check if device exists
            device = await self.get_device(user_id, device_id)
            if not device:
                raise ValidationError("Device not found")
            
            # Remove device data
            device_key = f"device:{user_id}:{device_id}"
            await cache_service.delete(device_key)
            
            # Remove from user's device list
            user_devices_key = f"user_devices:{user_id}"
            await cache_service.remove_from_set(user_devices_key, device_id)
            
            # Invalidate any active sessions for this device
            await self._invalidate_device_sessions(user_id, device_id)
            
            logger.info(f"Device removed for user {user_id}", device_id=device_id)
            
            return {
                "device_id": device_id,
                "removed": True,
                "message": "Device successfully removed"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove device: {str(e)}")
            raise ValidationError("Failed to remove device")
    
    async def get_device(self, user_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Get device information
        """
        try:
            device_key = f"device:{user_id}:{device_id}"
            device_data = await cache_service.get(device_key)
            
            if device_data:
                # Check if trust period has expired
                if device_data.get("trusted") and device_data.get("trusted_until"):
                    trusted_until = datetime.fromisoformat(device_data["trusted_until"])
                    if datetime.utcnow() > trusted_until:
                        device_data["trusted"] = False
                        device_data.pop("trusted_until", None)
                        # Update device
                        await cache_service.set(device_key, device_data, expire=self.trusted_device_expiry)
            
            return device_data
        
        except Exception as e:
            logger.error(f"Failed to get device: {str(e)}")
            return None
    
    async def get_user_devices(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all devices for a user
        """
        try:
            user_devices_key = f"user_devices:{user_id}"
            device_ids = await cache_service.get_set_members(user_devices_key)
            
            devices = []
            for device_id in device_ids:
                device = await self.get_device(user_id, device_id)
                if device:
                    devices.append(device)
            
            # Sort by last seen (most recent first)
            devices.sort(key=lambda d: d.get("last_seen", ""), reverse=True)
            
            return devices
        
        except Exception as e:
            logger.error(f"Failed to get user devices: {str(e)}")
            return []
    
    async def update_device_activity(
        self,
        user_id: str,
        device_id: str,
        ip_address: str
    ) -> Dict[str, Any]:
        """
        Update device activity (last seen, login count, etc.)
        """
        try:
            device = await self.get_device(user_id, device_id)
            if not device:
                raise ValidationError("Device not found")
            
            # Update activity data
            device["last_seen"] = datetime.utcnow().isoformat()
            device["login_count"] = device.get("login_count", 0) + 1
            
            # Update IP if changed
            if device.get("ip_address") != ip_address:
                device["previous_ip"] = device.get("ip_address")
                device["ip_address"] = ip_address
                
                # Get new location
                location_data = await self._get_location_from_ip(ip_address)
                if location_data:
                    device["location"] = location_data
                
                # Check for suspicious IP change
                await self._check_suspicious_ip_change(user_id, device_id, device)
            
            # Save updated device
            device_key = f"device:{user_id}:{device_id}"
            await cache_service.set(device_key, device, expire=self.trusted_device_expiry)
            
            return {
                "device_id": device_id,
                "last_seen": device["last_seen"],
                "login_count": device["login_count"],
                "trusted": device.get("trusted", False)
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to update device activity: {str(e)}")
            raise ValidationError("Failed to update device activity")
    
    async def check_device_trust(
        self,
        user_id: str,
        device_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a device is trusted
        Returns (is_trusted, reason)
        """
        try:
            device = await self.get_device(user_id, device_id)
            
            if not device:
                return False, "Device not found"
            
            if not device.get("verified"):
                return False, "Device not verified"
            
            if not device.get("trusted"):
                return False, "Device not marked as trusted"
            
            # Check if trust period has expired
            if device.get("trusted_until"):
                trusted_until = datetime.fromisoformat(device["trusted_until"])
                if datetime.utcnow() > trusted_until:
                    return False, "Trust period expired"
            
            # Check for suspicious activity
            if device.get("suspicious_activity_count", 0) >= self.suspicious_activity_threshold:
                return False, "Too many suspicious activities detected"
            
            return True, None
        
        except Exception as e:
            logger.error(f"Failed to check device trust: {str(e)}")
            return False, "Error checking device trust"
    
    async def send_device_verification_code(
        self,
        user_id: str,
        device_id: str,
        method: str = "email"
    ) -> Dict[str, Any]:
        """
        Send verification code for device
        """
        try:
            # Generate verification code
            code = ''.join(secrets.choice('0123456789') for _ in range(6))
            
            # Store verification code
            verification_key = f"device_verification:{user_id}:{device_id}"
            await cache_service.set(verification_key, code, expire=600)  # 10 minutes
            
            # Get user info from Clerk
            clerk_client = await self._get_clerk_client()
            user = await clerk_client.get_user(user_id)
            
            if method == "email" and user.email_addresses:
                email = user.email_addresses[0].email_address
                # Send email with verification code
                from app.tasks.email_tasks import send_verification_email
                send_verification_email.delay(email, code)
                
                logger.info(f"Device verification code sent to user {user_id}")
                
                return {
                    "sent": True,
                    "method": method,
                    "expires_in": 600,
                    "message": f"Verification code sent via {method}"
                }
            else:
                raise ValidationError(f"Verification method {method} not available")
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to send device verification code: {str(e)}")
            raise ValidationError("Failed to send verification code")
    
    async def get_device_sessions(
        self,
        user_id: str,
        device_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a device
        """
        try:
            sessions_key = f"device_sessions:{user_id}:{device_id}"
            session_ids = await cache_service.get_set_members(sessions_key)
            
            sessions = []
            for session_id in session_ids:
                session_data = await cache_service.get(f"session:{session_id}")
                if session_data:
                    sessions.append({
                        "session_id": session_id,
                        "created_at": session_data.get("created_at"),
                        "last_activity": session_data.get("last_activity"),
                        "ip_address": session_data.get("ip_address")
                    })
            
            return sessions
        
        except Exception as e:
            logger.error(f"Failed to get device sessions: {str(e)}")
            return []
    
    # ============= Helper Methods =============
    
    def _generate_device_id(
        self,
        user_id: str,
        user_agent: str,
        ip_address: str,
        fingerprint: Optional[str] = None
    ) -> str:
        """Generate unique device ID"""
        data = f"{user_id}:{user_agent}:{fingerprint or ip_address}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _generate_device_name(self, ua) -> str:
        """Generate human-readable device name"""
        device_type = self._get_device_type(ua)
        os_name = ua.os.family
        browser_name = ua.browser.family
        
        if device_type == "mobile":
            if ua.device.brand and ua.device.model:
                return f"{ua.device.brand} {ua.device.model}"
            return f"{os_name} Mobile"
        elif device_type == "tablet":
            if ua.device.brand and ua.device.model:
                return f"{ua.device.brand} {ua.device.model}"
            return f"{os_name} Tablet"
        else:
            return f"{browser_name} on {os_name}"
    
    def _get_device_type(self, ua) -> str:
        """Determine device type from user agent"""
        if ua.is_mobile:
            return "mobile"
        elif ua.is_tablet:
            return "tablet"
        elif ua.is_pc:
            return "desktop"
        elif ua.is_bot:
            return "bot"
        else:
            return "unknown"
    
    async def _get_location_from_ip(self, ip_addr: str) -> Optional[Dict[str, Any]]:
        """Get location data from IP address"""
        try:
            # Check if it's a private IP
            ip_obj = ip_address(ip_addr)
            if ip_obj.is_private:
                return {
                    "country": "Private Network",
                    "city": "Local",
                    "is_private": True
                }
            
            # Use IP geolocation service (example with ipapi.co)
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://ipapi.co/{ip_addr}/json/",
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "postal": data.get("postal"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "timezone": data.get("timezone"),
                        "is_private": False
                    }
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get location from IP: {str(e)}")
            return None
    
    async def _check_suspicious_device_activity(
        self,
        user_id: str,
        device_data: Dict[str, Any]
    ):
        """Check for suspicious device activity"""
        try:
            # Check for multiple devices from different locations in short time
            user_devices = await self.get_user_devices(user_id)
            
            recent_devices = []
            cutoff_time = datetime.utcnow() - timedelta(hours=1)
            
            for device in user_devices:
                created_at = datetime.fromisoformat(device.get("created_at", ""))
                if created_at > cutoff_time:
                    recent_devices.append(device)
            
            # If multiple devices from different countries in last hour
            if len(recent_devices) > 1:
                countries = set()
                for device in recent_devices:
                    location = device.get("location", {})
                    if location and not location.get("is_private"):
                        countries.add(location.get("country_code"))
                
                if len(countries) > 1:
                    logger.warning(
                        f"Suspicious activity: Multiple devices from different countries",
                        user_id=user_id,
                        countries=list(countries)
                    )
                    
                    # Send security alert
                    from app.tasks.email_tasks import send_security_alert
                    send_security_alert.delay(
                        user_id,
                        "Multiple Device Logins",
                        {"countries": list(countries), "device_count": len(recent_devices)}
                    )
        
        except Exception as e:
            logger.error(f"Failed to check suspicious activity: {str(e)}")
    
    async def _check_suspicious_ip_change(
        self,
        user_id: str,
        device_id: str,
        device_data: Dict[str, Any]
    ):
        """Check for suspicious IP changes"""
        try:
            current_location = device_data.get("location", {})
            previous_ip = device_data.get("previous_ip")
            
            if previous_ip and current_location and not current_location.get("is_private"):
                # Get previous location
                previous_location = await self._get_location_from_ip(previous_ip)
                
                if previous_location and not previous_location.get("is_private"):
                    # Check if country changed
                    if current_location.get("country_code") != previous_location.get("country_code"):
                        # Calculate time since last activity
                        last_seen = datetime.fromisoformat(device_data.get("last_seen", datetime.utcnow().isoformat()))
                        time_diff = (datetime.utcnow() - last_seen).total_seconds() / 3600  # hours
                        
                        # If country changed in less than reasonable travel time
                        if time_diff < 2:  # Less than 2 hours
                            logger.warning(
                                f"Suspicious IP change detected",
                                user_id=user_id,
                                device_id=device_id,
                                from_country=previous_location.get("country_code"),
                                to_country=current_location.get("country_code"),
                                time_diff_hours=time_diff
                            )
                            
                            # Increment suspicious activity count
                            device_data["suspicious_activity_count"] = device_data.get("suspicious_activity_count", 0) + 1
                            
                            # Send alert if threshold reached
                            if device_data["suspicious_activity_count"] >= self.suspicious_activity_threshold:
                                from app.tasks.email_tasks import send_security_alert
                                send_security_alert.delay(
                                    user_id,
                                    "Suspicious Location Change",
                                    {
                                        "from_country": previous_location.get("country"),
                                        "to_country": current_location.get("country"),
                                        "device": device_data.get("name")
                                    }
                                )
        
        except Exception as e:
            logger.error(f"Failed to check suspicious IP change: {str(e)}")
    
    async def _invalidate_device_sessions(self, user_id: str, device_id: str):
        """Invalidate all sessions for a device"""
        try:
            sessions_key = f"device_sessions:{user_id}:{device_id}"
            session_ids = await cache_service.get_set_members(sessions_key)
            
            for session_id in session_ids:
                await cache_service.delete(f"session:{session_id}")
            
            # Clear device sessions set
            await cache_service.delete(sessions_key)
            
            logger.info(f"Invalidated all sessions for device {device_id}")
        
        except Exception as e:
            logger.error(f"Failed to invalidate device sessions: {str(e)}")
    
    async def get_device_analytics(self, user_id: str) -> Dict[str, Any]:
        """
        Get device analytics for a user
        """
        try:
            devices = await self.get_user_devices(user_id)
            
            # Calculate analytics
            total_devices = len(devices)
            trusted_devices = len([d for d in devices if d.get("trusted")])
            verified_devices = len([d for d in devices if d.get("verified")])
            
            # Device type breakdown
            device_types = {}
            for device in devices:
                device_type = device.get("type", "unknown")
                device_types[device_type] = device_types.get(device_type, 0) + 1
            
            # Browser breakdown
            browsers = {}
            for device in devices:
                browser_name = device.get("browser", {}).get("name", "unknown")
                browsers[browser_name] = browsers.get(browser_name, 0) + 1
            
            # OS breakdown
            operating_systems = {}
            for device in devices:
                os_name = device.get("os", {}).get("name", "unknown")
                operating_systems[os_name] = operating_systems.get(os_name, 0) + 1
            
            # Location breakdown
            locations = {}
            for device in devices:
                location = device.get("location", {})
                if location and not location.get("is_private"):
                    country = location.get("country", "Unknown")
                    locations[country] = locations.get(country, 0) + 1
            
            return {
                "total_devices": total_devices,
                "trusted_devices": trusted_devices,
                "verified_devices": verified_devices,
                "device_types": device_types,
                "browsers": browsers,
                "operating_systems": operating_systems,
                "locations": locations,
                "device_limit": self.device_limit_per_user,
                "remaining_slots": max(0, self.device_limit_per_user - total_devices)
            }
        
        except Exception as e:
            logger.error(f"Failed to get device analytics: {str(e)}")
            return {}


# Singleton instance
device_service = DeviceService()