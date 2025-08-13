from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import secrets
import hashlib
import dns.resolver
import structlog
from enum import Enum

from app.core.config import settings
from app.core.exceptions import ValidationError, AuthorizationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class DomainStatus(Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class DomainService:
    """
    Service for managing organization domain verification and auto-join rules
    """
    
    def __init__(self):
        self.max_domains_per_org = 10
        self.verification_expiry_hours = 72
        self.dns_record_type = "TXT"
        self.dns_record_prefix = "_fastapi-auth-verification"
        self.auto_join_enabled = True
        self.clerk_client = None
    
    async def _get_clerk_client(self):
        """Get Clerk client instance"""
        if not self.clerk_client:
            self.clerk_client = get_clerk_client()
        return self.clerk_client
    
    async def add_domain(
        self,
        org_id: str,
        domain: str,
        added_by: str,
        auto_join_enabled: bool = True,
        default_role: str = "member"
    ) -> Dict[str, Any]:
        """
        Add a domain to an organization for verification
        """
        try:
            # Validate domain format
            if not self._validate_domain_format(domain):
                raise ValidationError("Invalid domain format")
            
            # Normalize domain (lowercase, remove www)
            normalized_domain = self._normalize_domain(domain)
            
            # Check if domain already exists for this org
            existing_domain = await self._get_org_domain(org_id, normalized_domain)
            if existing_domain:
                if existing_domain["status"] == DomainStatus.VERIFIED.value:
                    raise ValidationError("Domain is already verified for this organization")
                elif existing_domain["status"] == DomainStatus.PENDING.value:
                    raise ValidationError("Domain verification is already pending")
            
            # Check if domain is claimed by another organization
            if await self._is_domain_claimed(normalized_domain):
                raise ValidationError("Domain is already claimed by another organization")
            
            # Check domain limit
            org_domains = await self.get_organization_domains(org_id)
            if len(org_domains) >= self.max_domains_per_org:
                raise ValidationError(f"Maximum of {self.max_domains_per_org} domains allowed per organization")
            
            # Generate verification token
            verification_token = secrets.token_hex(32)
            domain_id = secrets.token_urlsafe(16)
            
            # Create domain record
            domain_data = {
                "domain_id": domain_id,
                "org_id": org_id,
                "domain": normalized_domain,
                "status": DomainStatus.PENDING.value,
                "verification_token": verification_token,
                "verification_method": "dns",
                "dns_record_name": f"{self.dns_record_prefix}.{normalized_domain}",
                "dns_record_value": f"fastapi-auth-verification={verification_token}",
                "auto_join_enabled": auto_join_enabled,
                "default_role": default_role,
                "added_by": added_by,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(hours=self.verification_expiry_hours)).isoformat(),
                "verification_attempts": 0
            }
            
            # Store domain data
            domain_key = f"domain:{domain_id}"
            await cache_service.set(
                domain_key,
                domain_data,
                expire=self.verification_expiry_hours * 3600
            )
            
            # Add to organization's domain list
            org_domains_key = f"org_domains:{org_id}"
            await cache_service.add_to_set(org_domains_key, domain_id)
            
            # Create domain index for quick lookup
            domain_index_key = f"domain_index:{normalized_domain}"
            await cache_service.set(domain_index_key, domain_id)
            
            logger.info(
                f"Domain added for verification",
                domain_id=domain_id,
                org_id=org_id,
                domain=normalized_domain
            )
            
            return {
                "domain_id": domain_id,
                "domain": normalized_domain,
                "status": DomainStatus.PENDING.value,
                "verification_method": "dns",
                "dns_record": {
                    "type": self.dns_record_type,
                    "name": domain_data["dns_record_name"],
                    "value": domain_data["dns_record_value"]
                },
                "expires_at": domain_data["expires_at"],
                "message": "Add the DNS TXT record to verify domain ownership"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to add domain: {str(e)}")
            raise ValidationError("Failed to add domain")
    
    async def verify_domain(
        self,
        domain_id: str,
        manual_trigger: bool = False
    ) -> Dict[str, Any]:
        """
        Verify domain ownership through DNS records
        """
        try:
            # Get domain data
            domain_key = f"domain:{domain_id}"
            domain_data = await cache_service.get(domain_key)
            
            if not domain_data:
                raise ValidationError("Domain not found")
            
            # Check if already verified
            if domain_data["status"] == DomainStatus.VERIFIED.value:
                return {
                    "verified": True,
                    "message": "Domain is already verified"
                }
            
            # Check if expired
            expires_at = datetime.fromisoformat(domain_data["expires_at"])
            if datetime.utcnow() > expires_at:
                domain_data["status"] = DomainStatus.EXPIRED.value
                await self._update_domain(domain_id, domain_data)
                raise ValidationError("Domain verification has expired")
            
            # Increment verification attempts
            domain_data["verification_attempts"] += 1
            domain_data["last_verification_attempt"] = datetime.utcnow().isoformat()
            
            # Perform DNS verification
            is_verified = await self._verify_dns_record(
                domain_data["domain"],
                domain_data["verification_token"]
            )
            
            if is_verified:
                # Mark as verified
                domain_data["status"] = DomainStatus.VERIFIED.value
                domain_data["verified_at"] = datetime.utcnow().isoformat()
                
                # Remove expiry
                domain_data.pop("expires_at", None)
                
                # Update domain data (store permanently)
                await cache_service.set(domain_key, domain_data)
                
                # Update domain index
                domain_index_key = f"domain_verified:{domain_data['domain']}"
                await cache_service.set(domain_index_key, domain_data["org_id"])
                
                logger.info(
                    f"Domain verified successfully",
                    domain_id=domain_id,
                    domain=domain_data["domain"]
                )
                
                return {
                    "verified": True,
                    "domain": domain_data["domain"],
                    "message": "Domain verified successfully"
                }
            else:
                # Update attempts
                await self._update_domain(domain_id, domain_data)
                
                return {
                    "verified": False,
                    "attempts": domain_data["verification_attempts"],
                    "message": "DNS record not found or incorrect. Please check your DNS settings."
                }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to verify domain: {str(e)}")
            raise ValidationError("Failed to verify domain")
    
    async def remove_domain(
        self,
        domain_id: str,
        removed_by: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Remove a domain from an organization
        """
        try:
            # Get domain data
            domain_key = f"domain:{domain_id}"
            domain_data = await cache_service.get(domain_key)
            
            if not domain_data:
                raise ValidationError("Domain not found")
            
            # Remove from organization's domain list
            org_domains_key = f"org_domains:{domain_data['org_id']}"
            await cache_service.remove_from_set(org_domains_key, domain_id)
            
            # Remove domain index
            domain_index_key = f"domain_index:{domain_data['domain']}"
            await cache_service.delete(domain_index_key)
            
            # Remove verified index if exists
            if domain_data["status"] == DomainStatus.VERIFIED.value:
                domain_verified_key = f"domain_verified:{domain_data['domain']}"
                await cache_service.delete(domain_verified_key)
            
            # Mark as removed (keep for audit)
            domain_data["removed"] = True
            domain_data["removed_by"] = removed_by
            domain_data["removed_at"] = datetime.utcnow().isoformat()
            domain_data["removal_reason"] = reason
            await cache_service.set(domain_key, domain_data, expire=30 * 86400)  # Keep for 30 days
            
            logger.info(
                f"Domain removed",
                domain_id=domain_id,
                domain=domain_data["domain"],
                removed_by=removed_by
            )
            
            return {
                "success": True,
                "domain": domain_data["domain"],
                "message": "Domain removed successfully"
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove domain: {str(e)}")
            raise ValidationError("Failed to remove domain")
    
    async def update_domain_settings(
        self,
        domain_id: str,
        auto_join_enabled: Optional[bool] = None,
        default_role: Optional[str] = None,
        allowed_email_patterns: Optional[List[str]] = None,
        blocked_email_patterns: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Update domain auto-join settings
        """
        try:
            # Get domain data
            domain_key = f"domain:{domain_id}"
            domain_data = await cache_service.get(domain_key)
            
            if not domain_data:
                raise ValidationError("Domain not found")
            
            if domain_data["status"] != DomainStatus.VERIFIED.value:
                raise ValidationError("Domain must be verified to update settings")
            
            # Update settings
            if auto_join_enabled is not None:
                domain_data["auto_join_enabled"] = auto_join_enabled
            
            if default_role is not None:
                if default_role not in ["member", "admin"]:
                    raise ValidationError("Invalid default role")
                domain_data["default_role"] = default_role
            
            if allowed_email_patterns is not None:
                domain_data["allowed_email_patterns"] = allowed_email_patterns
            
            if blocked_email_patterns is not None:
                domain_data["blocked_email_patterns"] = blocked_email_patterns
            
            domain_data["settings_updated_at"] = datetime.utcnow().isoformat()
            
            # Save updated data
            await cache_service.set(domain_key, domain_data)
            
            logger.info(
                f"Domain settings updated",
                domain_id=domain_id,
                domain=domain_data["domain"]
            )
            
            return {
                "domain_id": domain_id,
                "domain": domain_data["domain"],
                "auto_join_enabled": domain_data["auto_join_enabled"],
                "default_role": domain_data["default_role"],
                "allowed_email_patterns": domain_data.get("allowed_email_patterns"),
                "blocked_email_patterns": domain_data.get("blocked_email_patterns")
            }
        
        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to update domain settings: {str(e)}")
            raise ValidationError("Failed to update domain settings")
    
    async def check_auto_join_eligibility(
        self,
        email: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if an email is eligible for auto-join based on domain
        Returns (is_eligible, org_info)
        """
        try:
            # Extract domain from email
            if "@" not in email:
                return False, None
            
            domain = email.split("@")[1].lower()
            
            # Check if domain is verified for any organization
            domain_verified_key = f"domain_verified:{domain}"
            org_id = await cache_service.get(domain_verified_key)
            
            if not org_id:
                return False, None
            
            # Get domain data
            domain_index_key = f"domain_index:{domain}"
            domain_id = await cache_service.get(domain_index_key)
            
            if not domain_id:
                return False, None
            
            domain_key = f"domain:{domain_id}"
            domain_data = await cache_service.get(domain_key)
            
            if not domain_data:
                return False, None
            
            # Check if auto-join is enabled
            if not domain_data.get("auto_join_enabled"):
                return False, None
            
            # Check email patterns
            if domain_data.get("allowed_email_patterns"):
                # Check if email matches allowed patterns
                email_local = email.split("@")[0]
                matched = False
                for pattern in domain_data["allowed_email_patterns"]:
                    if self._match_email_pattern(email_local, pattern):
                        matched = True
                        break
                if not matched:
                    return False, None
            
            if domain_data.get("blocked_email_patterns"):
                # Check if email matches blocked patterns
                email_local = email.split("@")[0]
                for pattern in domain_data["blocked_email_patterns"]:
                    if self._match_email_pattern(email_local, pattern):
                        return False, None
            
            # Get organization info
            clerk_client = await self._get_clerk_client()
            org = await clerk_client.get_organization(org_id)
            
            return True, {
                "org_id": org_id,
                "org_name": org.name,
                "default_role": domain_data.get("default_role", "member"),
                "domain": domain
            }
        
        except Exception as e:
            logger.error(f"Failed to check auto-join eligibility: {str(e)}")
            return False, None
    
    async def get_organization_domains(
        self,
        org_id: str,
        include_removed: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get all domains for an organization
        """
        try:
            org_domains_key = f"org_domains:{org_id}"
            domain_ids = await cache_service.get_set_members(org_domains_key)
            
            domains = []
            for domain_id in domain_ids:
                domain_key = f"domain:{domain_id}"
                domain_data = await cache_service.get(domain_key)
                
                if domain_data:
                    # Skip removed domains unless requested
                    if domain_data.get("removed") and not include_removed:
                        continue
                    
                    # Check if expired
                    if domain_data["status"] == DomainStatus.PENDING.value:
                        if "expires_at" in domain_data:
                            expires_at = datetime.fromisoformat(domain_data["expires_at"])
                            if datetime.utcnow() > expires_at:
                                domain_data["status"] = DomainStatus.EXPIRED.value
                                await self._update_domain(domain_id, domain_data)
                    
                    # Add safe data (exclude verification token)
                    safe_data = {
                        "domain_id": domain_data["domain_id"],
                        "domain": domain_data["domain"],
                        "status": domain_data["status"],
                        "auto_join_enabled": domain_data.get("auto_join_enabled"),
                        "default_role": domain_data.get("default_role"),
                        "created_at": domain_data["created_at"],
                        "verification_attempts": domain_data.get("verification_attempts", 0)
                    }
                    
                    if domain_data["status"] == DomainStatus.VERIFIED.value:
                        safe_data["verified_at"] = domain_data.get("verified_at")
                    elif domain_data["status"] == DomainStatus.PENDING.value:
                        safe_data["expires_at"] = domain_data.get("expires_at")
                        safe_data["dns_record"] = {
                            "type": self.dns_record_type,
                            "name": domain_data["dns_record_name"],
                            "value": domain_data["dns_record_value"]
                        }
                    
                    domains.append(safe_data)
            
            # Sort by status (verified first) then by creation date
            domains.sort(key=lambda x: (
                0 if x["status"] == DomainStatus.VERIFIED.value else 1,
                x["created_at"]
            ))
            
            return domains
        
        except Exception as e:
            logger.error(f"Failed to get organization domains: {str(e)}")
            return []
    
    async def get_verified_domains_count(self, org_id: str) -> int:
        """
        Get count of verified domains for an organization
        """
        try:
            domains = await self.get_organization_domains(org_id)
            return len([d for d in domains if d["status"] == DomainStatus.VERIFIED.value])
        except:
            return 0
    
    # ============= Helper Methods =============
    
    def _validate_domain_format(self, domain: str) -> bool:
        """Validate domain format"""
        import re
        # Basic domain validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain (lowercase, remove www)"""
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    
    async def _is_domain_claimed(self, domain: str) -> bool:
        """Check if domain is already claimed by another organization"""
        domain_verified_key = f"domain_verified:{domain}"
        return await cache_service.exists(domain_verified_key)
    
    async def _verify_dns_record(self, domain: str, verification_token: str) -> bool:
        """Verify DNS TXT record for domain"""
        try:
            # Query DNS for TXT records
            dns_name = f"{self.dns_record_prefix}.{domain}"
            expected_value = f"fastapi-auth-verification={verification_token}"
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(dns_name, self.dns_record_type)
                
                for rdata in answers:
                    # TXT records may be in quotes
                    txt_value = str(rdata).strip('"')
                    if txt_value == expected_value:
                        return True
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # DNS record not found
                pass
            
            return False
        
        except Exception as e:
            logger.error(f"DNS verification failed: {str(e)}")
            return False
    
    def _match_email_pattern(self, email_local: str, pattern: str) -> bool:
        """Match email local part against pattern (supports wildcards)"""
        import fnmatch
        return fnmatch.fnmatch(email_local, pattern)
    
    async def _update_domain(self, domain_id: str, domain_data: Dict[str, Any]):
        """Update domain data"""
        domain_key = f"domain:{domain_id}"
        
        # Calculate remaining TTL if pending
        if domain_data["status"] == DomainStatus.PENDING.value and "expires_at" in domain_data:
            expires_at = datetime.fromisoformat(domain_data["expires_at"])
            remaining_seconds = max(0, int((expires_at - datetime.utcnow()).total_seconds()))
            if remaining_seconds > 0:
                await cache_service.set(domain_key, domain_data, expire=remaining_seconds)
            else:
                await cache_service.set(domain_key, domain_data, expire=86400)  # 1 day
        else:
            await cache_service.set(domain_key, domain_data)
    
    async def _get_org_domain(self, org_id: str, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain data for a specific domain in an organization"""
        domains = await self.get_organization_domains(org_id, include_removed=True)
        for domain_data in domains:
            if domain_data["domain"] == domain:
                # Get full domain data
                domain_key = f"domain:{domain_data['domain_id']}"
                return await cache_service.get(domain_key)
        return None


# Singleton instance
domain_service = DomainService()