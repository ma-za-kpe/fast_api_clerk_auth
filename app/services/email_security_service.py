from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta
import re
import hashlib
import dns.resolver
import httpx
import structlog
from email_validator import validate_email, EmailNotValidError

from app.core.config import settings
from app.core.exceptions import ValidationError, SecurityError
from app.services.cache_service import cache_service

logger = structlog.get_logger()


class EmailSecurityService:
    """
    Service for email security including disposable email blocking,
    domain reputation checking, and advanced email validation
    """
    
    def __init__(self):
        # Load disposable email domains list
        self.disposable_domains = self._load_disposable_domains()
        
        # Custom blocked domains (configured by admin)
        self.custom_blocked_domains: Set[str] = set()
        self.custom_allowed_domains: Set[str] = set()
        
        # Subaddress configuration
        self.allow_subaddress = getattr(settings, 'ALLOW_EMAIL_SUBADDRESS', True)
        self.subaddress_separators = ['+', '.']  # Gmail uses +, some use .
        
        # Email validation settings
        self.check_deliverability = getattr(settings, 'CHECK_EMAIL_DELIVERABILITY', False)
        self.strict_validation = getattr(settings, 'STRICT_EMAIL_VALIDATION', True)
        
        # Cache settings
        self.domain_check_cache_ttl = 3600  # 1 hour
        self.email_check_cache_ttl = 300  # 5 minutes
        
        # Rate limiting
        self.max_validations_per_ip = 50
        self.rate_limit_window = 3600  # 1 hour
    
    def _load_disposable_domains(self) -> Set[str]:
        """
        Load list of known disposable email domains
        """
        # This is a subset of common disposable email domains
        # In production, you'd load from a comprehensive list or API
        disposable = {
            # Temporary email services
            '10minutemail.com', '10minutemail.net', 'tempmail.com', 'temp-mail.org',
            'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
            'mailinator.com', 'mailinator.net', 'mailinator2.com',
            'yopmail.com', 'yopmail.fr', 'yopmail.net',
            'throwaway.email', 'throwawaymail.com',
            'maildrop.cc', 'mailnesia.com', 'trashmail.com',
            'sharklasers.com', 'spam4.me', 'grr.la',
            'guerrillamailblock.com', 'pokemail.net',
            'spamgourmet.com', 'spamex.com',
            'tempmailaddress.com', 'tempinbox.com',
            'disposableemailaddresses.com', 'fakeinbox.com',
            'trashmail.net', 'trashmail.de', 'trashmail.ws',
            'mytrashmail.com', 'mt2009.com', 'thankyou2010.com',
            'trash2009.com', 'temporaryemail.net',
            'spambox.us', 'spamfree24.org', 'spamhereplease.com',
            'bugmenot.com', 'emailondeck.com', 'getnada.com',
            'mail-temporaire.fr', 'jetable.org', 'kasmail.com',
            'nospam.ze.tc', 'speed.1s.fr', 'courriel.fr.nf',
            'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
            
            # Anonymous/privacy focused (some legit, but often abused)
            'protonmail.com', 'protonmail.ch', 'pm.me',
            'tutanota.com', 'tutanota.de', 'tutamail.com',
            'cock.li', 'cock.email', 'airmail.cc',
            'nuke.africa', 'waifu.club', 'national.shitposting.agency',
            
            # Known problematic domains
            'example.com', 'example.org', 'example.net',
            'test.com', 'test.org', 'localhost',
            'mailcatch.com', 'mailnull.com', 'nullbox.info',
            'emailias.com', 'mailin8r.com', 'mailexpire.com',
            'spamevader.com', 'spamgourmet.net'
        }
        
        return disposable
    
    async def validate_email(
        self,
        email: str,
        check_disposable: bool = True,
        check_deliverability: bool = None,
        allow_smtputf8: bool = True,
        allow_empty_local: bool = False
    ) -> Dict[str, Any]:
        """
        Comprehensive email validation with security checks
        """
        try:
            # Check cache first
            cache_key = f"email_validation:{hashlib.md5(email.encode()).hexdigest()}"
            cached_result = await cache_service.get(cache_key)
            if cached_result:
                return cached_result
            
            result = {
                "valid": False,
                "email": email,
                "normalized": None,
                "domain": None,
                "is_disposable": False,
                "is_subaddress": False,
                "is_role_based": False,
                "is_free_provider": False,
                "mx_records": False,
                "risk_score": 0.0,
                "errors": []
            }
            
            # Step 1: Basic format validation using email-validator
            try:
                validation = validate_email(
                    email,
                    check_deliverability=check_deliverability if check_deliverability is not None else self.check_deliverability
                )
                
                result["normalized"] = validation.normalized
                result["domain"] = validation.domain
                result["valid"] = True
                
            except EmailNotValidError as e:
                result["errors"].append(str(e))
                result["risk_score"] = 1.0
                return result
            
            # Step 2: Check for subaddress (+ or . addressing)
            local_part = result["normalized"].split('@')[0]
            for separator in self.subaddress_separators:
                if separator in local_part:
                    result["is_subaddress"] = True
                    if not self.allow_subaddress:
                        result["valid"] = False
                        result["errors"].append("Subaddress not allowed")
                        result["risk_score"] = 0.7
                    break
            
            # Step 3: Check if disposable email
            if check_disposable:
                is_disposable = await self.is_disposable_email(result["domain"])
                result["is_disposable"] = is_disposable
                if is_disposable:
                    result["valid"] = False
                    result["errors"].append("Disposable email addresses are not allowed")
                    result["risk_score"] = 0.9
            
            # Step 4: Check if role-based email
            is_role = self._is_role_based_email(local_part)
            result["is_role_based"] = is_role
            if is_role:
                result["risk_score"] = max(result["risk_score"], 0.5)
            
            # Step 5: Check if free email provider
            is_free = self._is_free_email_provider(result["domain"])
            result["is_free_provider"] = is_free
            if is_free:
                result["risk_score"] = max(result["risk_score"], 0.3)
            
            # Step 6: Check domain reputation and MX records
            if result["valid"] and self.check_deliverability:
                domain_check = await self.check_domain_reputation(result["domain"])
                result["mx_records"] = domain_check.get("has_mx_records", False)
                result["domain_reputation"] = domain_check.get("reputation", "unknown")
                
                if not result["mx_records"]:
                    result["valid"] = False
                    result["errors"].append("Domain has no valid MX records")
                    result["risk_score"] = 1.0
            
            # Step 7: Check custom blocked/allowed lists
            if result["domain"] in self.custom_blocked_domains:
                result["valid"] = False
                result["errors"].append("Domain is blocked by administrator")
                result["risk_score"] = 1.0
            elif result["domain"] in self.custom_allowed_domains:
                # Override other checks if explicitly allowed
                result["valid"] = True
                result["risk_score"] = min(result["risk_score"], 0.2)
            
            # Cache the result
            await cache_service.set(cache_key, result, expire=self.email_check_cache_ttl)
            
            # Log high-risk validations
            if result["risk_score"] >= 0.7:
                logger.warning(
                    "High-risk email validation",
                    email=email,
                    risk_score=result["risk_score"],
                    errors=result["errors"]
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Email validation error: {str(e)}")
            return {
                "valid": False,
                "email": email,
                "errors": [f"Validation error: {str(e)}"],
                "risk_score": 0.5
            }
    
    async def is_disposable_email(self, domain: str) -> bool:
        """
        Check if email domain is disposable/temporary
        """
        try:
            # Check cache
            cache_key = f"disposable_check:{domain}"
            cached = await cache_service.get(cache_key)
            if cached is not None:
                return cached
            
            # Check against known list
            is_disposable = domain.lower() in self.disposable_domains
            
            # If not in local list, check online service (optional)
            if not is_disposable and getattr(settings, 'CHECK_DISPOSABLE_API', False):
                is_disposable = await self._check_disposable_api(domain)
            
            # Cache result
            await cache_service.set(cache_key, is_disposable, expire=self.domain_check_cache_ttl)
            
            return is_disposable
            
        except Exception as e:
            logger.error(f"Error checking disposable email: {str(e)}")
            return False
    
    async def _check_disposable_api(self, domain: str) -> bool:
        """
        Check domain against online disposable email API
        """
        try:
            # Example using debounce.io API (requires API key)
            api_key = getattr(settings, 'DEBOUNCE_API_KEY', None)
            if not api_key:
                return False
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://api.debounce.io/v1/",
                    params={
                        "email": f"test@{domain}",
                        "api": api_key
                    },
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("disposable", False) == "true"
                    
        except Exception as e:
            logger.error(f"Disposable API check failed: {str(e)}")
        
        return False
    
    def _is_role_based_email(self, local_part: str) -> bool:
        """
        Check if email is role-based (admin@, support@, etc.)
        """
        role_prefixes = {
            'admin', 'administrator', 'webmaster', 'postmaster',
            'support', 'help', 'contact', 'sales', 'info',
            'marketing', 'noreply', 'no-reply', 'donotreply',
            'abuse', 'spam', 'privacy', 'security',
            'hostmaster', 'usenet', 'news', 'www',
            'ftp', 'mail', 'email', 'test', 'testing'
        }
        
        local_lower = local_part.lower()
        return local_lower in role_prefixes or any(
            local_lower.startswith(prefix) for prefix in role_prefixes
        )
    
    def _is_free_email_provider(self, domain: str) -> bool:
        """
        Check if domain is a free email provider
        """
        free_providers = {
            'gmail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.fr',
            'hotmail.com', 'outlook.com', 'live.com', 'msn.com',
            'aol.com', 'icloud.com', 'me.com', 'mac.com',
            'mail.com', 'gmx.com', 'gmx.net', 'gmx.de',
            'yandex.com', 'yandex.ru', 'mail.ru',
            'qq.com', '163.com', '126.com', 'sina.com',
            'zoho.com', 'rediffmail.com'
        }
        
        return domain.lower() in free_providers
    
    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation and MX records
        """
        try:
            # Check cache
            cache_key = f"domain_reputation:{domain}"
            cached = await cache_service.get(cache_key)
            if cached:
                return cached
            
            result = {
                "domain": domain,
                "has_mx_records": False,
                "mx_hosts": [],
                "has_spf": False,
                "has_dmarc": False,
                "reputation": "unknown",
                "risk_score": 0.0
            }
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                result["has_mx_records"] = len(mx_records) > 0
                result["mx_hosts"] = [str(mx.exchange) for mx in mx_records[:5]]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                result["risk_score"] = 0.8
            
            # Check SPF record
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    if 'v=spf1' in str(record):
                        result["has_spf"] = True
                        break
            except:
                pass
            
            # Check DMARC record
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    if 'v=DMARC1' in str(record):
                        result["has_dmarc"] = True
                        break
            except:
                pass
            
            # Calculate reputation based on checks
            if result["has_mx_records"]:
                if result["has_spf"] and result["has_dmarc"]:
                    result["reputation"] = "excellent"
                    result["risk_score"] = 0.1
                elif result["has_spf"] or result["has_dmarc"]:
                    result["reputation"] = "good"
                    result["risk_score"] = 0.3
                else:
                    result["reputation"] = "fair"
                    result["risk_score"] = 0.5
            else:
                result["reputation"] = "poor"
                result["risk_score"] = 0.9
            
            # Cache result
            await cache_service.set(cache_key, result, expire=self.domain_check_cache_ttl)
            
            return result
            
        except Exception as e:
            logger.error(f"Domain reputation check error: {str(e)}")
            return {
                "domain": domain,
                "has_mx_records": False,
                "reputation": "unknown",
                "risk_score": 0.5,
                "error": str(e)
            }
    
    async def add_blocked_domain(self, domain: str, reason: Optional[str] = None) -> bool:
        """
        Add domain to custom blocked list
        """
        try:
            domain_lower = domain.lower()
            self.custom_blocked_domains.add(domain_lower)
            
            # Store in cache for persistence
            cache_key = "email_security:blocked_domains"
            blocked_list = list(self.custom_blocked_domains)
            await cache_service.set(cache_key, blocked_list, expire=None)
            
            # Log the action
            logger.info(
                "Domain added to blocklist",
                domain=domain,
                reason=reason
            )
            
            # Clear validation cache for this domain
            await self._clear_domain_cache(domain_lower)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add blocked domain: {str(e)}")
            return False
    
    async def remove_blocked_domain(self, domain: str) -> bool:
        """
        Remove domain from custom blocked list
        """
        try:
            domain_lower = domain.lower()
            if domain_lower in self.custom_blocked_domains:
                self.custom_blocked_domains.remove(domain_lower)
                
                # Update cache
                cache_key = "email_security:blocked_domains"
                blocked_list = list(self.custom_blocked_domains)
                await cache_service.set(cache_key, blocked_list, expire=None)
                
                logger.info("Domain removed from blocklist", domain=domain)
                
                # Clear validation cache
                await self._clear_domain_cache(domain_lower)
                
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to remove blocked domain: {str(e)}")
            return False
    
    async def add_allowed_domain(self, domain: str, reason: Optional[str] = None) -> bool:
        """
        Add domain to custom allowed list (whitelist)
        """
        try:
            domain_lower = domain.lower()
            self.custom_allowed_domains.add(domain_lower)
            
            # Store in cache
            cache_key = "email_security:allowed_domains"
            allowed_list = list(self.custom_allowed_domains)
            await cache_service.set(cache_key, allowed_list, expire=None)
            
            logger.info(
                "Domain added to allowlist",
                domain=domain,
                reason=reason
            )
            
            # Clear validation cache
            await self._clear_domain_cache(domain_lower)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add allowed domain: {str(e)}")
            return False
    
    async def get_blocked_domains(self) -> List[str]:
        """
        Get list of custom blocked domains
        """
        return list(self.custom_blocked_domains)
    
    async def get_allowed_domains(self) -> List[str]:
        """
        Get list of custom allowed domains
        """
        return list(self.custom_allowed_domains)
    
    async def check_email_breach(self, email: str) -> Dict[str, Any]:
        """
        Check if email has been in known data breaches (using HIBP API)
        """
        try:
            # Check cache
            cache_key = f"breach_check:{hashlib.sha1(email.encode()).hexdigest()}"
            cached = await cache_service.get(cache_key)
            if cached:
                return cached
            
            result = {
                "email": email,
                "breached": False,
                "breach_count": 0,
                "breaches": [],
                "checked_at": datetime.utcnow().isoformat()
            }
            
            # Check Have I Been Pwned API
            hibp_api_key = getattr(settings, 'HIBP_API_KEY', None)
            if not hibp_api_key:
                result["error"] = "Breach check not configured"
                return result
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={
                        "hibp-api-key": hibp_api_key,
                        "user-agent": "FastAPI-Auth-System"
                    },
                    params={"truncateResponse": "false"},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    breaches = response.json()
                    result["breached"] = True
                    result["breach_count"] = len(breaches)
                    result["breaches"] = [
                        {
                            "name": breach["Name"],
                            "domain": breach["Domain"],
                            "date": breach["BreachDate"],
                            "data_types": breach["DataClasses"]
                        }
                        for breach in breaches[:5]  # Limit to 5 most recent
                    ]
                elif response.status_code == 404:
                    # Not found = good news
                    result["breached"] = False
                else:
                    result["error"] = f"API error: {response.status_code}"
            
            # Cache for 24 hours
            await cache_service.set(cache_key, result, expire=86400)
            
            return result
            
        except Exception as e:
            logger.error(f"Email breach check error: {str(e)}")
            return {
                "email": email,
                "breached": False,
                "error": str(e)
            }
    
    async def _clear_domain_cache(self, domain: str):
        """
        Clear all cached data for a domain
        """
        try:
            # Clear domain-specific caches
            await cache_service.delete(f"disposable_check:{domain}")
            await cache_service.delete(f"domain_reputation:{domain}")
            
            # Clear email validation caches for this domain
            # This would need to iterate through cached emails
            # For now, we'll let them expire naturally
            
        except Exception as e:
            logger.error(f"Failed to clear domain cache: {str(e)}")
    
    async def load_custom_lists(self):
        """
        Load custom blocked/allowed domain lists from cache
        """
        try:
            # Load blocked domains
            blocked_key = "email_security:blocked_domains"
            blocked_list = await cache_service.get(blocked_key)
            if blocked_list:
                self.custom_blocked_domains = set(blocked_list)
            
            # Load allowed domains
            allowed_key = "email_security:allowed_domains"
            allowed_list = await cache_service.get(allowed_key)
            if allowed_list:
                self.custom_allowed_domains = set(allowed_list)
            
            logger.info(
                "Loaded custom email lists",
                blocked_count=len(self.custom_blocked_domains),
                allowed_count=len(self.custom_allowed_domains)
            )
            
        except Exception as e:
            logger.error(f"Failed to load custom lists: {str(e)}")
    
    async def get_validation_stats(self, timeframe: str = "24h") -> Dict[str, Any]:
        """
        Get email validation statistics
        """
        try:
            # This would aggregate validation results from cache/database
            # Placeholder implementation
            return {
                "timeframe": timeframe,
                "total_validations": 0,
                "blocked_disposable": 0,
                "blocked_invalid": 0,
                "blocked_custom": 0,
                "high_risk_count": 0,
                "average_risk_score": 0.0
            }
            
        except Exception as e:
            logger.error(f"Failed to get validation stats: {str(e)}")
            return {}


# Create singleton instance
email_security_service = EmailSecurityService()