from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import httpx
import hashlib
import hmac
import secrets
import base64
import json
from enum import Enum
import structlog
import re
from fastapi import Request

from app.core.config import settings
from app.core.exceptions import ValidationError, SecurityError
from app.services.cache_service import cache_service
from app.services.analytics_service import get_analytics_service

logger = structlog.get_logger()


class CaptchaProvider(Enum):
    RECAPTCHA_V3 = "recaptcha_v3"
    RECAPTCHA_V2 = "recaptcha_v2"
    HCAPTCHA = "hcaptcha"
    CLOUDFLARE_TURNSTILE = "cloudflare_turnstile"
    CUSTOM = "custom"


class BotProtectionService:
    """
    Service for bot protection including CAPTCHA verification and bot detection
    """
    
    def __init__(self):
        # reCAPTCHA configuration
        self.recaptcha_v3_site_key = getattr(settings, 'RECAPTCHA_V3_SITE_KEY', None)
        self.recaptcha_v3_secret_key = getattr(settings, 'RECAPTCHA_V3_SECRET_KEY', None)
        self.recaptcha_v3_threshold = getattr(settings, 'RECAPTCHA_V3_THRESHOLD', 0.5)
        
        # hCaptcha configuration
        self.hcaptcha_site_key = getattr(settings, 'HCAPTCHA_SITE_KEY', None)
        self.hcaptcha_secret_key = getattr(settings, 'HCAPTCHA_SECRET_KEY', None)
        
        # Cloudflare Turnstile configuration
        self.turnstile_site_key = getattr(settings, 'TURNSTILE_SITE_KEY', None)
        self.turnstile_secret_key = getattr(settings, 'TURNSTILE_SECRET_KEY', None)
        
        # Bot detection thresholds
        self.suspicious_score_threshold = 0.7
        self.block_score_threshold = 0.9
        
        # Rate limiting for challenge verifications
        self.max_challenge_attempts = 5
        self.challenge_cooldown_minutes = 15
    
    # ============= CAPTCHA Methods =============
    
    async def verify_recaptcha_v3(
        self,
        token: str,
        action: str,
        remote_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify reCAPTCHA v3 token
        """
        if not self.recaptcha_v3_secret_key:
            logger.warning("reCAPTCHA v3 not configured")
            return {"success": False, "error": "reCAPTCHA not configured"}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={
                        "secret": self.recaptcha_v3_secret_key,
                        "response": token,
                        "remoteip": remote_ip
                    }
                )
                
                result = response.json()
                
                if not result.get("success"):
                    logger.warning(
                        "reCAPTCHA v3 verification failed",
                        errors=result.get("error-codes"),
                        action=action
                    )
                    return {
                        "success": False,
                        "error": "reCAPTCHA verification failed",
                        "error_codes": result.get("error-codes", [])
                    }
                
                score = result.get("score", 0)
                
                # Check if score meets threshold
                if score < self.recaptcha_v3_threshold:
                    logger.warning(
                        "reCAPTCHA v3 score below threshold",
                        score=score,
                        threshold=self.recaptcha_v3_threshold,
                        action=action
                    )
                    return {
                        "success": False,
                        "score": score,
                        "error": "Verification score too low",
                        "is_bot": True
                    }
                
                # Verify action matches
                if result.get("action") != action:
                    logger.warning(
                        "reCAPTCHA v3 action mismatch",
                        expected=action,
                        received=result.get("action")
                    )
                    return {
                        "success": False,
                        "error": "Action mismatch"
                    }
                
                logger.info(
                    "reCAPTCHA v3 verification successful",
                    score=score,
                    action=action
                )
                
                return {
                    "success": True,
                    "score": score,
                    "action": action,
                    "hostname": result.get("hostname"),
                    "challenge_ts": result.get("challenge_ts"),
                    "is_bot": False
                }
        
        except Exception as e:
            logger.error(f"reCAPTCHA v3 verification error: {str(e)}")
            return {
                "success": False,
                "error": "Verification service error"
            }
    
    async def verify_hcaptcha(
        self,
        token: str,
        remote_ip: Optional[str] = None,
        sitekey: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify hCaptcha token
        """
        if not self.hcaptcha_secret_key:
            logger.warning("hCaptcha not configured")
            return {"success": False, "error": "hCaptcha not configured"}
        
        try:
            async with httpx.AsyncClient() as client:
                data = {
                    "secret": self.hcaptcha_secret_key,
                    "response": token
                }
                
                if remote_ip:
                    data["remoteip"] = remote_ip
                if sitekey:
                    data["sitekey"] = sitekey
                
                response = await client.post(
                    "https://hcaptcha.com/siteverify",
                    data=data
                )
                
                result = response.json()
                
                if not result.get("success"):
                    logger.warning(
                        "hCaptcha verification failed",
                        errors=result.get("error-codes")
                    )
                    return {
                        "success": False,
                        "error": "hCaptcha verification failed",
                        "error_codes": result.get("error-codes", [])
                    }
                
                logger.info("hCaptcha verification successful")
                
                return {
                    "success": True,
                    "hostname": result.get("hostname"),
                    "challenge_ts": result.get("challenge_ts"),
                    "credit": result.get("credit", False)
                }
        
        except Exception as e:
            logger.error(f"hCaptcha verification error: {str(e)}")
            return {
                "success": False,
                "error": "Verification service error"
            }
    
    async def verify_turnstile(
        self,
        token: str,
        remote_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify Cloudflare Turnstile token
        """
        if not self.turnstile_secret_key:
            logger.warning("Cloudflare Turnstile not configured")
            return {"success": False, "error": "Turnstile not configured"}
        
        try:
            async with httpx.AsyncClient() as client:
                data = {
                    "secret": self.turnstile_secret_key,
                    "response": token
                }
                
                if remote_ip:
                    data["remoteip"] = remote_ip
                
                response = await client.post(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    json=data
                )
                
                result = response.json()
                
                if not result.get("success"):
                    logger.warning(
                        "Turnstile verification failed",
                        errors=result.get("error-codes")
                    )
                    return {
                        "success": False,
                        "error": "Turnstile verification failed",
                        "error_codes": result.get("error-codes", [])
                    }
                
                logger.info("Turnstile verification successful")
                
                return {
                    "success": True,
                    "hostname": result.get("hostname"),
                    "challenge_ts": result.get("challenge_ts"),
                    "metadata": result.get("metadata")
                }
        
        except Exception as e:
            logger.error(f"Turnstile verification error: {str(e)}")
            return {
                "success": False,
                "error": "Verification service error"
            }
    
    # ============= Custom Challenge Methods =============
    
    async def create_custom_challenge(
        self,
        session_id: str,
        challenge_type: str = "math"
    ) -> Dict[str, Any]:
        """
        Create a custom challenge for bot detection
        """
        try:
            challenge_id = secrets.token_urlsafe(16)
            
            if challenge_type == "math":
                challenge_data = self._generate_math_challenge()
            elif challenge_type == "puzzle":
                challenge_data = self._generate_puzzle_challenge()
            elif challenge_type == "honeypot":
                challenge_data = self._generate_honeypot_challenge()
            else:
                raise ValidationError(f"Unknown challenge type: {challenge_type}")
            
            # Store challenge in cache
            cache_key = f"bot_challenge:{challenge_id}"
            await cache_service.set(
                cache_key,
                {
                    "session_id": session_id,
                    "type": challenge_type,
                    "answer": challenge_data["answer"],
                    "created_at": datetime.utcnow().isoformat(),
                    "attempts": 0
                },
                expire=300  # 5 minutes
            )
            
            logger.info(
                "Custom challenge created",
                challenge_id=challenge_id,
                type=challenge_type
            )
            
            return {
                "challenge_id": challenge_id,
                "type": challenge_type,
                "challenge": challenge_data["challenge"],
                "expires_in": 300
            }
        
        except Exception as e:
            logger.error(f"Failed to create custom challenge: {str(e)}")
            raise ValidationError("Failed to create challenge")
    
    async def verify_custom_challenge(
        self,
        challenge_id: str,
        answer: str,
        session_id: str
    ) -> Dict[str, Any]:
        """
        Verify a custom challenge answer
        """
        try:
            cache_key = f"bot_challenge:{challenge_id}"
            challenge_data = await cache_service.get(cache_key)
            
            if not challenge_data:
                return {
                    "success": False,
                    "error": "Challenge expired or invalid"
                }
            
            # Verify session matches
            if challenge_data.get("session_id") != session_id:
                logger.warning(
                    "Challenge session mismatch",
                    challenge_id=challenge_id
                )
                return {
                    "success": False,
                    "error": "Session mismatch"
                }
            
            # Check attempts
            attempts = challenge_data.get("attempts", 0)
            if attempts >= self.max_challenge_attempts:
                await cache_service.delete(cache_key)
                return {
                    "success": False,
                    "error": "Maximum attempts exceeded"
                }
            
            # Verify answer
            correct_answer = str(challenge_data.get("answer"))
            if str(answer).strip().lower() != correct_answer.lower():
                # Increment attempts
                challenge_data["attempts"] = attempts + 1
                await cache_service.set(cache_key, challenge_data, expire=300)
                
                return {
                    "success": False,
                    "error": "Incorrect answer",
                    "attempts_remaining": self.max_challenge_attempts - attempts - 1
                }
            
            # Challenge passed - delete it
            await cache_service.delete(cache_key)
            
            # Mark session as verified
            await self._mark_session_verified(session_id)
            
            logger.info(
                "Custom challenge verified",
                challenge_id=challenge_id,
                type=challenge_data.get("type")
            )
            
            return {
                "success": True,
                "message": "Challenge completed successfully"
            }
        
        except Exception as e:
            logger.error(f"Failed to verify custom challenge: {str(e)}")
            return {
                "success": False,
                "error": "Verification failed"
            }
    
    # ============= Bot Detection Methods =============
    
    async def analyze_request(
        self,
        request: Request,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze request for bot-like behavior
        """
        try:
            score = 0.0
            signals = []
            
            # Get request metadata
            user_agent = request.headers.get("user-agent", "")
            remote_ip = request.client.host if request.client else None
            
            # 1. Check User-Agent patterns
            ua_score, ua_signals = self._analyze_user_agent(user_agent)
            score += ua_score
            signals.extend(ua_signals)
            
            # 2. Check request patterns
            if remote_ip:
                pattern_score, pattern_signals = await self._analyze_request_patterns(
                    remote_ip, user_id
                )
                score += pattern_score
                signals.extend(pattern_signals)
            
            # 3. Check for headless browser indicators
            headless_score, headless_signals = self._detect_headless_browser(request.headers)
            score += headless_score
            signals.extend(headless_signals)
            
            # 4. Check for automated behavior
            automation_score, automation_signals = await self._detect_automation(
                remote_ip, user_id
            )
            score += automation_score
            signals.extend(automation_signals)
            
            # Normalize score (0-1)
            normalized_score = min(score / 4.0, 1.0)
            
            # Determine action
            if normalized_score >= self.block_score_threshold:
                action = "block"
            elif normalized_score >= self.suspicious_score_threshold:
                action = "challenge"
            else:
                action = "allow"
            
            result = {
                "score": normalized_score,
                "action": action,
                "signals": signals,
                "is_bot": normalized_score >= self.suspicious_score_threshold,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Log detection result
            if normalized_score >= self.suspicious_score_threshold:
                logger.warning(
                    "Potential bot detected",
                    score=normalized_score,
                    action=action,
                    signals=signals,
                    ip=remote_ip
                )
            
            # Store result for analytics
            await self._store_detection_result(remote_ip, user_id, result)
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to analyze request: {str(e)}")
            return {
                "score": 0.0,
                "action": "allow",
                "signals": [],
                "is_bot": False,
                "error": str(e)
            }
    
    def _analyze_user_agent(self, user_agent: str) -> Tuple[float, List[str]]:
        """
        Analyze User-Agent for bot patterns
        """
        score = 0.0
        signals = []
        
        if not user_agent:
            score += 0.5
            signals.append("missing_user_agent")
            return score, signals
        
        # Known bot patterns
        bot_patterns = [
            r'bot|crawler|spider|scraper|crawling',
            r'python-requests|urllib|httpx|aiohttp',
            r'headless|phantom|puppeteer|playwright',
            r'wget|curl|fetch',
            r'scanner|monitor|checker'
        ]
        
        ua_lower = user_agent.lower()
        for pattern in bot_patterns:
            if re.search(pattern, ua_lower, re.IGNORECASE):
                score += 0.8
                signals.append(f"bot_pattern:{pattern.split('|')[0]}")
                break
        
        # Check for suspicious patterns
        if len(user_agent) < 20:
            score += 0.3
            signals.append("short_user_agent")
        
        if not any(browser in ua_lower for browser in ['chrome', 'firefox', 'safari', 'edge']):
            score += 0.2
            signals.append("no_common_browser")
        
        return score, signals
    
    async def _analyze_request_patterns(
        self,
        remote_ip: str,
        user_id: Optional[str]
    ) -> Tuple[float, List[str]]:
        """
        Analyze request patterns for suspicious behavior
        """
        score = 0.0
        signals = []
        
        # Check request rate
        rate_key = f"bot_req_rate:{remote_ip}"
        current_count = await cache_service.get(rate_key) or 0
        
        if current_count > 100:  # More than 100 requests per minute
            score += 0.8
            signals.append("high_request_rate")
        elif current_count > 50:
            score += 0.4
            signals.append("elevated_request_rate")
        
        # Update counter
        await cache_service.set(rate_key, current_count + 1, expire=60)
        
        # Check for rapid-fire requests
        last_req_key = f"bot_last_req:{remote_ip}"
        last_req_time = await cache_service.get(last_req_key)
        
        if last_req_time:
            time_diff = (datetime.utcnow() - datetime.fromisoformat(last_req_time)).total_seconds()
            if time_diff < 0.1:  # Less than 100ms between requests
                score += 0.7
                signals.append("rapid_fire_requests")
            elif time_diff < 0.5:
                score += 0.3
                signals.append("fast_requests")
        
        await cache_service.set(last_req_key, datetime.utcnow().isoformat(), expire=60)
        
        return score, signals
    
    def _detect_headless_browser(self, headers: Dict[str, str]) -> Tuple[float, List[str]]:
        """
        Detect headless browser indicators
        """
        score = 0.0
        signals = []
        
        # Check for missing headers common in real browsers
        expected_headers = ['accept-language', 'accept-encoding', 'accept']
        missing_headers = [h for h in expected_headers if h not in headers]
        
        if len(missing_headers) >= 2:
            score += 0.5
            signals.append("missing_browser_headers")
        
        # Check for headless-specific headers
        if 'headless' in str(headers).lower():
            score += 0.9
            signals.append("headless_indicator")
        
        # Check for automation tool headers
        automation_headers = ['x-automated-test', 'x-selenium', 'x-puppeteer']
        for header in automation_headers:
            if header in headers:
                score += 0.9
                signals.append(f"automation_header:{header}")
                break
        
        return score, signals
    
    async def _detect_automation(
        self,
        remote_ip: Optional[str],
        user_id: Optional[str]
    ) -> Tuple[float, List[str]]:
        """
        Detect automated behavior patterns
        """
        score = 0.0
        signals = []
        
        if not remote_ip:
            return score, signals
        
        # Check for consistent timing patterns
        timing_key = f"bot_timing:{remote_ip}"
        timing_data = await cache_service.get(timing_key) or []
        
        current_time = datetime.utcnow().timestamp()
        timing_data.append(current_time)
        
        if len(timing_data) > 5:
            # Check for regular intervals
            intervals = [timing_data[i] - timing_data[i-1] for i in range(1, len(timing_data))]
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            
            if variance < 0.1:  # Very consistent timing
                score += 0.6
                signals.append("consistent_timing")
            
            # Keep only recent timings
            timing_data = timing_data[-10:]
        
        await cache_service.set(timing_key, timing_data, expire=300)
        
        # Check for lack of mouse/keyboard events (would need frontend integration)
        # This is a placeholder for when frontend sends interaction data
        
        return score, signals
    
    # ============= Helper Methods =============
    
    def _generate_math_challenge(self) -> Dict[str, Any]:
        """
        Generate a simple math challenge
        """
        import random
        
        a = random.randint(1, 20)
        b = random.randint(1, 20)
        operations = [
            ('+', lambda x, y: x + y),
            ('-', lambda x, y: x - y),
            ('*', lambda x, y: x * y)
        ]
        
        op_symbol, op_func = random.choice(operations)
        answer = op_func(a, b)
        
        return {
            "challenge": f"What is {a} {op_symbol} {b}?",
            "answer": str(answer)
        }
    
    def _generate_puzzle_challenge(self) -> Dict[str, Any]:
        """
        Generate a simple word puzzle challenge
        """
        import random
        
        puzzles = [
            {
                "challenge": "Type the word 'HUMAN' backwards",
                "answer": "namuh"
            },
            {
                "challenge": "What color is the sky on a clear day?",
                "answer": "blue"
            },
            {
                "challenge": "How many letters are in the word 'ROBOT'?",
                "answer": "5"
            },
            {
                "challenge": "Complete the sequence: 2, 4, 6, ?",
                "answer": "8"
            }
        ]
        
        return random.choice(puzzles)
    
    def _generate_honeypot_challenge(self) -> Dict[str, Any]:
        """
        Generate a honeypot field (invisible to users)
        """
        return {
            "challenge": "hidden_field",
            "answer": ""  # Should remain empty
        }
    
    async def _mark_session_verified(self, session_id: str):
        """
        Mark a session as human-verified
        """
        cache_key = f"bot_verified:{session_id}"
        await cache_service.set(
            cache_key,
            {
                "verified": True,
                "timestamp": datetime.utcnow().isoformat()
            },
            expire=3600  # Valid for 1 hour
        )
    
    async def _store_detection_result(
        self,
        remote_ip: Optional[str],
        user_id: Optional[str],
        result: Dict[str, Any]
    ):
        """
        Store bot detection result for analytics
        """
        try:
            # Store in time-series format for analytics
            analytics_key = f"bot_detection:{datetime.utcnow().strftime('%Y%m%d%H')}"
            await cache_service.push_to_list(
                analytics_key,
                {
                    "ip": remote_ip,
                    "user_id": user_id,
                    "score": result["score"],
                    "action": result["action"],
                    "signals": result["signals"],
                    "timestamp": result["timestamp"]
                }
            )
            await cache_service.expire(analytics_key, 86400)  # Keep for 24 hours
        except Exception as e:
            logger.error(f"Failed to store detection result: {str(e)}")
    
    async def get_verification_config(self) -> Dict[str, Any]:
        """
        Get current CAPTCHA configuration for frontend
        """
        config = {
            "enabled_providers": [],
            "default_provider": None,
            "site_keys": {}
        }
        
        if self.recaptcha_v3_site_key:
            config["enabled_providers"].append("recaptcha_v3")
            config["site_keys"]["recaptcha_v3"] = self.recaptcha_v3_site_key
            if not config["default_provider"]:
                config["default_provider"] = "recaptcha_v3"
        
        if self.hcaptcha_site_key:
            config["enabled_providers"].append("hcaptcha")
            config["site_keys"]["hcaptcha"] = self.hcaptcha_site_key
            if not config["default_provider"]:
                config["default_provider"] = "hcaptcha"
        
        if self.turnstile_site_key:
            config["enabled_providers"].append("turnstile")
            config["site_keys"]["turnstile"] = self.turnstile_site_key
            if not config["default_provider"]:
                config["default_provider"] = "turnstile"
        
        # Always enable custom challenges as fallback
        config["enabled_providers"].append("custom")
        
        return config


# Create singleton instance
bot_protection_service = BotProtectionService()