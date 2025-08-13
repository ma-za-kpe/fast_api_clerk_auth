from fastapi import APIRouter, Depends, Request, HTTPException, Body
from typing import Dict, Any, Optional
from pydantic import BaseModel
import structlog

from app.services.bot_protection_service import bot_protection_service, CaptchaProvider
from app.core.exceptions import ValidationError, SecurityError
from app.api.v1.deps import get_optional_current_user

router = APIRouter()
logger = structlog.get_logger()


# ============= Request Models =============

class CaptchaVerifyRequest(BaseModel):
    provider: str
    token: str
    action: Optional[str] = None
    remote_ip: Optional[str] = None


class ChallengeVerifyRequest(BaseModel):
    challenge_id: str
    answer: str
    session_id: str


class BotCheckRequest(BaseModel):
    session_id: str
    page_url: Optional[str] = None
    interaction_data: Optional[Dict[str, Any]] = None


# ============= Endpoints =============

@router.get("/config")
async def get_bot_protection_config():
    """
    Get bot protection configuration for frontend
    """
    try:
        config = await bot_protection_service.get_verification_config()
        
        return {
            "status": "success",
            "config": config,
            "message": "Bot protection is active" if config["enabled_providers"] else "Bot protection not configured"
        }
    
    except Exception as e:
        logger.error(f"Failed to get bot protection config: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve configuration")


@router.post("/verify-captcha")
async def verify_captcha(
    request: CaptchaVerifyRequest,
    req: Request
):
    """
    Verify CAPTCHA token from various providers
    """
    try:
        # Get real IP if not provided
        if not request.remote_ip:
            request.remote_ip = req.client.host if req.client else None
        
        result = None
        
        # Route to appropriate verification method
        if request.provider == "recaptcha_v3":
            if not request.action:
                raise ValidationError("Action required for reCAPTCHA v3")
            
            result = await bot_protection_service.verify_recaptcha_v3(
                token=request.token,
                action=request.action,
                remote_ip=request.remote_ip
            )
        
        elif request.provider == "hcaptcha":
            result = await bot_protection_service.verify_hcaptcha(
                token=request.token,
                remote_ip=request.remote_ip
            )
        
        elif request.provider == "turnstile":
            result = await bot_protection_service.verify_turnstile(
                token=request.token,
                remote_ip=request.remote_ip
            )
        
        else:
            raise ValidationError(f"Unsupported CAPTCHA provider: {request.provider}")
        
        if not result.get("success"):
            logger.warning(
                "CAPTCHA verification failed",
                provider=request.provider,
                error=result.get("error"),
                ip=request.remote_ip
            )
            raise ValidationError(result.get("error", "CAPTCHA verification failed"))
        
        logger.info(
            "CAPTCHA verified successfully",
            provider=request.provider,
            score=result.get("score")
        )
        
        return {
            "verified": True,
            "provider": request.provider,
            "score": result.get("score"),
            "is_bot": result.get("is_bot", False),
            "details": result
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"CAPTCHA verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")


@router.post("/challenge/create")
async def create_challenge(
    session_id: str = Body(...),
    challenge_type: str = Body("math"),
    req: Request = None
):
    """
    Create a custom challenge for bot detection
    """
    try:
        # Validate challenge type
        valid_types = ["math", "puzzle", "honeypot"]
        if challenge_type not in valid_types:
            raise ValidationError(f"Invalid challenge type. Must be one of: {valid_types}")
        
        challenge = await bot_protection_service.create_custom_challenge(
            session_id=session_id,
            challenge_type=challenge_type
        )
        
        logger.info(
            "Challenge created",
            session_id=session_id,
            type=challenge_type,
            challenge_id=challenge["challenge_id"]
        )
        
        return challenge
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Failed to create challenge: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create challenge")


@router.post("/challenge/verify")
async def verify_challenge(
    request: ChallengeVerifyRequest,
    req: Request = None
):
    """
    Verify a custom challenge answer
    """
    try:
        result = await bot_protection_service.verify_custom_challenge(
            challenge_id=request.challenge_id,
            answer=request.answer,
            session_id=request.session_id
        )
        
        if not result.get("success"):
            logger.warning(
                "Challenge verification failed",
                challenge_id=request.challenge_id,
                error=result.get("error")
            )
            
            # Return with appropriate status but don't raise exception
            # to allow retry attempts
            return {
                "verified": False,
                "error": result.get("error"),
                "attempts_remaining": result.get("attempts_remaining")
            }
        
        logger.info(
            "Challenge verified successfully",
            challenge_id=request.challenge_id,
            session_id=request.session_id
        )
        
        return {
            "verified": True,
            "message": "Challenge completed successfully"
        }
    
    except Exception as e:
        logger.error(f"Challenge verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")


@router.post("/analyze")
async def analyze_request(
    req: Request,
    bot_check: Optional[BotCheckRequest] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)
):
    """
    Analyze current request for bot-like behavior
    """
    try:
        user_id = current_user.get("user_id") if current_user else None
        
        # Perform bot analysis
        analysis = await bot_protection_service.analyze_request(
            request=req,
            user_id=user_id
        )
        
        # Log suspicious activity
        if analysis.get("is_bot"):
            logger.warning(
                "Bot-like behavior detected",
                score=analysis["score"],
                action=analysis["action"],
                signals=analysis["signals"],
                user_id=user_id,
                ip=req.client.host if req.client else None
            )
        
        # If action is block, raise security error
        if analysis["action"] == "block":
            raise SecurityError("Automated behavior detected. Access denied.")
        
        return {
            "status": "analyzed",
            "score": analysis["score"],
            "action": analysis["action"],
            "is_bot": analysis["is_bot"],
            "requires_challenge": analysis["action"] == "challenge",
            "signals": analysis["signals"] if analysis["score"] > 0.5 else []
        }
    
    except SecurityError:
        raise
    except Exception as e:
        logger.error(f"Request analysis error: {str(e)}")
        # Don't block on error, allow request to proceed
        return {
            "status": "error",
            "score": 0.0,
            "action": "allow",
            "is_bot": False,
            "error": "Analysis failed"
        }


@router.get("/stats")
async def get_bot_protection_stats(
    timeframe: str = "1h",
    current_user: Dict[str, Any] = Depends(get_optional_current_user)
):
    """
    Get bot protection statistics (admin only)
    """
    try:
        # Check if user is admin
        if not current_user or not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # This would fetch statistics from analytics service
        # Placeholder implementation
        stats = {
            "timeframe": timeframe,
            "total_requests_analyzed": 0,
            "bot_detections": 0,
            "challenges_issued": 0,
            "challenges_passed": 0,
            "blocked_requests": 0,
            "top_signals": [],
            "detection_rate": 0.0
        }
        
        return stats
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get bot protection stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.post("/report-interaction")
async def report_user_interaction(
    session_id: str = Body(...),
    interaction_type: str = Body(...),
    data: Dict[str, Any] = Body({}),
    req: Request = None
):
    """
    Report user interaction data for improved bot detection
    """
    try:
        # Store interaction data for analysis
        # This helps distinguish real users from bots
        
        valid_interactions = ["mouse_move", "click", "keypress", "scroll", "focus", "form_interaction"]
        
        if interaction_type not in valid_interactions:
            raise ValidationError(f"Invalid interaction type: {interaction_type}")
        
        # Store interaction (implementation would go to analytics)
        logger.debug(
            "User interaction reported",
            session_id=session_id,
            type=interaction_type
        )
        
        return {
            "status": "recorded",
            "session_id": session_id,
            "interaction_type": interaction_type
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Failed to report interaction: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to record interaction")