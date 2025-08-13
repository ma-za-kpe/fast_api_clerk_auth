from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, EmailStr
import structlog

from app.services.email_security_service import email_security_service
from app.core.exceptions import ValidationError, SecurityError
from app.api.v1.deps import require_admin, get_optional_current_user

router = APIRouter()
logger = structlog.get_logger()


# ============= Request Models =============

class EmailValidationRequest(BaseModel):
    email: EmailStr
    check_disposable: bool = True
    check_deliverability: bool = False
    strict_validation: bool = True


class DomainManagementRequest(BaseModel):
    domain: str
    reason: Optional[str] = None


class BulkEmailValidationRequest(BaseModel):
    emails: List[EmailStr]
    check_disposable: bool = True
    check_deliverability: bool = False


# ============= Public Endpoints =============

@router.post("/validate")
async def validate_email(
    request: EmailValidationRequest,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)
):
    """
    Validate an email address with comprehensive security checks
    """
    try:
        result = await email_security_service.validate_email(
            email=request.email,
            check_disposable=request.check_disposable,
            check_deliverability=request.check_deliverability
        )
        
        # Log validation attempt
        logger.info(
            "Email validation performed",
            email=request.email[:3] + "***",
            valid=result["valid"],
            risk_score=result["risk_score"],
            user_id=current_user.get("user_id") if current_user else None
        )
        
        # For non-admin users, simplify the response
        if not current_user or not current_user.get("is_admin"):
            return {
                "valid": result["valid"],
                "email": result["email"],
                "normalized": result["normalized"],
                "errors": result["errors"] if not result["valid"] else []
            }
        
        # Full response for admins
        return result
    
    except Exception as e:
        logger.error(f"Email validation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Email validation failed")


@router.post("/validate-bulk")
async def validate_emails_bulk(
    request: BulkEmailValidationRequest,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Validate multiple email addresses (admin only)
    """
    try:
        if len(request.emails) > 100:
            raise ValidationError("Maximum 100 emails per request")
        
        results = []
        for email in request.emails:
            result = await email_security_service.validate_email(
                email=email,
                check_disposable=request.check_disposable,
                check_deliverability=request.check_deliverability
            )
            results.append({
                "email": email,
                "valid": result["valid"],
                "risk_score": result["risk_score"],
                "errors": result["errors"]
            })
        
        # Summary statistics
        valid_count = sum(1 for r in results if r["valid"])
        high_risk_count = sum(1 for r in results if r["risk_score"] >= 0.7)
        
        return {
            "total": len(results),
            "valid": valid_count,
            "invalid": len(results) - valid_count,
            "high_risk": high_risk_count,
            "results": results
        }
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Bulk email validation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Bulk validation failed")


@router.get("/check-disposable/{email}")
async def check_disposable_email(
    email: EmailStr
):
    """
    Check if an email domain is disposable/temporary
    """
    try:
        domain = email.split('@')[1]
        is_disposable = await email_security_service.is_disposable_email(domain)
        
        return {
            "email": email,
            "domain": domain,
            "is_disposable": is_disposable,
            "blocked": is_disposable
        }
    
    except Exception as e:
        logger.error(f"Disposable check error: {str(e)}")
        raise HTTPException(status_code=500, detail="Check failed")


@router.get("/domain-reputation/{domain}")
async def check_domain_reputation(
    domain: str,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)
):
    """
    Check domain reputation and email infrastructure
    """
    try:
        reputation = await email_security_service.check_domain_reputation(domain)
        
        # Simplified response for non-admins
        if not current_user or not current_user.get("is_admin"):
            return {
                "domain": domain,
                "reputation": reputation["reputation"],
                "has_mx_records": reputation["has_mx_records"]
            }
        
        return reputation
    
    except Exception as e:
        logger.error(f"Domain reputation check error: {str(e)}")
        raise HTTPException(status_code=500, detail="Reputation check failed")


# ============= Admin Endpoints =============

@router.get("/blocked-domains")
async def get_blocked_domains(
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Get list of blocked email domains (admin only)
    """
    try:
        blocked = await email_security_service.get_blocked_domains()
        
        return {
            "total": len(blocked),
            "domains": blocked,
            "includes_disposable": True,
            "custom_count": len(blocked)
        }
    
    except Exception as e:
        logger.error(f"Failed to get blocked domains: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve blocked domains")


@router.post("/blocked-domains")
async def add_blocked_domain(
    request: DomainManagementRequest,
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Add domain to blocked list (admin only)
    """
    try:
        success = await email_security_service.add_blocked_domain(
            domain=request.domain,
            reason=request.reason
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to add domain")
        
        logger.info(
            "Domain added to blocklist",
            domain=request.domain,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        return {
            "message": f"Domain {request.domain} added to blocklist",
            "domain": request.domain,
            "reason": request.reason
        }
    
    except Exception as e:
        logger.error(f"Failed to add blocked domain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add domain")


@router.delete("/blocked-domains/{domain}")
async def remove_blocked_domain(
    domain: str,
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Remove domain from blocked list (admin only)
    """
    try:
        success = await email_security_service.remove_blocked_domain(domain)
        
        if not success:
            raise HTTPException(status_code=404, detail="Domain not found in blocklist")
        
        logger.info(
            "Domain removed from blocklist",
            domain=domain,
            admin_id=admin_user.get("user_id")
        )
        
        return {
            "message": f"Domain {domain} removed from blocklist",
            "domain": domain
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove blocked domain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to remove domain")


@router.get("/allowed-domains")
async def get_allowed_domains(
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Get list of explicitly allowed email domains (admin only)
    """
    try:
        allowed = await email_security_service.get_allowed_domains()
        
        return {
            "total": len(allowed),
            "domains": allowed
        }
    
    except Exception as e:
        logger.error(f"Failed to get allowed domains: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve allowed domains")


@router.post("/allowed-domains")
async def add_allowed_domain(
    request: DomainManagementRequest,
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Add domain to allowed list - overrides other checks (admin only)
    """
    try:
        success = await email_security_service.add_allowed_domain(
            domain=request.domain,
            reason=request.reason
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to add domain")
        
        logger.info(
            "Domain added to allowlist",
            domain=request.domain,
            admin_id=admin_user.get("user_id"),
            reason=request.reason
        )
        
        return {
            "message": f"Domain {request.domain} added to allowlist",
            "domain": request.domain,
            "reason": request.reason
        }
    
    except Exception as e:
        logger.error(f"Failed to add allowed domain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add domain")


@router.post("/check-breach")
async def check_email_breach(
    email: EmailStr = Body(...),
    current_user: Dict[str, Any] = Depends(get_optional_current_user)
):
    """
    Check if email has been in known data breaches
    """
    try:
        # Only allow users to check their own email or admins to check any
        if current_user:
            user_email = current_user.get("email")
            is_admin = current_user.get("is_admin", False)
            
            if not is_admin and user_email != email:
                raise HTTPException(status_code=403, detail="Can only check your own email")
        
        result = await email_security_service.check_email_breach(email)
        
        # Simplify response for non-admins
        if not current_user or not current_user.get("is_admin"):
            return {
                "email": email,
                "breached": result["breached"],
                "breach_count": result["breach_count"],
                "message": f"Email found in {result['breach_count']} breach(es)" if result["breached"] else "No breaches found"
            }
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email breach check error: {str(e)}")
        raise HTTPException(status_code=500, detail="Breach check failed")


@router.get("/stats")
async def get_email_security_stats(
    timeframe: str = Query("24h", regex="^(1h|24h|7d|30d)$"),
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Get email security statistics (admin only)
    """
    try:
        stats = await email_security_service.get_validation_stats(timeframe)
        
        return {
            "timeframe": timeframe,
            "statistics": stats,
            "blocked_domains_count": len(await email_security_service.get_blocked_domains()),
            "allowed_domains_count": len(await email_security_service.get_allowed_domains())
        }
    
    except Exception as e:
        logger.error(f"Failed to get email security stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.post("/reload-lists")
async def reload_custom_lists(
    admin_user: Dict[str, Any] = Depends(require_admin)
):
    """
    Reload custom blocked/allowed domain lists from storage (admin only)
    """
    try:
        await email_security_service.load_custom_lists()
        
        blocked_count = len(await email_security_service.get_blocked_domains())
        allowed_count = len(await email_security_service.get_allowed_domains())
        
        logger.info(
            "Email security lists reloaded",
            admin_id=admin_user.get("user_id"),
            blocked_count=blocked_count,
            allowed_count=allowed_count
        )
        
        return {
            "message": "Email security lists reloaded successfully",
            "blocked_domains": blocked_count,
            "allowed_domains": allowed_count
        }
    
    except Exception as e:
        logger.error(f"Failed to reload lists: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to reload lists")