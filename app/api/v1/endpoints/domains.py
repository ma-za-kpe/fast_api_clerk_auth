from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, Body, Query, HTTPException
import structlog

from app.core.exceptions import AuthenticationError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user, get_current_org_member
from app.services.domain_service import domain_service, DomainStatus

router = APIRouter()
logger = structlog.get_logger()


@router.post("/")
async def add_domain(
    org_id: str = Body(...),
    domain: str = Body(..., description="Domain to verify (e.g., example.com)"),
    auto_join_enabled: bool = Body(True, description="Enable auto-join for this domain"),
    default_role: str = Body("member", description="Default role for auto-joined users"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Add a domain for verification
    """
    try:
        # Check if user has permission (must be admin or owner)
        member = await get_current_org_member(org_id, current_user)
        if member.get("role") not in ["admin", "owner"]:
            raise AuthorizationError("Only admins and owners can add domains")
        
        result = await domain_service.add_domain(
            org_id=org_id,
            domain=domain,
            added_by=current_user.get("user_id"),
            auto_join_enabled=auto_join_enabled,
            default_role=default_role
        )
        
        logger.info(
            f"Domain added for verification",
            org_id=org_id,
            domain=domain,
            added_by=current_user.get("user_id")
        )
        
        return result
    
    except (ValidationError, AuthorizationError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to add domain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add domain")


@router.post("/{domain_id}/verify")
async def verify_domain(
    domain_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify domain ownership through DNS records
    """
    try:
        # Get domain data to check org ownership
        result = await domain_service.verify_domain(
            domain_id=domain_id,
            manual_trigger=True
        )
        
        logger.info(
            f"Domain verification attempted",
            domain_id=domain_id,
            verified=result.get("verified"),
            user_id=current_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to verify domain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify domain")


@router.delete("/{domain_id}")
async def remove_domain(
    domain_id: str,
    reason: Optional[str] = Body(None, embed=True),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove a domain from an organization
    """
    try:
        # Note: Should check if user has permission to remove
        # For now, we'll allow admins and owners
        
        result = await domain_service.remove_domain(
            domain_id=domain_id,
            removed_by=current_user.get("user_id"),
            reason=reason
        )
        
        logger.info(
            f"Domain removed",
            domain_id=domain_id,
            removed_by=current_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to remove domain: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to remove domain")


@router.patch("/{domain_id}/settings")
async def update_domain_settings(
    domain_id: str,
    auto_join_enabled: Optional[bool] = Body(None),
    default_role: Optional[str] = Body(None),
    allowed_email_patterns: Optional[List[str]] = Body(None),
    blocked_email_patterns: Optional[List[str]] = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update domain auto-join settings
    """
    try:
        # Note: Should check if user has permission
        
        result = await domain_service.update_domain_settings(
            domain_id=domain_id,
            auto_join_enabled=auto_join_enabled,
            default_role=default_role,
            allowed_email_patterns=allowed_email_patterns,
            blocked_email_patterns=blocked_email_patterns
        )
        
        logger.info(
            f"Domain settings updated",
            domain_id=domain_id,
            updated_by=current_user.get("user_id")
        )
        
        return result
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update domain settings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update settings")


@router.get("/organization/{org_id}")
async def get_organization_domains(
    org_id: str,
    include_removed: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get all domains for an organization
    """
    try:
        # Check if user is a member of the organization
        member = await get_current_org_member(org_id, current_user)
        if not member:
            raise AuthorizationError("You must be a member to view domains")
        
        domains = await domain_service.get_organization_domains(
            org_id=org_id,
            include_removed=include_removed
        )
        
        # Get verified count
        verified_count = await domain_service.get_verified_domains_count(org_id)
        
        return {
            "domains": domains,
            "total": len(domains),
            "verified_count": verified_count,
            "pending_count": len([d for d in domains if d["status"] == DomainStatus.PENDING.value]),
            "max_allowed": domain_service.max_domains_per_org
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get organization domains: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve domains")


@router.post("/check-auto-join")
async def check_auto_join_eligibility(
    email: str = Body(..., embed=True)
):
    """
    Check if an email is eligible for auto-join based on domain
    """
    try:
        is_eligible, org_info = await domain_service.check_auto_join_eligibility(email)
        
        if is_eligible and org_info:
            return {
                "eligible": True,
                "organization": {
                    "id": org_info["org_id"],
                    "name": org_info["org_name"],
                    "default_role": org_info["default_role"],
                    "domain": org_info["domain"]
                },
                "message": f"You can automatically join {org_info['org_name']}"
            }
        else:
            return {
                "eligible": False,
                "message": "No auto-join available for this email domain"
            }
    
    except Exception as e:
        logger.error(f"Failed to check auto-join eligibility: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check eligibility")


@router.get("/{domain_id}/dns-instructions")
async def get_dns_instructions(
    domain_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get DNS configuration instructions for domain verification
    """
    try:
        # Get domain from organization domains
        # This is a simplified version - in production you'd validate ownership
        
        return {
            "instructions": [
                {
                    "step": 1,
                    "title": "Access your DNS provider",
                    "description": "Log in to your domain registrar or DNS hosting provider"
                },
                {
                    "step": 2,
                    "title": "Add TXT record",
                    "description": "Create a new TXT record with the provided name and value"
                },
                {
                    "step": 3,
                    "title": "Wait for propagation",
                    "description": "DNS changes can take up to 48 hours to propagate worldwide"
                },
                {
                    "step": 4,
                    "title": "Verify domain",
                    "description": "Click the 'Verify' button to check your DNS configuration"
                }
            ],
            "common_providers": {
                "GoDaddy": "Manage DNS > Add Record > Type: TXT",
                "Namecheap": "Advanced DNS > Add New Record > TXT Record",
                "Cloudflare": "DNS > Add Record > Type: TXT",
                "Google Domains": "DNS > Custom Records > Add > Type: TXT",
                "AWS Route 53": "Create Record > Type: TXT"
            },
            "troubleshooting": [
                "Ensure there are no typos in the record name or value",
                "Some providers automatically add the domain name to the record",
                "Use online DNS lookup tools to verify your record is visible",
                "If verification fails, wait a few more hours for DNS propagation"
            ]
        }
    
    except Exception as e:
        logger.error(f"Failed to get DNS instructions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get instructions")


@router.get("/stats/{org_id}")
async def get_domain_statistics(
    org_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get domain statistics for an organization
    """
    try:
        # Check permission (admin or owner only)
        member = await get_current_org_member(org_id, current_user)
        if member.get("role") not in ["admin", "owner"]:
            raise AuthorizationError("Only admins and owners can view statistics")
        
        domains = await domain_service.get_organization_domains(
            org_id=org_id,
            include_removed=True
        )
        
        # Calculate statistics
        total = len(domains)
        verified = len([d for d in domains if d["status"] == DomainStatus.VERIFIED.value])
        pending = len([d for d in domains if d["status"] == DomainStatus.PENDING.value])
        failed = len([d for d in domains if d["status"] == DomainStatus.FAILED.value])
        expired = len([d for d in domains if d["status"] == DomainStatus.EXPIRED.value])
        
        # Get auto-join stats
        auto_join_enabled = len([
            d for d in domains 
            if d["status"] == DomainStatus.VERIFIED.value and d.get("auto_join_enabled")
        ])
        
        return {
            "total_domains": total,
            "verified": verified,
            "pending": pending,
            "failed": failed,
            "expired": expired,
            "auto_join_enabled": auto_join_enabled,
            "verification_rate": round((verified / total * 100) if total > 0 else 0, 2),
            "max_allowed": domain_service.max_domains_per_org,
            "remaining_slots": max(0, domain_service.max_domains_per_org - (verified + pending))
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get domain statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.post("/batch-verify")
async def batch_verify_domains(
    org_id: str = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Attempt to verify all pending domains for an organization
    """
    try:
        # Check permission
        member = await get_current_org_member(org_id, current_user)
        if member.get("role") not in ["admin", "owner"]:
            raise AuthorizationError("Only admins and owners can batch verify domains")
        
        domains = await domain_service.get_organization_domains(org_id)
        
        results = []
        for domain in domains:
            if domain["status"] == DomainStatus.PENDING.value:
                try:
                    result = await domain_service.verify_domain(
                        domain["domain_id"],
                        manual_trigger=True
                    )
                    results.append({
                        "domain_id": domain["domain_id"],
                        "domain": domain["domain"],
                        "verified": result.get("verified"),
                        "message": result.get("message")
                    })
                except Exception as e:
                    results.append({
                        "domain_id": domain["domain_id"],
                        "domain": domain["domain"],
                        "verified": False,
                        "error": str(e)
                    })
        
        successful = len([r for r in results if r.get("verified")])
        
        logger.info(
            f"Batch domain verification completed",
            org_id=org_id,
            total_attempted=len(results),
            successful=successful
        )
        
        return {
            "results": results,
            "total_attempted": len(results),
            "successful": successful,
            "failed": len(results) - successful
        }
    
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to batch verify domains: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to batch verify")