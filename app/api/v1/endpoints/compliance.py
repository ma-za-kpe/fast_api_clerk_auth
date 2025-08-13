from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, Path
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import structlog
import json
import io

from app.core.deps import get_current_user, get_db, require_admin
from app.core.clerk import ClerkUser
from app.services.compliance_service import (
    get_compliance_service,
    ComplianceService,
    ComplianceRequestType,
    ConsentType,
    RequestStatus
)
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()


# ============= Request Models =============

class ConsentRequest(BaseModel):
    consent_type: ConsentType
    granted: bool
    purpose: str
    legal_basis: str


class DataSubjectRequestCreate(BaseModel):
    request_type: ComplianceRequestType
    description: str
    verification_data: Optional[Dict[str, Any]] = None


class DataErasureRequest(BaseModel):
    force_delete: bool = False


# ============= Consent Management Endpoints =============

@router.post("/consent", summary="Record user consent")
async def record_consent(
    consent_request: ConsentRequest,
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Record consent for GDPR compliance"""
    try:
        compliance_service = get_compliance_service(db)
        
        consent_record = await compliance_service.record_consent(
            user_id=current_user.id,
            consent_type=consent_request.consent_type,
            granted=consent_request.granted,
            purpose=consent_request.purpose,
            legal_basis=consent_request.legal_basis
        )
        
        return {
            "message": "Consent recorded successfully",
            "consent_type": consent_record.consent_type.value,
            "granted": consent_record.granted,
            "timestamp": consent_record.timestamp.isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to record consent: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to record consent")


@router.delete("/consent/{consent_type}", summary="Withdraw consent")
async def withdraw_consent(
    consent_type: ConsentType = Path(...),
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Withdraw user consent"""
    try:
        compliance_service = get_compliance_service(db)
        
        success = await compliance_service.withdraw_consent(
            user_id=current_user.id,
            consent_type=consent_type
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Consent record not found")
        
        return {
            "message": "Consent withdrawn successfully",
            "consent_type": consent_type.value,
            "withdrawn_at": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to withdraw consent: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to withdraw consent")


@router.get("/consent", summary="Get user consents")
async def get_user_consents(
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all consent records for the current user"""
    try:
        compliance_service = get_compliance_service(db)
        
        consents = await compliance_service.get_user_consents(current_user.id)
        
        return {
            "user_id": current_user.id,
            "consents": [
                {
                    "consent_type": consent.consent_type.value,
                    "granted": consent.granted,
                    "timestamp": consent.timestamp.isoformat(),
                    "purpose": consent.purpose,
                    "legal_basis": consent.legal_basis,
                    "withdrawal_timestamp": consent.withdrawal_timestamp.isoformat() if consent.withdrawal_timestamp else None
                }
                for consent in consents
            ],
            "total_consents": len(consents)
        }
    
    except Exception as e:
        logger.error(f"Failed to get user consents: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user consents")


# ============= Data Subject Rights Endpoints =============

@router.post("/data-subject-request", summary="Create data subject request")
async def create_data_subject_request(
    request_data: DataSubjectRequestCreate,
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new data subject request (GDPR/CCPA)"""
    try:
        compliance_service = get_compliance_service(db)
        
        request = await compliance_service.create_data_subject_request(
            user_id=current_user.id,
            request_type=request_data.request_type,
            requested_by=current_user.id,
            description=request_data.description,
            verification_data=request_data.verification_data
        )
        
        return {
            "request_id": request.id,
            "request_type": request.request_type.value,
            "status": request.status.value,
            "created_at": request.created_at.isoformat(),
            "description": request.description,
            "message": f"Data subject request created. Request ID: {request.id}"
        }
    
    except Exception as e:
        logger.error(f"Failed to create data subject request: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create data subject request")


@router.post("/data-access/{request_id}/process", summary="Process data access request")
async def process_data_access_request(
    request_id: str = Path(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: ClerkUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Process GDPR Article 15 - Right of access request (Admin only)"""
    try:
        compliance_service = get_compliance_service(db)
        
        # Process the request in the background
        background_tasks.add_task(
            compliance_service.process_data_access_request,
            request_id
        )
        
        return {
            "message": "Data access request is being processed",
            "request_id": request_id,
            "estimated_completion": datetime.utcnow() + timedelta(hours=2)
        }
    
    except Exception as e:
        logger.error(f"Failed to process data access request: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process data access request")


@router.post("/data-erasure/{request_id}/process", summary="Process data erasure request")
async def process_data_erasure_request(
    request_id: str = Path(...),
    erasure_data: DataErasureRequest = DataErasureRequest(),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    current_user: ClerkUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Process GDPR Article 17 - Right to erasure request (Admin only)"""
    try:
        compliance_service = get_compliance_service(db)
        
        # Process the erasure request in the background
        background_tasks.add_task(
            compliance_service.process_data_erasure_request,
            request_id,
            erasure_data.force_delete
        )
        
        return {
            "message": "Data erasure request is being processed",
            "request_id": request_id,
            "force_delete": erasure_data.force_delete,
            "estimated_completion": datetime.utcnow() + timedelta(hours=1)
        }
    
    except Exception as e:
        logger.error(f"Failed to process data erasure request: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process data erasure request")


@router.get("/download/{request_id}", summary="Download data package")
async def download_data_package(
    request_id: str = Path(...),
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Download processed data package"""
    try:
        from app.services.cache_service import cache_service
        
        # Get the data package
        package_key = f"data_package:{request_id}"
        data_package = await cache_service.get(package_key)
        
        if not data_package:
            raise HTTPException(status_code=404, detail="Data package not found or expired")
        
        # Verify user owns this request
        request_data = await cache_service.get(f"compliance_request:{request_id}")
        if not request_data or request_data["user_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied to this data package")
        
        # Create downloadable content
        json_content = json.dumps(data_package, indent=2)
        
        def generate():
            yield json_content.encode('utf-8')
        
        headers = {
            'Content-Disposition': f'attachment; filename="data_export_{request_id}.json"',
            'Content-Type': 'application/json'
        }
        
        return StreamingResponse(
            io.BytesIO(json_content.encode('utf-8')),
            media_type='application/json',
            headers=headers
        )
    
    except Exception as e:
        logger.error(f"Failed to download data package: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to download data package")


# ============= Admin Endpoints =============

@router.get("/dashboard", summary="Get compliance dashboard")
async def get_compliance_dashboard(
    current_user: ClerkUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get compliance dashboard metrics (Admin only)"""
    try:
        compliance_service = get_compliance_service(db)
        
        dashboard = await compliance_service.get_compliance_dashboard()
        
        return dashboard
    
    except Exception as e:
        logger.error(f"Failed to get compliance dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get compliance dashboard")


@router.get("/requests", summary="Get all compliance requests")
async def get_compliance_requests(
    status: Optional[RequestStatus] = Query(None),
    request_type: Optional[ComplianceRequestType] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: ClerkUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all compliance requests with filtering (Admin only)"""
    try:
        from app.services.cache_service import cache_service
        
        # This would normally query a database table
        # For now, we'll return a placeholder structure
        
        return {
            "requests": [],
            "total": 0,
            "filters": {
                "status": status.value if status else None,
                "request_type": request_type.value if request_type else None
            },
            "pagination": {
                "limit": limit,
                "offset": offset
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to get compliance requests: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get compliance requests")


@router.get("/data-categories", summary="Get data categories")
async def get_data_categories(
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all data categories and their descriptions"""
    try:
        compliance_service = get_compliance_service(db)
        
        return {
            "data_categories": compliance_service.data_categories,
            "retention_periods": compliance_service.retention_periods,
            "message": "Data categories and retention periods for transparency"
        }
    
    except Exception as e:
        logger.error(f"Failed to get data categories: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get data categories")


@router.get("/privacy-policy", summary="Get privacy policy information")
async def get_privacy_policy():
    """Get privacy policy and data processing information"""
    return {
        "privacy_policy": {
            "version": "1.0",
            "last_updated": "2024-01-01",
            "data_controller": "Your Company Name",
            "contact_email": "privacy@yourcompany.com",
            "dpo_contact": "dpo@yourcompany.com"
        },
        "data_processing": {
            "legal_bases": [
                "consent",
                "contract",
                "legitimate_interest",
                "legal_obligation"
            ],
            "processing_purposes": [
                "Service provision",
                "Security and fraud prevention",
                "Analytics and improvement",
                "Legal compliance",
                "Marketing (with consent)"
            ],
            "data_retention": "Data is retained according to our retention schedule based on legal requirements and business needs",
            "third_party_sharing": "We share data with service providers and as required by law"
        },
        "user_rights": [
            "Right of access (Article 15)",
            "Right to rectification (Article 16)",
            "Right to erasure (Article 17)",
            "Right to restrict processing (Article 18)",
            "Right to data portability (Article 20)",
            "Right to object (Article 21)",
            "Rights related to automated decision making (Article 22)"
        ]
    }


# ============= User Self-Service Endpoints =============

@router.get("/my-requests", summary="Get user's compliance requests")
async def get_my_compliance_requests(
    current_user: ClerkUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all compliance requests for the current user"""
    try:
        from app.services.cache_service import cache_service
        
        user_requests_key = f"user_requests:{current_user.id}"
        request_ids = await cache_service.get_list(user_requests_key) or []
        
        requests = []
        for request_id in request_ids:
            request_data = await cache_service.get(f"compliance_request:{request_id}")
            if request_data:
                requests.append({
                    "request_id": request_data["id"],
                    "request_type": request_data["request_type"],
                    "status": request_data["status"],
                    "created_at": request_data["created_at"],
                    "completed_at": request_data.get("completed_at"),
                    "description": request_data["description"]
                })
        
        return {
            "user_id": current_user.id,
            "requests": requests,
            "total_requests": len(requests)
        }
    
    except Exception as e:
        logger.error(f"Failed to get user compliance requests: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user compliance requests")