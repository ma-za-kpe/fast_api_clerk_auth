from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime
import structlog

from app.core.exceptions import AuthorizationError, ValidationError
from app.api.v1.deps import get_current_user
from app.core.permissions import require_permission
from app.services.avatar_service import avatar_service

router = APIRouter()
logger = structlog.get_logger()


@router.get("/dashboard")
@require_permission("users:read")
async def get_avatar_dashboard(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get avatar management dashboard (admin only)
    """
    try:
        # Get avatar analytics
        total_files = 0
        total_size = 0
        
        from pathlib import Path
        from app.core.config import settings
        
        storage_path = Path(settings.UPLOAD_DIR if hasattr(settings, 'UPLOAD_DIR') else "./uploads/avatars")
        
        if storage_path.exists():
            for file_path in storage_path.rglob("*"):
                if file_path.is_file():
                    total_files += 1
                    total_size += file_path.stat().st_size
        
        # Basic statistics
        dashboard_data = {
            "admin_user": current_user["user_id"],
            "statistics": {
                "total_avatar_files": total_files,
                "total_storage_mb": round(total_size / (1024 * 1024), 2),
                "average_file_size_kb": round((total_size / total_files) / 1024, 2) if total_files > 0 else 0,
                "storage_path": str(storage_path)
            },
            "system_info": {
                "max_file_size_mb": 5,
                "allowed_formats": ["jpeg", "jpg", "png", "gif", "webp"],
                "thumbnail_sizes": ["small (50x50)", "medium (150x150)", "large (300x300)"],
                "default_avatar_types": ["initials", "identicon"]
            },
            "recommendations": [],
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Add recommendations based on usage
        if total_files > 1000:
            dashboard_data["recommendations"].append({
                "type": "storage",
                "message": "Consider implementing cloud storage for avatars",
                "priority": "medium"
            })
        
        if total_size > 1024 * 1024 * 1024:  # 1GB
            dashboard_data["recommendations"].append({
                "type": "optimization",
                "message": "Storage usage is high - consider running optimization",
                "priority": "high"
            })
        
        return dashboard_data
    
    except Exception as e:
        logger.error(f"Failed to get avatar dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get avatar dashboard")


@router.get("/system-status")
async def get_avatar_system_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get avatar system status and health
    """
    try:
        from pathlib import Path
        from app.core.config import settings
        import os
        
        storage_path = Path(settings.UPLOAD_DIR if hasattr(settings, 'UPLOAD_DIR') else "./uploads/avatars")
        
        # Check storage path
        storage_accessible = storage_path.exists() and os.access(storage_path, os.W_OK)
        
        # Check disk space
        if storage_path.exists():
            stat = os.statvfs(storage_path)
            free_space_gb = (stat.f_frsize * stat.f_bavail) / (1024 * 1024 * 1024)
        else:
            free_space_gb = 0
        
        # System status
        status = {
            "storage": {
                "path": str(storage_path),
                "accessible": storage_accessible,
                "free_space_gb": round(free_space_gb, 2),
                "status": "healthy" if storage_accessible and free_space_gb > 1 else "warning"
            },
            "features": {
                "upload": True,
                "crop": True,
                "thumbnails": True,
                "default_generation": True,
                "url_import": True
            },
            "health_score": 100 if storage_accessible and free_space_gb > 1 else 75,
            "checked_at": datetime.utcnow().isoformat()
        }
        
        return status
    
    except Exception as e:
        logger.error(f"Failed to get avatar system status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get system status")


@router.post("/maintenance/cleanup")
@require_permission("users:manage")
async def cleanup_avatar_storage(
    dry_run: bool = Query(default=True, description="Preview changes without executing"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Clean up orphaned avatar files (admin only)
    """
    try:
        from pathlib import Path
        from app.core.config import settings
        
        storage_path = Path(settings.UPLOAD_DIR if hasattr(settings, 'UPLOAD_DIR') else "./uploads/avatars")
        
        if not storage_path.exists():
            return {"message": "Avatar storage directory does not exist"}
        
        # Find potentially orphaned files
        orphaned_files = []
        total_size = 0
        
        for file_path in storage_path.rglob("*"):
            if file_path.is_file():
                # Simple heuristic: very old files might be orphaned
                file_age_days = (datetime.utcnow().timestamp() - file_path.stat().st_mtime) / (24 * 3600)
                
                if file_age_days > 90:  # Files older than 90 days
                    file_size = file_path.stat().st_size
                    orphaned_files.append({
                        "file": str(file_path),
                        "size_mb": round(file_size / (1024 * 1024), 3),
                        "age_days": round(file_age_days, 1)
                    })
                    total_size += file_size
        
        if not dry_run:
            # Actually delete the files
            deleted_count = 0
            for file_info in orphaned_files:
                try:
                    Path(file_info["file"]).unlink()
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Failed to delete {file_info['file']}: {str(e)}")
            
            logger.info(f"Avatar cleanup: {deleted_count} files deleted")
            
            return {
                "action": "cleanup_executed",
                "files_deleted": deleted_count,
                "space_freed_mb": round(total_size / (1024 * 1024), 2),
                "cleaned_by": current_user["user_id"],
                "cleaned_at": datetime.utcnow().isoformat()
            }
        else:
            return {
                "action": "cleanup_preview",
                "files_to_delete": len(orphaned_files),
                "space_to_free_mb": round(total_size / (1024 * 1024), 2),
                "files": orphaned_files[:10],  # Show first 10 files
                "note": "This is a preview. Set dry_run=false to execute cleanup"
            }
    
    except Exception as e:
        logger.error(f"Failed to cleanup avatar storage: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cleanup storage")


@router.get("/formats")
async def get_supported_formats():
    """
    Get supported avatar formats and specifications
    """
    return {
        "supported_formats": {
            "jpeg": {
                "extensions": [".jpg", ".jpeg"],
                "mime_types": ["image/jpeg"],
                "description": "JPEG format with lossy compression"
            },
            "png": {
                "extensions": [".png"],
                "mime_types": ["image/png"],
                "description": "PNG format with lossless compression and transparency support"
            },
            "gif": {
                "extensions": [".gif"],
                "mime_types": ["image/gif"],
                "description": "GIF format with animation support (first frame used)"
            },
            "webp": {
                "extensions": [".webp"],
                "mime_types": ["image/webp"],
                "description": "Modern WebP format with superior compression"
            }
        },
        "specifications": {
            "max_file_size_mb": 5,
            "max_dimensions": "800x800 (original)",
            "thumbnail_sizes": {
                "small": "50x50",
                "medium": "150x150", 
                "large": "300x300"
            },
            "default_quality": 90,
            "processing": "PIL (Python Imaging Library)"
        },
        "features": {
            "automatic_resizing": True,
            "thumbnail_generation": True,
            "format_conversion": True,
            "transparency_handling": True,
            "metadata_preservation": False,
            "watermarking": False
        }
    }