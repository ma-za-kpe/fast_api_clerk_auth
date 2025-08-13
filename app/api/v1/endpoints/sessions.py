from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from datetime import datetime, timedelta
import structlog

from app.core.clerk import get_clerk_client
from app.core.exceptions import NotFoundError, ValidationError, AuthorizationError
from app.api.v1.deps import get_current_user
from app.db.database import get_db
from app.db.models import UserSession
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_

router = APIRouter()
logger = structlog.get_logger()


@router.get("/")
async def list_sessions(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    include_expired: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    List all sessions for the current user
    """
    try:
        user_id = current_user.get("user_id")
        
        # Get sessions from Clerk
        clerk_sessions = await clerk_client.list_user_sessions(user_id)
        
        # Get additional session data from local database
        query = select(UserSession).where(
            UserSession.user_id == user_id
        )
        
        if not include_expired:
            query = query.where(UserSession.is_active == True)
        
        query = query.order_by(UserSession.last_activity_at.desc())
        query = query.limit(limit).offset(offset)
        
        result = await db.execute(query)
        db_sessions = result.scalars().all()
        
        # Combine data from both sources
        sessions = []
        for clerk_session in clerk_sessions:
            session_data = {
                "session_id": clerk_session.id,
                "status": clerk_session.status,
                "created_at": clerk_session.created_at,
                "last_active_at": clerk_session.last_active_at,
                "expire_at": clerk_session.expire_at,
                "client_id": clerk_session.client_id
            }
            
            # Add local session data if available
            db_session = next(
                (s for s in db_sessions if s.session_id == clerk_session.id),
                None
            )
            
            if db_session:
                session_data.update({
                    "ip_address": db_session.ip_address,
                    "user_agent": db_session.user_agent,
                    "location": db_session.location,
                    "device_info": db_session.device_info
                })
            elif clerk_session.latest_activity:
                session_data.update({
                    "ip_address": clerk_session.latest_activity.ip_address,
                    "user_agent": clerk_session.latest_activity.user_agent
                })
            
            # Mark current session
            if clerk_session.id == current_user.get("session_id"):
                session_data["is_current"] = True
            else:
                session_data["is_current"] = False
            
            sessions.append(session_data)
        
        return {
            "sessions": sessions,
            "total": len(sessions),
            "limit": limit,
            "offset": offset,
            "active_count": len([s for s in sessions if s.get("status") == "active"])
        }
    
    except Exception as e:
        logger.error("Failed to list sessions", error=str(e))
        raise ValidationError(f"Failed to list sessions: {str(e)}")


@router.get("/current")
async def get_current_session(
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of the current session
    """
    try:
        session_id = current_user.get("session_id")
        
        if not session_id:
            raise NotFoundError("No active session found")
        
        # Get session from Clerk
        clerk_session = await clerk_client.get_session(session_id)
        
        if not clerk_session:
            raise NotFoundError("Session not found")
        
        # Get additional data from local database
        query = select(UserSession).where(
            UserSession.session_id == session_id
        )
        result = await db.execute(query)
        db_session = result.scalar_one_or_none()
        
        session_data = {
            "session_id": clerk_session.id,
            "user_id": clerk_session.user_id,
            "status": clerk_session.status,
            "created_at": clerk_session.created_at,
            "last_active_at": clerk_session.last_active_at,
            "expire_at": clerk_session.expire_at,
            "client_id": clerk_session.client_id
        }
        
        if db_session:
            session_data.update({
                "ip_address": db_session.ip_address,
                "user_agent": db_session.user_agent,
                "location": db_session.location,
                "device_info": db_session.device_info,
                "organization_id": db_session.organization_id
            })
        elif clerk_session.latest_activity:
            session_data.update({
                "ip_address": clerk_session.latest_activity.ip_address,
                "user_agent": clerk_session.latest_activity.user_agent
            })
        
        # Add session metadata
        session_data["metadata"] = {
            "auth_payload": current_user.get("auth_payload", {}),
            "organization_id": current_user.get("org_id")
        }
        
        return session_data
    
    except NotFoundError:
        raise
    except Exception as e:
        logger.error("Failed to get current session", error=str(e))
        raise ValidationError(f"Failed to get session: {str(e)}")


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific session
    """
    try:
        user_id = current_user.get("user_id")
        
        # Get session from Clerk
        clerk_session = await clerk_client.get_session(session_id)
        
        if not clerk_session:
            raise NotFoundError(f"Session {session_id} not found")
        
        # Verify session belongs to user
        if clerk_session.user_id != user_id:
            raise AuthorizationError("You can only view your own sessions")
        
        # Get additional data from local database
        query = select(UserSession).where(
            UserSession.session_id == session_id
        )
        result = await db.execute(query)
        db_session = result.scalar_one_or_none()
        
        session_data = {
            "session_id": clerk_session.id,
            "user_id": clerk_session.user_id,
            "status": clerk_session.status,
            "created_at": clerk_session.created_at,
            "last_active_at": clerk_session.last_active_at,
            "expire_at": clerk_session.expire_at,
            "client_id": clerk_session.client_id
        }
        
        if db_session:
            session_data.update({
                "ip_address": db_session.ip_address,
                "user_agent": db_session.user_agent,
                "location": db_session.location,
                "device_info": db_session.device_info,
                "organization_id": db_session.organization_id
            })
        elif clerk_session.latest_activity:
            session_data.update({
                "ip_address": clerk_session.latest_activity.ip_address,
                "user_agent": clerk_session.latest_activity.user_agent
            })
        
        return session_data
    
    except (NotFoundError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to get session {session_id}", error=str(e))
        raise ValidationError(f"Failed to get session: {str(e)}")


@router.delete("/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke a specific session
    """
    try:
        user_id = current_user.get("user_id")
        current_session_id = current_user.get("session_id")
        
        # Get session to verify ownership
        clerk_session = await clerk_client.get_session(session_id)
        
        if not clerk_session:
            raise NotFoundError(f"Session {session_id} not found")
        
        # Verify session belongs to user
        if clerk_session.user_id != user_id:
            raise AuthorizationError("You can only revoke your own sessions")
        
        # Prevent revoking current session (optional)
        if session_id == current_session_id:
            logger.warning("User attempting to revoke current session")
            # You might want to allow this for "logout from this device"
        
        # Revoke session in Clerk
        success = await clerk_client.revoke_session(session_id)
        
        if success:
            # Update local database
            query = update(UserSession).where(
                UserSession.session_id == session_id
            ).values(
                is_active=False,
                ended_at=datetime.utcnow()
            )
            
            await db.execute(query)
            await db.commit()
            
            logger.info(f"Session revoked", session_id=session_id, user_id=user_id)
            
            return {
                "message": "Session revoked successfully",
                "session_id": session_id
            }
        else:
            raise ValidationError("Failed to revoke session")
    
    except (NotFoundError, AuthorizationError):
        raise
    except Exception as e:
        logger.error(f"Failed to revoke session {session_id}", error=str(e))
        raise ValidationError(f"Failed to revoke session: {str(e)}")


@router.delete("/")
async def revoke_all_sessions(
    except_current: bool = Query(True, description="Keep current session active"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke all sessions for the current user
    """
    try:
        user_id = current_user.get("user_id")
        current_session_id = current_user.get("session_id")
        
        # Get all user sessions
        sessions = await clerk_client.list_user_sessions(user_id)
        
        revoked_count = 0
        failed_count = 0
        
        for session in sessions:
            # Skip current session if requested
            if except_current and session.id == current_session_id:
                continue
            
            try:
                success = await clerk_client.revoke_session(session.id)
                if success:
                    revoked_count += 1
                    
                    # Update local database
                    query = update(UserSession).where(
                        UserSession.session_id == session.id
                    ).values(
                        is_active=False,
                        ended_at=datetime.utcnow()
                    )
                    
                    await db.execute(query)
                else:
                    failed_count += 1
            except Exception as e:
                logger.error(f"Failed to revoke session {session.id}", error=str(e))
                failed_count += 1
        
        await db.commit()
        
        logger.info(
            "Bulk session revocation completed",
            user_id=user_id,
            revoked=revoked_count,
            failed=failed_count
        )
        
        return {
            "message": "Sessions revoked",
            "revoked_count": revoked_count,
            "failed_count": failed_count,
            "kept_current": except_current
        }
    
    except Exception as e:
        logger.error("Failed to revoke all sessions", error=str(e))
        raise ValidationError(f"Failed to revoke sessions: {str(e)}")


@router.post("/{session_id}/refresh")
async def refresh_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    clerk_client = Depends(get_clerk_client),
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh/extend a session
    """
    try:
        user_id = current_user.get("user_id")
        current_session_id = current_user.get("session_id")
        
        # Can only refresh current session
        if session_id != current_session_id:
            raise AuthorizationError("You can only refresh your current session")
        
        # Update last activity in local database
        query = select(UserSession).where(
            UserSession.session_id == session_id
        )
        result = await db.execute(query)
        db_session = result.scalar_one_or_none()
        
        if db_session:
            db_session.last_activity_at = datetime.utcnow()
            await db.commit()
        else:
            # Create local session record if it doesn't exist
            new_session = UserSession(
                session_id=session_id,
                user_id=user_id,
                organization_id=current_user.get("org_id"),
                last_activity_at=datetime.utcnow(),
                created_at=datetime.utcnow()
            )
            db.add(new_session)
            await db.commit()
        
        logger.info("Session refreshed", session_id=session_id)
        
        return {
            "message": "Session refreshed successfully",
            "session_id": session_id,
            "refreshed_at": datetime.utcnow().isoformat()
        }
    
    except AuthorizationError:
        raise
    except Exception as e:
        logger.error(f"Failed to refresh session {session_id}", error=str(e))
        raise ValidationError(f"Failed to refresh session: {str(e)}")


@router.get("/activity/recent")
async def get_recent_activity(
    days: int = Query(7, ge=1, le=30),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get recent session activity for the user
    """
    try:
        user_id = current_user.get("user_id")
        since_date = datetime.utcnow() - timedelta(days=days)
        
        # Query recent sessions from local database
        query = select(UserSession).where(
            and_(
                UserSession.user_id == user_id,
                UserSession.created_at >= since_date
            )
        ).order_by(UserSession.created_at.desc())
        
        result = await db.execute(query)
        sessions = result.scalars().all()
        
        activity = []
        for session in sessions:
            activity.append({
                "session_id": session.session_id,
                "ip_address": session.ip_address,
                "location": session.location,
                "device_info": session.device_info,
                "created_at": session.created_at.isoformat(),
                "last_activity_at": session.last_activity_at.isoformat(),
                "is_active": session.is_active
            })
        
        # Group by date
        activity_by_date = {}
        for item in activity:
            date_key = item["created_at"][:10]  # Extract date part
            if date_key not in activity_by_date:
                activity_by_date[date_key] = []
            activity_by_date[date_key].append(item)
        
        return {
            "activity": activity,
            "activity_by_date": activity_by_date,
            "total_sessions": len(activity),
            "active_sessions": len([a for a in activity if a["is_active"]]),
            "unique_ips": len(set(a["ip_address"] for a in activity if a["ip_address"])),
            "period_days": days
        }
    
    except Exception as e:
        logger.error("Failed to get recent activity", error=str(e))
        raise ValidationError(f"Failed to get activity: {str(e)}")


@router.get("/security/analysis")
async def analyze_session_security(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Analyze session security and provide recommendations
    """
    try:
        user_id = current_user.get("user_id")
        
        # Get all active sessions
        query = select(UserSession).where(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )
        )
        
        result = await db.execute(query)
        active_sessions = result.scalars().all()
        
        security_analysis = {
            "total_active_sessions": len(active_sessions),
            "security_score": 100,
            "risks": [],
            "recommendations": []
        }
        
        # Check for multiple locations
        unique_locations = set(s.location for s in active_sessions if s.location)
        if len(unique_locations) > 3:
            security_analysis["risks"].append({
                "level": "medium",
                "description": f"Sessions active from {len(unique_locations)} different locations"
            })
            security_analysis["security_score"] -= 20
            security_analysis["recommendations"].append(
                "Review and revoke sessions from unfamiliar locations"
            )
        
        # Check for old active sessions
        week_ago = datetime.utcnow() - timedelta(days=7)
        old_sessions = [s for s in active_sessions if s.created_at < week_ago]
        if old_sessions:
            security_analysis["risks"].append({
                "level": "low",
                "description": f"{len(old_sessions)} sessions older than 7 days"
            })
            security_analysis["security_score"] -= 10
            security_analysis["recommendations"].append(
                "Consider revoking old sessions for better security"
            )
        
        # Check for unusual IP addresses
        unique_ips = set(s.ip_address for s in active_sessions if s.ip_address)
        if len(unique_ips) > 5:
            security_analysis["risks"].append({
                "level": "medium",
                "description": f"Sessions from {len(unique_ips)} different IP addresses"
            })
            security_analysis["security_score"] -= 15
        
        # Add general recommendations
        if security_analysis["security_score"] == 100:
            security_analysis["recommendations"].append(
                "Your session security looks good!"
            )
        
        security_analysis["recommendations"].extend([
            "Enable two-factor authentication for added security",
            "Regularly review and revoke unused sessions",
            "Use strong, unique passwords for your account"
        ])
        
        return security_analysis
    
    except Exception as e:
        logger.error("Failed to analyze session security", error=str(e))
        raise ValidationError(f"Failed to analyze security: {str(e)}")