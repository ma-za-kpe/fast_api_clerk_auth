from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Request, Query, HTTPException
from fastapi.responses import RedirectResponse
import structlog

from app.core.exceptions import AuthenticationError, ValidationError
from app.api.v1.deps import get_optional_current_user
from app.core.clerk import get_clerk_client
from app.services.oauth_service import oauth_service
from app.services.cache_service import cache_service

router = APIRouter()
logger = structlog.get_logger()


@router.get("/providers")
async def get_oauth_providers():
    """
    Get list of configured OAuth providers with detailed information
    """
    providers = oauth_service.get_supported_providers()
    
    # Provider display information
    provider_info = {
        "google": {
            "name": "Google",
            "description": "Sign in with your Google account",
            "icon": "google",
            "color": "#4285F4"
        },
        "github": {
            "name": "GitHub", 
            "description": "Sign in with your GitHub account",
            "icon": "github",
            "color": "#333"
        },
        "microsoft": {
            "name": "Microsoft",
            "description": "Sign in with your Microsoft account",
            "icon": "microsoft", 
            "color": "#00BCF2"
        },
        "facebook": {
            "name": "Facebook",
            "description": "Sign in with your Facebook account",
            "icon": "facebook",
            "color": "#1877F2"
        },
        "discord": {
            "name": "Discord",
            "description": "Sign in with your Discord account", 
            "icon": "discord",
            "color": "#5865F2"
        },
        "linkedin": {
            "name": "LinkedIn",
            "description": "Sign in with your LinkedIn account",
            "icon": "linkedin",
            "color": "#0077B5" 
        },
        "apple": {
            "name": "Apple",
            "description": "Sign in with your Apple ID",
            "icon": "apple",
            "color": "#000"
        },
        "twitter": {
            "name": "Twitter/X",
            "description": "Sign in with your Twitter account",
            "icon": "twitter",
            "color": "#1DA1F2"
        },
        "slack": {
            "name": "Slack", 
            "description": "Sign in with your Slack account",
            "icon": "slack",
            "color": "#4A154B"
        },
        "spotify": {
            "name": "Spotify",
            "description": "Sign in with your Spotify account",
            "icon": "spotify", 
            "color": "#1DB954"
        },
        "gitlab": {
            "name": "GitLab",
            "description": "Sign in with your GitLab account",
            "icon": "gitlab",
            "color": "#FC6D26"
        },
        "twitch": {
            "name": "Twitch",
            "description": "Sign in with your Twitch account",
            "icon": "twitch",
            "color": "#9146FF"
        },
        "tiktok": {
            "name": "TikTok",
            "description": "Sign in with your TikTok account",
            "icon": "tiktok",
            "color": "#000000"
        },
        "instagram": {
            "name": "Instagram",
            "description": "Sign in with your Instagram account",
            "icon": "instagram",
            "color": "#E4405F"
        },
        "dropbox": {
            "name": "Dropbox",
            "description": "Sign in with your Dropbox account",
            "icon": "dropbox",
            "color": "#0061FF"
        },
        "notion": {
            "name": "Notion",
            "description": "Sign in with your Notion account",
            "icon": "notion",
            "color": "#000000"
        },
        "linear": {
            "name": "Linear",
            "description": "Sign in with your Linear account",
            "icon": "linear",
            "color": "#5E6AD2"
        },
        "box": {
            "name": "Box",
            "description": "Sign in with your Box account",
            "icon": "box",
            "color": "#0061D5"
        },
        "hubspot": {
            "name": "HubSpot",
            "description": "Sign in with your HubSpot account",
            "icon": "hubspot",
            "color": "#FF7A59"
        },
        "atlassian": {
            "name": "Atlassian",
            "description": "Sign in with your Atlassian account",
            "icon": "atlassian",
            "color": "#0052CC"
        },
        "bitbucket": {
            "name": "Bitbucket",
            "description": "Sign in with your Bitbucket account",
            "icon": "bitbucket",
            "color": "#205081"
        }
    }
    
    return {
        "providers": [
            {
                "id": provider,
                "enabled": True,
                "connect_url": f"/api/v1/oauth/{provider}/authorize",
                **provider_info.get(provider, {
                    "name": provider.title(),
                    "description": f"Sign in with {provider.title()}",
                    "icon": provider,
                    "color": "#000"
                })
            }
            for provider in providers
        ],
        "total_providers": len(providers)
    }


@router.get("/{provider}/authorize")
async def oauth_authorize(
    provider: str,
    redirect_uri: Optional[str] = Query(None),
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)
):
    """
    Initialize OAuth flow - redirect to provider's authorization page
    """
    try:
        # Check if provider is supported
        if provider not in oauth_service.get_supported_providers():
            raise ValidationError(f"Provider {provider} is not configured")
        
        # Generate authorization URL
        auth_data = await oauth_service.get_authorization_url(
            provider_name=provider,
            redirect_uri=redirect_uri
        )
        
        # Store user context if authenticated (for account linking)
        if current_user:
            state_key = f"oauth_user_context:{auth_data['state']}"
            await cache_service.set(
                state_key,
                {"user_id": current_user.get("user_id")},
                expire=600
            )
        
        logger.info(f"Redirecting to {provider} OAuth", 
                   user_id=current_user.get("user_id") if current_user else None)
        
        # Redirect to provider
        return RedirectResponse(url=auth_data["url"], status_code=302)
    
    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"OAuth authorization failed: {str(e)}")
        raise HTTPException(status_code=500, detail="OAuth initialization failed")


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str = Query(...),
    state: str = Query(...),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
    clerk_client = Depends(get_clerk_client)
):
    """
    OAuth callback - handle the response from the OAuth provider
    """
    try:
        # Check for OAuth errors
        if error:
            logger.error(f"OAuth error from {provider}: {error} - {error_description}")
            raise AuthenticationError(f"OAuth failed: {error_description or error}")
        
        # Exchange code for token
        token_data = await oauth_service.exchange_code_for_token(
            provider_name=provider,
            code=code,
            state=state
        )
        
        # Get user info from provider
        user_info = await oauth_service.get_user_info(
            provider_name=provider,
            access_token=token_data["access_token"]
        )
        
        # Check if this is account linking or new auth
        state_key = f"oauth_user_context:{state}"
        user_context = await cache_service.get(state_key)
        
        if user_context:
            # Link OAuth account to existing user
            user_id = user_context.get("user_id")
            await oauth_service.link_oauth_account(
                user_id=user_id,
                provider=provider,
                provider_user_id=user_info["id"],
                provider_data=user_info
            )
            
            await cache_service.delete(state_key)
            
            logger.info(f"Linked {provider} account to user {user_id}")
            
            return {
                "status": "linked",
                "provider": provider,
                "user_id": user_id,
                "message": f"Successfully linked {provider} account"
            }
        
        else:
            # Create or get user based on OAuth info
            email = user_info.get("email")
            
            if not email:
                raise ValidationError(f"No email provided by {provider}")
            
            # Check if user exists
            user = await clerk_client.get_user_by_email(email)
            
            if not user:
                # Create new user
                user = await clerk_client.create_user(
                    email_address=email,
                    first_name=user_info.get("given_name"),
                    last_name=user_info.get("family_name"),
                    username=user_info.get("username"),
                    public_metadata={
                        "auth_method": f"oauth_{provider}",
                        f"oauth_{provider}": {
                            "id": user_info["id"],
                            "verified": user_info.get("email_verified", False)
                        }
                    },
                    private_metadata={
                        "oauth_providers": [provider]
                    }
                )
                
                logger.info(f"Created new user via {provider} OAuth", user_id=user.id)
            
            else:
                # Link OAuth to existing user
                await oauth_service.link_oauth_account(
                    user_id=user.id,
                    provider=provider,
                    provider_user_id=user_info["id"],
                    provider_data=user_info
                )
                
                logger.info(f"Linked {provider} to existing user", user_id=user.id)
            
            # Create session
            import secrets
            session_id = secrets.token_urlsafe(32)
            await cache_service.cache_user_session(
                session_id=session_id,
                user_id=user.id,
                data={
                    "auth_method": f"oauth_{provider}",
                    "provider_user_id": user_info["id"]
                },
                expire=86400
            )
            
            return {
                "status": "authenticated",
                "provider": provider,
                "user_id": user.id,
                "session_id": session_id,
                "email": email,
                "is_new_user": user is None,
                "redirect_url": f"{settings.FRONTEND_URL}/dashboard"
            }
    
    except (AuthenticationError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed: {str(e)}")
        raise HTTPException(status_code=500, detail="OAuth authentication failed")


@router.post("/{provider}/disconnect")
async def disconnect_oauth_provider(
    provider: str,
    current_user: Dict[str, Any] = Depends(get_optional_current_user)
):
    """
    Disconnect OAuth provider from user account
    """
    try:
        if not current_user:
            raise AuthenticationError("Authentication required")
        
        user_id = current_user.get("user_id")
        
        # Unlink OAuth account
        success = await oauth_service.unlink_oauth_account(
            user_id=user_id,
            provider=provider
        )
        
        if not success:
            raise ValidationError(f"Failed to disconnect {provider}")
        
        logger.info(f"Disconnected {provider} from user {user_id}")
        
        return {
            "status": "disconnected",
            "provider": provider,
            "message": f"Successfully disconnected {provider} account"
        }
    
    except (AuthenticationError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Failed to disconnect OAuth provider: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disconnect provider")


@router.get("/{provider}/status")
async def get_oauth_status(
    provider: str,
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Check if OAuth provider is connected for current user
    """
    try:
        if not current_user:
            return {
                "provider": provider,
                "connected": False,
                "authenticated": False
            }
        
        user_id = current_user.get("user_id")
        
        # Get user from Clerk
        user = await clerk_client.get_user(user_id)
        
        # Check if provider is linked
        public_metadata = user.public_metadata or {}
        oauth_key = f"oauth_{provider}"
        
        if oauth_key in public_metadata:
            provider_data = public_metadata[oauth_key]
            return {
                "provider": provider,
                "connected": True,
                "authenticated": True,
                "provider_user_id": provider_data.get("id"),
                "linked_at": provider_data.get("linked_at"),
                "username": provider_data.get("username")
            }
        
        return {
            "provider": provider,
            "connected": False,
            "authenticated": True
        }
    
    except Exception as e:
        logger.error(f"Failed to get OAuth status: {str(e)}")
        return {
            "provider": provider,
            "connected": False,
            "error": "Failed to check status"
        }


@router.get("/dashboard")
async def get_oauth_dashboard(
    current_user: Dict[str, Any] = Depends(get_optional_current_user),
    clerk_client = Depends(get_clerk_client)
):
    """
    Get OAuth dashboard with all connected providers and recommendations
    """
    try:
        if not current_user:
            return {
                "authenticated": False,
                "message": "Authentication required",
                "available_providers": oauth_service.get_supported_providers()
            }
        
        user_id = current_user.get("user_id")
        
        # Get user from Clerk
        user = await clerk_client.get_user(user_id)
        public_metadata = user.public_metadata or {}
        
        # Get all configured providers
        available_providers = oauth_service.get_supported_providers()
        connected_providers = []
        unconnected_providers = []
        
        for provider in available_providers:
            oauth_key = f"oauth_{provider}"
            if oauth_key in public_metadata:
                provider_data = public_metadata[oauth_key]
                connected_providers.append({
                    "provider": provider,
                    "provider_user_id": provider_data.get("id"),
                    "username": provider_data.get("username"),
                    "linked_at": provider_data.get("linked_at"),
                    "disconnect_url": f"/api/v1/oauth/{provider}/disconnect"
                })
            else:
                unconnected_providers.append({
                    "provider": provider,
                    "connect_url": f"/api/v1/oauth/{provider}/authorize"
                })
        
        # Security recommendations
        recommendations = []
        if len(connected_providers) == 0:
            recommendations.append({
                "type": "info",
                "message": "Connect social accounts for easier sign-in",
                "action": "connect_provider"
            })
        elif len(connected_providers) == 1:
            recommendations.append({
                "type": "suggestion", 
                "message": "Consider connecting a backup social account",
                "action": "connect_backup_provider"
            })
        
        if len(connected_providers) >= 3:
            recommendations.append({
                "type": "security",
                "message": "Review connected accounts and remove unused ones",
                "action": "review_connections"
            })
        
        return {
            "authenticated": True,
            "user_id": user_id,
            "connected_providers": connected_providers,
            "unconnected_providers": unconnected_providers,
            "total_connected": len(connected_providers),
            "total_available": len(available_providers),
            "recommendations": recommendations,
            "security_score": min(100, (len(connected_providers) * 20) + 40)  # Basic scoring
        }
    
    except Exception as e:
        logger.error(f"Failed to get OAuth dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load OAuth dashboard")


@router.post("/bulk-disconnect")
async def bulk_disconnect_providers(
    providers: List[str],
    current_user: Dict[str, Any] = Depends(get_optional_current_user)
):
    """
    Disconnect multiple OAuth providers at once
    """
    try:
        if not current_user:
            raise AuthenticationError("Authentication required")
        
        user_id = current_user.get("user_id")
        results = []
        
        for provider in providers:
            try:
                success = await oauth_service.unlink_oauth_account(user_id, provider)
                results.append({
                    "provider": provider,
                    "success": success,
                    "status": "disconnected" if success else "failed"
                })
            except Exception as e:
                results.append({
                    "provider": provider,
                    "success": False,
                    "status": "error",
                    "error": str(e)
                })
        
        successful_disconnects = [r for r in results if r["success"]]
        failed_disconnects = [r for r in results if not r["success"]]
        
        logger.info(f"Bulk disconnect: {len(successful_disconnects)} successful, {len(failed_disconnects)} failed")
        
        return {
            "total_attempted": len(providers),
            "successful": len(successful_disconnects),
            "failed": len(failed_disconnects),
            "results": results,
            "message": f"Disconnected {len(successful_disconnects)} of {len(providers)} providers"
        }
    
    except Exception as e:
        logger.error(f"Bulk disconnect failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to disconnect providers")