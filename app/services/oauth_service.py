from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets
import hashlib
import base64
import json
from urllib.parse import urlencode, parse_qs
import httpx
import structlog

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ValidationError
from app.services.cache_service import cache_service
from app.core.clerk import get_clerk_client

logger = structlog.get_logger()


class OAuthProvider:
    """Base OAuth provider configuration"""
    
    def __init__(
        self,
        name: str,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
        user_info_url: str,
        scopes: List[str],
        redirect_uri: Optional[str] = None
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.user_info_url = user_info_url
        self.scopes = scopes
        self.redirect_uri = redirect_uri or f"{settings.FRONTEND_URL}/auth/callback/{name}"


class OAuthService:
    """
    OAuth service for handling social authentication providers
    """
    
    def __init__(self):
        self.providers = self._initialize_providers()
        self.clerk_client = None
    
    def _initialize_providers(self) -> Dict[str, OAuthProvider]:
        """Initialize OAuth providers from settings"""
        providers = {}
        
        # Google OAuth
        if hasattr(settings, 'GOOGLE_CLIENT_ID') and settings.GOOGLE_CLIENT_ID:
            providers['google'] = OAuthProvider(
                name='google',
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
                authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
                token_url='https://oauth2.googleapis.com/token',
                user_info_url='https://www.googleapis.com/oauth2/v2/userinfo',
                scopes=['openid', 'email', 'profile']
            )
        
        # GitHub OAuth
        if hasattr(settings, 'GITHUB_CLIENT_ID') and settings.GITHUB_CLIENT_ID:
            providers['github'] = OAuthProvider(
                name='github',
                client_id=settings.GITHUB_CLIENT_ID,
                client_secret=settings.GITHUB_CLIENT_SECRET,
                authorize_url='https://github.com/login/oauth/authorize',
                token_url='https://github.com/login/oauth/access_token',
                user_info_url='https://api.github.com/user',
                scopes=['user:email']
            )
        
        # Microsoft OAuth
        if hasattr(settings, 'MICROSOFT_CLIENT_ID') and settings.MICROSOFT_CLIENT_ID:
            providers['microsoft'] = OAuthProvider(
                name='microsoft',
                client_id=settings.MICROSOFT_CLIENT_ID,
                client_secret=settings.MICROSOFT_CLIENT_SECRET,
                authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
                user_info_url='https://graph.microsoft.com/v1.0/me',
                scopes=['openid', 'email', 'profile']
            )
        
        # Facebook OAuth
        if hasattr(settings, 'FACEBOOK_CLIENT_ID') and settings.FACEBOOK_CLIENT_ID:
            providers['facebook'] = OAuthProvider(
                name='facebook',
                client_id=settings.FACEBOOK_CLIENT_ID,
                client_secret=settings.FACEBOOK_CLIENT_SECRET,
                authorize_url='https://www.facebook.com/v12.0/dialog/oauth',
                token_url='https://graph.facebook.com/v12.0/oauth/access_token',
                user_info_url='https://graph.facebook.com/me?fields=id,email,name,picture',
                scopes=['email', 'public_profile']
            )
        
        # Discord OAuth
        if hasattr(settings, 'DISCORD_CLIENT_ID') and settings.DISCORD_CLIENT_ID:
            providers['discord'] = OAuthProvider(
                name='discord',
                client_id=settings.DISCORD_CLIENT_ID,
                client_secret=settings.DISCORD_CLIENT_SECRET,
                authorize_url='https://discord.com/api/oauth2/authorize',
                token_url='https://discord.com/api/oauth2/token',
                user_info_url='https://discord.com/api/users/@me',
                scopes=['identify', 'email']
            )
        
        # LinkedIn OAuth
        if hasattr(settings, 'LINKEDIN_CLIENT_ID') and settings.LINKEDIN_CLIENT_ID:
            providers['linkedin'] = OAuthProvider(
                name='linkedin',
                client_id=settings.LINKEDIN_CLIENT_ID,
                client_secret=settings.LINKEDIN_CLIENT_SECRET,
                authorize_url='https://www.linkedin.com/oauth/v2/authorization',
                token_url='https://www.linkedin.com/oauth/v2/accessToken',
                user_info_url='https://api.linkedin.com/v2/me',
                scopes=['r_liteprofile', 'r_emailaddress']
            )
        
        # Apple OAuth (requires additional setup)
        if hasattr(settings, 'APPLE_CLIENT_ID') and settings.APPLE_CLIENT_ID:
            providers['apple'] = OAuthProvider(
                name='apple',
                client_id=settings.APPLE_CLIENT_ID,
                client_secret=settings.APPLE_CLIENT_SECRET,  # This is a JWT
                authorize_url='https://appleid.apple.com/auth/authorize',
                token_url='https://appleid.apple.com/auth/token',
                user_info_url='',  # Apple doesn't provide a user info endpoint
                scopes=['name', 'email']
            )
        
        # Twitter/X OAuth
        if hasattr(settings, 'TWITTER_CLIENT_ID') and settings.TWITTER_CLIENT_ID:
            providers['twitter'] = OAuthProvider(
                name='twitter',
                client_id=settings.TWITTER_CLIENT_ID,
                client_secret=settings.TWITTER_CLIENT_SECRET,
                authorize_url='https://twitter.com/i/oauth2/authorize',
                token_url='https://api.twitter.com/2/oauth2/token',
                user_info_url='https://api.twitter.com/2/users/me?user.fields=profile_image_url,email',
                scopes=['tweet.read', 'users.read', 'offline.access']
            )
        
        # Slack OAuth
        if hasattr(settings, 'SLACK_CLIENT_ID') and settings.SLACK_CLIENT_ID:
            providers['slack'] = OAuthProvider(
                name='slack',
                client_id=settings.SLACK_CLIENT_ID,
                client_secret=settings.SLACK_CLIENT_SECRET,
                authorize_url='https://slack.com/oauth/v2/authorize',
                token_url='https://slack.com/api/oauth.v2.access',
                user_info_url='https://slack.com/api/users.info',
                scopes=['identity.basic', 'identity.email']
            )
        
        # Spotify OAuth
        if hasattr(settings, 'SPOTIFY_CLIENT_ID') and settings.SPOTIFY_CLIENT_ID:
            providers['spotify'] = OAuthProvider(
                name='spotify',
                client_id=settings.SPOTIFY_CLIENT_ID,
                client_secret=settings.SPOTIFY_CLIENT_SECRET,
                authorize_url='https://accounts.spotify.com/authorize',
                token_url='https://accounts.spotify.com/api/token',
                user_info_url='https://api.spotify.com/v1/me',
                scopes=['user-read-email', 'user-read-private']
            )
        
        # GitLab OAuth
        if hasattr(settings, 'GITLAB_CLIENT_ID') and settings.GITLAB_CLIENT_ID:
            providers['gitlab'] = OAuthProvider(
                name='gitlab',
                client_id=settings.GITLAB_CLIENT_ID,
                client_secret=settings.GITLAB_CLIENT_SECRET,
                authorize_url='https://gitlab.com/oauth/authorize',
                token_url='https://gitlab.com/oauth/token',
                user_info_url='https://gitlab.com/api/v4/user',
                scopes=['read_user']
            )
        
        # Twitch OAuth
        if hasattr(settings, 'TWITCH_CLIENT_ID') and settings.TWITCH_CLIENT_ID:
            providers['twitch'] = OAuthProvider(
                name='twitch',
                client_id=settings.TWITCH_CLIENT_ID,
                client_secret=settings.TWITCH_CLIENT_SECRET,
                authorize_url='https://id.twitch.tv/oauth2/authorize',
                token_url='https://id.twitch.tv/oauth2/token',
                user_info_url='https://api.twitch.tv/helix/users',
                scopes=['user:read:email']
            )
        
        # TikTok OAuth
        if hasattr(settings, 'TIKTOK_CLIENT_ID') and settings.TIKTOK_CLIENT_ID:
            providers['tiktok'] = OAuthProvider(
                name='tiktok',
                client_id=settings.TIKTOK_CLIENT_ID,
                client_secret=settings.TIKTOK_CLIENT_SECRET,
                authorize_url='https://www.tiktok.com/auth/authorize',
                token_url='https://open-api.tiktok.com/oauth/access_token/',
                user_info_url='https://open-api.tiktok.com/user/info/',
                scopes=['user.info.basic']
            )
        
        # Instagram OAuth
        if hasattr(settings, 'INSTAGRAM_CLIENT_ID') and settings.INSTAGRAM_CLIENT_ID:
            providers['instagram'] = OAuthProvider(
                name='instagram',
                client_id=settings.INSTAGRAM_CLIENT_ID,
                client_secret=settings.INSTAGRAM_CLIENT_SECRET,
                authorize_url='https://api.instagram.com/oauth/authorize',
                token_url='https://api.instagram.com/oauth/access_token',
                user_info_url='https://graph.instagram.com/me?fields=id,username,account_type',
                scopes=['user_profile', 'user_media']
            )
        
        # Dropbox OAuth
        if hasattr(settings, 'DROPBOX_CLIENT_ID') and settings.DROPBOX_CLIENT_ID:
            providers['dropbox'] = OAuthProvider(
                name='dropbox',
                client_id=settings.DROPBOX_CLIENT_ID,
                client_secret=settings.DROPBOX_CLIENT_SECRET,
                authorize_url='https://www.dropbox.com/oauth2/authorize',
                token_url='https://api.dropboxapi.com/oauth2/token',
                user_info_url='https://api.dropboxapi.com/2/users/get_current_account',
                scopes=['account_info.read']
            )
        
        # Notion OAuth
        if hasattr(settings, 'NOTION_CLIENT_ID') and settings.NOTION_CLIENT_ID:
            providers['notion'] = OAuthProvider(
                name='notion',
                client_id=settings.NOTION_CLIENT_ID,
                client_secret=settings.NOTION_CLIENT_SECRET,
                authorize_url='https://api.notion.com/v1/oauth/authorize',
                token_url='https://api.notion.com/v1/oauth/token',
                user_info_url='https://api.notion.com/v1/users/me',
                scopes=[]  # Notion doesn't require specific scopes
            )
        
        # Linear OAuth
        if hasattr(settings, 'LINEAR_CLIENT_ID') and settings.LINEAR_CLIENT_ID:
            providers['linear'] = OAuthProvider(
                name='linear',
                client_id=settings.LINEAR_CLIENT_ID,
                client_secret=settings.LINEAR_CLIENT_SECRET,
                authorize_url='https://linear.app/oauth/authorize',
                token_url='https://api.linear.app/oauth/token',
                user_info_url='https://api.linear.app/graphql',  # GraphQL endpoint
                scopes=['read']
            )
        
        # Box OAuth
        if hasattr(settings, 'BOX_CLIENT_ID') and settings.BOX_CLIENT_ID:
            providers['box'] = OAuthProvider(
                name='box',
                client_id=settings.BOX_CLIENT_ID,
                client_secret=settings.BOX_CLIENT_SECRET,
                authorize_url='https://account.box.com/api/oauth2/authorize',
                token_url='https://api.box.com/oauth2/token',
                user_info_url='https://api.box.com/2.0/users/me',
                scopes=['base_explorer.read']
            )
        
        # HubSpot OAuth
        if hasattr(settings, 'HUBSPOT_CLIENT_ID') and settings.HUBSPOT_CLIENT_ID:
            providers['hubspot'] = OAuthProvider(
                name='hubspot',
                client_id=settings.HUBSPOT_CLIENT_ID,
                client_secret=settings.HUBSPOT_CLIENT_SECRET,
                authorize_url='https://app.hubspot.com/oauth/authorize',
                token_url='https://api.hubapi.com/oauth/v1/token',
                user_info_url='https://api.hubapi.com/oauth/v1/access-tokens',
                scopes=['oauth', 'contacts']
            )
        
        # Atlassian OAuth
        if hasattr(settings, 'ATLASSIAN_CLIENT_ID') and settings.ATLASSIAN_CLIENT_ID:
            providers['atlassian'] = OAuthProvider(
                name='atlassian',
                client_id=settings.ATLASSIAN_CLIENT_ID,
                client_secret=settings.ATLASSIAN_CLIENT_SECRET,
                authorize_url='https://auth.atlassian.com/authorize',
                token_url='https://auth.atlassian.com/oauth/token',
                user_info_url='https://api.atlassian.com/me',
                scopes=['read:me', 'offline_access']
            )
        
        # Bitbucket OAuth
        if hasattr(settings, 'BITBUCKET_CLIENT_ID') and settings.BITBUCKET_CLIENT_ID:
            providers['bitbucket'] = OAuthProvider(
                name='bitbucket',
                client_id=settings.BITBUCKET_CLIENT_ID,
                client_secret=settings.BITBUCKET_CLIENT_SECRET,
                authorize_url='https://bitbucket.org/site/oauth2/authorize',
                token_url='https://bitbucket.org/site/oauth2/access_token',
                user_info_url='https://api.bitbucket.org/2.0/user',
                scopes=['account', 'email']
            )
        
        return providers
    
    async def get_authorization_url(
        self,
        provider_name: str,
        state: Optional[str] = None,
        redirect_uri: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate OAuth authorization URL for a provider
        """
        if provider_name not in self.providers:
            raise ValidationError(f"Provider {provider_name} not configured")
        
        provider = self.providers[provider_name]
        
        # Generate state for CSRF protection
        if not state:
            state = secrets.token_urlsafe(32)
        
        # Store state in cache for verification
        cache_key = f"oauth_state:{state}"
        cache_data = {
            "provider": provider_name,
            "created_at": datetime.utcnow().isoformat(),
            "redirect_uri": redirect_uri or provider.redirect_uri
        }
        await cache_service.set(cache_key, cache_data, expire=600)  # 10 minutes
        
        # Build authorization URL
        params = {
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri or provider.redirect_uri,
            "response_type": "code",
            "scope": " ".join(provider.scopes),
            "state": state
        }
        
        # Provider-specific parameters
        if provider_name == "google":
            params["access_type"] = "offline"
            params["prompt"] = "consent"
        elif provider_name == "github":
            params["allow_signup"] = "true"
        elif provider_name == "apple":
            params["response_mode"] = "form_post"
        elif provider_name == "twitter":
            params["code_challenge"] = "challenge"
            params["code_challenge_method"] = "plain"
        elif provider_name == "slack":
            params["user_scope"] = "identity.basic,identity.email"
        elif provider_name == "spotify":
            params["show_dialog"] = "true"
        
        auth_url = f"{provider.authorize_url}?{urlencode(params)}"
        
        logger.info(f"Generated OAuth authorization URL for {provider_name}")
        
        return {
            "url": auth_url,
            "state": state,
            "provider": provider_name
        }
    
    async def exchange_code_for_token(
        self,
        provider_name: str,
        code: str,
        state: str,
        redirect_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token
        """
        if provider_name not in self.providers:
            raise ValidationError(f"Provider {provider_name} not configured")
        
        # Verify state to prevent CSRF
        cache_key = f"oauth_state:{state}"
        state_data = await cache_service.get(cache_key)
        
        if not state_data:
            raise AuthenticationError("Invalid or expired state")
        
        if state_data.get("provider") != provider_name:
            raise AuthenticationError("State provider mismatch")
        
        provider = self.providers[provider_name]
        redirect_uri = redirect_uri or state_data.get("redirect_uri") or provider.redirect_uri
        
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            token_data = {
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code"
            }
            
            headers = {"Accept": "application/json"}
            
            response = await client.post(
                provider.token_url,
                data=token_data,
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Token exchange failed for {provider_name}: {response.text}")
                raise AuthenticationError("Failed to exchange code for token")
            
            token_response = response.json()
        
        # Delete used state
        await cache_service.delete(cache_key)
        
        # Store tokens in cache
        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")
        expires_in = token_response.get("expires_in", 3600)
        
        token_cache_key = f"oauth_token:{provider_name}:{access_token[:8]}"
        await cache_service.set(
            token_cache_key,
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "provider": provider_name,
                "expires_at": (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
            },
            expire=expires_in
        )
        
        logger.info(f"Successfully exchanged code for token with {provider_name}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "provider": provider_name
        }
    
    async def get_user_info(
        self,
        provider_name: str,
        access_token: str
    ) -> Dict[str, Any]:
        """
        Get user information from OAuth provider
        """
        if provider_name not in self.providers:
            raise ValidationError(f"Provider {provider_name} not configured")
        
        provider = self.providers[provider_name]
        
        # Special case for Apple (uses ID token)
        if provider_name == "apple":
            # Apple returns user info in the ID token
            # This would require JWT decoding
            return self._decode_apple_id_token(access_token)
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}"}
            
            # LinkedIn requires special handling
            if provider_name == "linkedin":
                # Get basic profile
                profile_response = await client.get(
                    provider.user_info_url,
                    headers=headers
                )
                profile = profile_response.json()
                
                # Get email separately
                email_response = await client.get(
                    "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                    headers=headers
                )
                email_data = email_response.json()
                
                return self._normalize_linkedin_user(profile, email_data)
            
            # Slack requires user ID from the token exchange
            elif provider_name == "slack":
                # First get user ID from auth.test
                auth_response = await client.get(
                    "https://slack.com/api/auth.test",
                    headers=headers
                )
                auth_data = auth_response.json()
                user_id = auth_data.get("user_id")
                
                # Then get user info
                user_response = await client.get(
                    f"https://slack.com/api/users.info?user={user_id}",
                    headers=headers
                )
                user_data = user_response.json()
                
                return self._normalize_slack_user(user_data)
            
            # Twitch requires Client-ID header
            elif provider_name == "twitch":
                headers["Client-ID"] = provider.client_id
            
            response = await client.get(
                provider.user_info_url,
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get user info from {provider_name}: {response.text}")
                raise AuthenticationError("Failed to get user information")
            
            user_data = response.json()
        
        # Normalize user data across providers
        normalized = self._normalize_user_data(provider_name, user_data)
        
        logger.info(f"Retrieved user info from {provider_name}", user_id=normalized.get("id"))
        
        return normalized
    
    def _normalize_user_data(self, provider: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize user data from different providers
        """
        normalized = {
            "provider": provider,
            "raw_data": data
        }
        
        if provider == "google":
            normalized.update({
                "id": data.get("id"),
                "email": data.get("email"),
                "email_verified": data.get("verified_email", False),
                "name": data.get("name"),
                "given_name": data.get("given_name"),
                "family_name": data.get("family_name"),
                "picture": data.get("picture"),
                "locale": data.get("locale")
            })
        
        elif provider == "github":
            normalized.update({
                "id": str(data.get("id")),
                "email": data.get("email"),
                "email_verified": True,  # GitHub verifies emails
                "name": data.get("name"),
                "username": data.get("login"),
                "picture": data.get("avatar_url"),
                "bio": data.get("bio"),
                "company": data.get("company"),
                "location": data.get("location")
            })
        
        elif provider == "microsoft":
            normalized.update({
                "id": data.get("id"),
                "email": data.get("mail") or data.get("userPrincipalName"),
                "email_verified": True,
                "name": data.get("displayName"),
                "given_name": data.get("givenName"),
                "family_name": data.get("surname"),
                "job_title": data.get("jobTitle"),
                "office_location": data.get("officeLocation")
            })
        
        elif provider == "facebook":
            normalized.update({
                "id": data.get("id"),
                "email": data.get("email"),
                "email_verified": True,
                "name": data.get("name"),
                "picture": data.get("picture", {}).get("data", {}).get("url")
            })
        
        elif provider == "discord":
            normalized.update({
                "id": data.get("id"),
                "email": data.get("email"),
                "email_verified": data.get("verified", False),
                "username": data.get("username"),
                "discriminator": data.get("discriminator"),
                "picture": f"https://cdn.discordapp.com/avatars/{data.get('id')}/{data.get('avatar')}.png" if data.get('avatar') else None,
                "locale": data.get("locale")
            })
        
        elif provider == "twitter":
            normalized.update({
                "id": data.get("id"),
                "email": data.get("email"),
                "email_verified": True,  # Twitter verifies emails
                "username": data.get("username"),
                "name": data.get("name"),
                "picture": data.get("profile_image_url"),
                "followers_count": data.get("public_metrics", {}).get("followers_count"),
                "verified": data.get("verified", False)
            })
        
        elif provider == "spotify":
            normalized.update({
                "id": data.get("id"),
                "email": data.get("email"),
                "email_verified": True,
                "name": data.get("display_name"),
                "username": data.get("id"),
                "picture": data.get("images", [{}])[0].get("url") if data.get("images") else None,
                "country": data.get("country"),
                "followers_count": data.get("followers", {}).get("total"),
                "premium": data.get("product") == "premium"
            })
        
        elif provider == "gitlab":
            normalized.update({
                "id": str(data.get("id")),
                "email": data.get("email"),
                "email_verified": data.get("confirmed_at") is not None,
                "username": data.get("username"),
                "name": data.get("name"),
                "picture": data.get("avatar_url"),
                "bio": data.get("bio"),
                "location": data.get("location"),
                "website": data.get("web_url")
            })
        
        elif provider == "twitch":
            # Twitch returns data in a different format
            user_data = data.get("data", [{}])[0] if data.get("data") else {}
            normalized.update({
                "id": user_data.get("id"),
                "email": user_data.get("email"),
                "email_verified": True,
                "username": user_data.get("login"),
                "name": user_data.get("display_name"),
                "picture": user_data.get("profile_image_url"),
                "bio": user_data.get("description"),
                "view_count": user_data.get("view_count"),
                "broadcaster_type": user_data.get("broadcaster_type")
            })
        
        return normalized
    
    def _normalize_linkedin_user(self, profile: Dict, email_data: Dict) -> Dict[str, Any]:
        """
        Normalize LinkedIn user data
        """
        email = None
        if email_data.get("elements"):
            email = email_data["elements"][0]["handle~"]["emailAddress"]
        
        return {
            "provider": "linkedin",
            "id": profile.get("id"),
            "email": email,
            "email_verified": True,
            "name": f"{profile.get('localizedFirstName', '')} {profile.get('localizedLastName', '')}".strip(),
            "given_name": profile.get("localizedFirstName"),
            "family_name": profile.get("localizedLastName"),
            "raw_data": {"profile": profile, "email": email_data}
        }
    
    def _normalize_slack_user(self, data: Dict) -> Dict[str, Any]:
        """
        Normalize Slack user data
        """
        user = data.get("user", {})
        profile = user.get("profile", {})
        
        return {
            "provider": "slack",
            "id": user.get("id"),
            "email": profile.get("email"),
            "email_verified": True,  # Slack verifies emails
            "username": user.get("name"),
            "name": profile.get("real_name") or profile.get("display_name"),
            "given_name": profile.get("first_name"),
            "family_name": profile.get("last_name"),
            "picture": profile.get("image_192") or profile.get("image_72"),
            "title": profile.get("title"),
            "phone": profile.get("phone"),
            "raw_data": data
        }
    
    def _decode_apple_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Decode Apple ID token (requires JWT library)
        """
        # This would require proper JWT validation with Apple's public keys
        # For now, return placeholder
        return {
            "provider": "apple",
            "id": "apple_user_id",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Apple User"
        }
    
    async def link_oauth_account(
        self,
        user_id: str,
        provider: str,
        provider_user_id: str,
        provider_data: Dict[str, Any]
    ) -> bool:
        """
        Link OAuth account to existing user in Clerk
        """
        if not self.clerk_client:
            from app.core.clerk import get_clerk_client
            self.clerk_client = get_clerk_client()
        
        try:
            # Update user metadata with OAuth info
            await self.clerk_client.update_user(
                user_id=user_id,
                public_metadata={
                    f"oauth_{provider}": {
                        "id": provider_user_id,
                        "linked_at": datetime.utcnow().isoformat(),
                        "username": provider_data.get("username"),
                        "picture": provider_data.get("picture")
                    }
                }
            )
            
            logger.info(f"Linked {provider} account to user {user_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to link OAuth account: {str(e)}")
            return False
    
    async def unlink_oauth_account(
        self,
        user_id: str,
        provider: str
    ) -> bool:
        """
        Unlink OAuth account from user
        """
        if not self.clerk_client:
            from app.core.clerk import get_clerk_client
            self.clerk_client = get_clerk_client()
        
        try:
            # Get current user
            user = await self.clerk_client.get_user(user_id)
            
            # Remove OAuth info from metadata
            public_metadata = user.public_metadata or {}
            if f"oauth_{provider}" in public_metadata:
                del public_metadata[f"oauth_{provider}"]
            
            await self.clerk_client.update_user(
                user_id=user_id,
                public_metadata=public_metadata
            )
            
            logger.info(f"Unlinked {provider} account from user {user_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to unlink OAuth account: {str(e)}")
            return False
    
    def get_supported_providers(self) -> List[str]:
        """
        Get list of configured OAuth providers
        """
        return list(self.providers.keys())


# Singleton instance
oauth_service = OAuthService()