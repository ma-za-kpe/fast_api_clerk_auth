"""
WebAuthn/Passkeys Service
Implements FIDO2/WebAuthn for passwordless biometric authentication
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import base64
import json
import secrets
from dataclasses import dataclass

from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    AuthenticatorAttachment
)
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.client import ClientData
from fido2.utils import websafe_encode, websafe_decode
from fido2 import cbor

from app.core.config import settings
from app.core.cache import cache_service
from app.core.database import get_db
from app.core.exceptions import (
    BadRequestError,
    NotFoundError,
    AuthenticationError,
    ConflictError
)
from app.services.activity_service import activity_service
from sqlalchemy import select, and_, delete
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class WebAuthnCredential:
    """WebAuthn credential data"""
    credential_id: str
    public_key: bytes
    sign_count: int
    user_id: str
    name: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    authenticator_type: Optional[str] = None
    is_passkey: bool = False
    backed_up: bool = False
    device_info: Optional[Dict[str, Any]] = None


class WebAuthnService:
    """Service for WebAuthn/Passkeys authentication"""
    
    def __init__(self):
        # Configure RP (Relying Party)
        self.rp_id = settings.FRONTEND_URL.replace("https://", "").replace("http://", "").split(":")[0]
        self.rp_name = settings.APP_NAME or "FastAPI Auth"
        
        # Initialize FIDO2 server
        self.rp = PublicKeyCredentialRpEntity(
            id=self.rp_id,
            name=self.rp_name
        )
        
        self.server = Fido2Server(self.rp)
        
        # Configuration
        self.challenge_ttl = 300  # 5 minutes
        self.max_credentials_per_user = 10
        
        # Supported algorithms (in order of preference)
        self.supported_algorithms = [
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-7  # ES256 (ECDSA w/ SHA-256)
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-257  # RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=-8  # EdDSA
            )
        ]
    
    async def start_registration(
        self,
        user_id: str,
        user_email: str,
        user_name: Optional[str] = None,
        authenticator_attachment: Optional[str] = None,
        resident_key: bool = True,
        user_verification: str = "preferred"
    ) -> Dict[str, Any]:
        """
        Start WebAuthn registration ceremony
        
        Args:
            user_id: User identifier
            user_email: User email
            user_name: Display name
            authenticator_attachment: "platform", "cross-platform", or None
            resident_key: Whether to create a passkey (discoverable credential)
            user_verification: "required", "preferred", or "discouraged"
        """
        # Get existing credentials to exclude
        existing_credentials = await self._get_user_credentials(user_id)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=websafe_decode(cred.credential_id)
            )
            for cred in existing_credentials
        ]
        
        # Create user entity
        user = PublicKeyCredentialUserEntity(
            id=user_id.encode(),
            name=user_email,
            display_name=user_name or user_email
        )
        
        # Configure authenticator selection
        authenticator_selection = AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment(authenticator_attachment) if authenticator_attachment else None,
            resident_key=ResidentKeyRequirement.REQUIRED if resident_key else ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement(user_verification)
        )
        
        # Generate registration options
        options, state = self.server.register_begin(
            user=user,
            credentials=exclude_credentials,
            authenticator_selection=authenticator_selection,
            attestation=AttestationConveyancePreference.NONE,
            challenge=secrets.token_bytes(32)
        )
        
        # Store challenge in cache
        challenge_key = f"webauthn_reg_challenge:{user_id}"
        await cache_service.set(
            challenge_key,
            {
                "challenge": websafe_encode(state["challenge"]),
                "user_id": user_id,
                "user_email": user_email,
                "user_name": user_name
            },
            ttl=self.challenge_ttl
        )
        
        # Convert to JSON-serializable format
        return {
            "publicKey": {
                "challenge": websafe_encode(options.challenge),
                "rp": {
                    "id": options.rp.id,
                    "name": options.rp.name
                },
                "user": {
                    "id": websafe_encode(options.user.id),
                    "name": options.user.name,
                    "displayName": options.user.display_name
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": param.alg}
                    for param in options.pub_key_cred_params
                ],
                "timeout": options.timeout,
                "excludeCredentials": [
                    {
                        "type": "public-key",
                        "id": websafe_encode(cred.id)
                    }
                    for cred in options.exclude_credentials
                ] if options.exclude_credentials else [],
                "authenticatorSelection": {
                    "authenticatorAttachment": authenticator_selection.authenticator_attachment.value if authenticator_selection.authenticator_attachment else None,
                    "residentKey": authenticator_selection.resident_key.value,
                    "userVerification": authenticator_selection.user_verification.value
                },
                "attestation": options.attestation.value
            }
        }
    
    async def complete_registration(
        self,
        user_id: str,
        credential_id: str,
        client_data_json: str,
        attestation_object: str,
        credential_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Complete WebAuthn registration ceremony
        
        Args:
            user_id: User identifier
            credential_id: Base64 encoded credential ID
            client_data_json: Base64 encoded client data
            attestation_object: Base64 encoded attestation object
            credential_name: Optional name for the credential
        """
        # Get challenge from cache
        challenge_key = f"webauthn_reg_challenge:{user_id}"
        challenge_data = await cache_service.get(challenge_key)
        
        if not challenge_data:
            raise BadRequestError("Registration challenge expired or not found")
        
        # Decode data
        try:
            credential_id_bytes = websafe_decode(credential_id)
            client_data = ClientData(websafe_decode(client_data_json))
            attestation = AttestationObject(websafe_decode(attestation_object))
        except Exception as e:
            raise BadRequestError(f"Invalid registration data: {str(e)}")
        
        # Verify registration
        state = {"challenge": websafe_decode(challenge_data["challenge"])}
        
        try:
            auth_data = self.server.register_complete(
                state,
                response=attestation,
                client_data=client_data
            )
        except Exception as e:
            raise BadRequestError(f"Registration verification failed: {str(e)}")
        
        # Check credential limit
        existing_count = await self._count_user_credentials(user_id)
        if existing_count >= self.max_credentials_per_user:
            raise BadRequestError(f"Maximum credentials limit ({self.max_credentials_per_user}) reached")
        
        # Determine credential type
        is_passkey = auth_data.is_user_present and auth_data.is_user_verified
        authenticator_type = self._detect_authenticator_type(attestation_object)
        
        # Store credential
        credential = WebAuthnCredential(
            credential_id=credential_id,
            public_key=auth_data.credential_data.public_key,
            sign_count=auth_data.counter,
            user_id=user_id,
            name=credential_name or f"Credential {existing_count + 1}",
            created_at=datetime.utcnow(),
            authenticator_type=authenticator_type,
            is_passkey=is_passkey,
            backed_up=auth_data.is_backed_up if hasattr(auth_data, 'is_backed_up') else False
        )
        
        await self._store_credential(credential)
        
        # Clear challenge
        await cache_service.delete(challenge_key)
        
        # Log activity
        await activity_service.log_activity(
            user_id=user_id,
            action="webauthn.credential_registered",
            resource_type="credential",
            resource_id=credential_id,
            details={
                "credential_name": credential.name,
                "is_passkey": is_passkey,
                "authenticator_type": authenticator_type
            }
        )
        
        return {
            "credential_id": credential_id,
            "name": credential.name,
            "is_passkey": is_passkey,
            "authenticator_type": authenticator_type,
            "created_at": credential.created_at.isoformat()
        }
    
    async def start_authentication(
        self,
        user_id: Optional[str] = None,
        user_verification: str = "preferred"
    ) -> Dict[str, Any]:
        """
        Start WebAuthn authentication ceremony
        
        Args:
            user_id: Optional user ID for second factor auth
            user_verification: "required", "preferred", or "discouraged"
        """
        # Get credentials to allow
        allow_credentials = []
        
        if user_id:
            # Second factor authentication - get user's credentials
            credentials = await self._get_user_credentials(user_id)
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    id=websafe_decode(cred.credential_id)
                )
                for cred in credentials
            ]
        
        # For passkey authentication (no user_id), allow_credentials is empty
        # The authenticator will use discoverable credentials
        
        # Generate authentication options
        challenge = secrets.token_bytes(32)
        
        # Store challenge
        challenge_key = f"webauthn_auth_challenge:{challenge.hex()}"
        await cache_service.set(
            challenge_key,
            {
                "challenge": websafe_encode(challenge),
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat()
            },
            ttl=self.challenge_ttl
        )
        
        return {
            "publicKey": {
                "challenge": websafe_encode(challenge),
                "rpId": self.rp_id,
                "timeout": 60000,  # 60 seconds
                "allowCredentials": [
                    {
                        "type": "public-key",
                        "id": websafe_encode(cred.id)
                    }
                    for cred in allow_credentials
                ] if allow_credentials else [],
                "userVerification": user_verification
            },
            "challenge_id": challenge.hex()
        }
    
    async def complete_authentication(
        self,
        challenge_id: str,
        credential_id: str,
        client_data_json: str,
        authenticator_data: str,
        signature: str,
        user_handle: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Complete WebAuthn authentication ceremony
        
        Args:
            challenge_id: Challenge identifier
            credential_id: Base64 encoded credential ID
            client_data_json: Base64 encoded client data
            authenticator_data: Base64 encoded authenticator data
            signature: Base64 encoded signature
            user_handle: Optional user handle for passkey auth
        """
        # Get challenge from cache
        challenge_key = f"webauthn_auth_challenge:{challenge_id}"
        challenge_data = await cache_service.get(challenge_key)
        
        if not challenge_data:
            raise AuthenticationError("Authentication challenge expired or not found")
        
        # Decode data
        try:
            credential_id_bytes = websafe_decode(credential_id)
            client_data = ClientData(websafe_decode(client_data_json))
            auth_data = AuthenticatorData(websafe_decode(authenticator_data))
            signature_bytes = websafe_decode(signature)
        except Exception as e:
            raise BadRequestError(f"Invalid authentication data: {str(e)}")
        
        # Get credential from database
        stored_credential = await self._get_credential(credential_id)
        if not stored_credential:
            raise AuthenticationError("Credential not found")
        
        # Verify user if provided
        if challenge_data["user_id"] and stored_credential.user_id != challenge_data["user_id"]:
            raise AuthenticationError("Credential does not belong to user")
        
        # Verify authentication
        state = {"challenge": websafe_decode(challenge_data["challenge"])}
        
        try:
            self.server.authenticate_complete(
                state,
                credentials=[stored_credential.public_key],
                credential_id=credential_id_bytes,
                client_data=client_data,
                auth_data=auth_data,
                signature=signature_bytes
            )
        except Exception as e:
            raise AuthenticationError(f"Authentication verification failed: {str(e)}")
        
        # Verify sign count
        if auth_data.counter > 0 and auth_data.counter <= stored_credential.sign_count:
            # Possible cloned authenticator
            await activity_service.log_activity(
                user_id=stored_credential.user_id,
                action="webauthn.suspicious_activity",
                resource_type="credential",
                resource_id=credential_id,
                details={"reason": "Sign count not incremented"}
            )
            raise AuthenticationError("Suspicious authenticator activity detected")
        
        # Update credential
        await self._update_credential_usage(
            credential_id,
            sign_count=auth_data.counter,
            last_used=datetime.utcnow()
        )
        
        # Clear challenge
        await cache_service.delete(challenge_key)
        
        # Log activity
        await activity_service.log_activity(
            user_id=stored_credential.user_id,
            action="webauthn.authentication_success",
            resource_type="credential",
            resource_id=credential_id,
            details={
                "credential_name": stored_credential.name,
                "is_passkey": stored_credential.is_passkey
            }
        )
        
        return {
            "user_id": stored_credential.user_id,
            "credential_id": credential_id,
            "credential_name": stored_credential.name,
            "is_passkey": stored_credential.is_passkey,
            "authenticated_at": datetime.utcnow().isoformat()
        }
    
    async def list_user_credentials(
        self,
        user_id: str
    ) -> List[Dict[str, Any]]:
        """List all WebAuthn credentials for a user"""
        credentials = await self._get_user_credentials(user_id)
        
        return [
            {
                "credential_id": cred.credential_id,
                "name": cred.name,
                "is_passkey": cred.is_passkey,
                "authenticator_type": cred.authenticator_type,
                "backed_up": cred.backed_up,
                "created_at": cred.created_at.isoformat(),
                "last_used_at": cred.last_used_at.isoformat() if cred.last_used_at else None
            }
            for cred in credentials
        ]
    
    async def rename_credential(
        self,
        user_id: str,
        credential_id: str,
        new_name: str
    ) -> Dict[str, str]:
        """Rename a WebAuthn credential"""
        credential = await self._get_credential(credential_id)
        
        if not credential or credential.user_id != user_id:
            raise NotFoundError("Credential not found")
        
        await self._update_credential_name(credential_id, new_name)
        
        return {"message": "Credential renamed successfully"}
    
    async def delete_credential(
        self,
        user_id: str,
        credential_id: str
    ) -> Dict[str, str]:
        """Delete a WebAuthn credential"""
        credential = await self._get_credential(credential_id)
        
        if not credential or credential.user_id != user_id:
            raise NotFoundError("Credential not found")
        
        # Check if it's the last credential
        count = await self._count_user_credentials(user_id)
        if count == 1:
            raise BadRequestError("Cannot delete the last credential")
        
        await self._delete_credential(credential_id)
        
        # Log activity
        await activity_service.log_activity(
            user_id=user_id,
            action="webauthn.credential_deleted",
            resource_type="credential",
            resource_id=credential_id,
            details={"credential_name": credential.name}
        )
        
        return {"message": "Credential deleted successfully"}
    
    def _detect_authenticator_type(self, attestation_object: str) -> str:
        """Detect authenticator type from attestation"""
        # This is simplified - in production, parse attestation statement
        # to determine actual authenticator type
        return "platform"  # or "cross-platform", "hybrid", etc.
    
    async def _get_user_credentials(self, user_id: str) -> List[WebAuthnCredential]:
        """Get all credentials for a user from database"""
        # This would query your database
        # For now, returning from cache as example
        cache_key = f"webauthn_credentials:{user_id}"
        credentials = await cache_service.get(cache_key) or []
        
        return [WebAuthnCredential(**cred) for cred in credentials]
    
    async def _get_credential(self, credential_id: str) -> Optional[WebAuthnCredential]:
        """Get a specific credential from database"""
        # This would query your database
        cache_key = f"webauthn_credential:{credential_id}"
        cred_data = await cache_service.get(cache_key)
        
        return WebAuthnCredential(**cred_data) if cred_data else None
    
    async def _count_user_credentials(self, user_id: str) -> int:
        """Count user's credentials"""
        credentials = await self._get_user_credentials(user_id)
        return len(credentials)
    
    async def _store_credential(self, credential: WebAuthnCredential):
        """Store credential in database"""
        # Store in cache as example - should be database
        cache_key = f"webauthn_credential:{credential.credential_id}"
        await cache_service.set(cache_key, credential.__dict__)
        
        # Also update user's credential list
        user_key = f"webauthn_credentials:{credential.user_id}"
        user_creds = await cache_service.get(user_key) or []
        user_creds.append(credential.__dict__)
        await cache_service.set(user_key, user_creds)
    
    async def _update_credential_usage(
        self,
        credential_id: str,
        sign_count: int,
        last_used: datetime
    ):
        """Update credential usage stats"""
        credential = await self._get_credential(credential_id)
        if credential:
            credential.sign_count = sign_count
            credential.last_used_at = last_used
            
            cache_key = f"webauthn_credential:{credential_id}"
            await cache_service.set(cache_key, credential.__dict__)
    
    async def _update_credential_name(self, credential_id: str, new_name: str):
        """Update credential name"""
        credential = await self._get_credential(credential_id)
        if credential:
            credential.name = new_name
            
            cache_key = f"webauthn_credential:{credential_id}"
            await cache_service.set(cache_key, credential.__dict__)
    
    async def _delete_credential(self, credential_id: str):
        """Delete credential from database"""
        credential = await self._get_credential(credential_id)
        if credential:
            # Remove from cache
            await cache_service.delete(f"webauthn_credential:{credential_id}")
            
            # Update user's credential list
            user_key = f"webauthn_credentials:{credential.user_id}"
            user_creds = await cache_service.get(user_key) or []
            user_creds = [c for c in user_creds if c["credential_id"] != credential_id]
            await cache_service.set(user_key, user_creds)


# Create singleton instance
webauthn_service = WebAuthnService()