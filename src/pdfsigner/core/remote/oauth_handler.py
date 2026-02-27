"""
oauth_handler.py - OAuth 2.0 authorization flow for QTSP authentication

Implements OAuth 2.0 Authorization Code flow with PKCE for authenticating
with Qualified Trust Service Providers for remote signing.
"""

import hashlib
import secrets
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from urllib.parse import urlencode

import requests
from loguru import logger


@dataclass
class OAuthToken:
    """OAuth 2.0 token response."""

    access_token: str = ""
    token_type: str = "bearer"
    expires_in: int = 3600
    refresh_token: str = ""
    scope: str = ""
    obtained_at: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return time.time() > (self.obtained_at + self.expires_in - 60)  # 60s buffer


class OAuthHandler:
    """OAuth 2.0 handler for QTSP authentication.

    Supports:
    - Authorization Code flow with PKCE
    - Token refresh
    - Token storage
    """

    def __init__(
        self,
        authorize_url: str,
        token_url: str,
        client_id: str,
        redirect_uri: str = "http://localhost:8765/callback",
        scope: str = "service credential",
    ):
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self._token: OAuthToken | None = None
        self._code_verifier: str = ""
        self._state: str = ""

    def generate_auth_url(self) -> str:
        """Generate authorization URL with PKCE challenge.

        Returns:
            URL to redirect user for authorization
        """
        # Generate PKCE code verifier and challenge
        self._code_verifier = secrets.token_urlsafe(64)[:128]
        code_challenge = (
            urlsafe_b64encode(hashlib.sha256(self._code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(32),
        }
        self._state = params["state"]

        return f"{self.authorize_url}?{urlencode(params)}"

    def exchange_code(self, authorization_code: str, state: str = "") -> OAuthToken:
        """Exchange authorization code for access token.

        Args:
            authorization_code: Code received from authorization callback
            state: State parameter from callback (verified against stored state)

        Returns:
            OAuthToken with access and refresh tokens

        Raises:
            ValueError: If state parameter doesn't match (CSRF protection)
        """
        if state and self._state and state != self._state:
            raise ValueError("OAuth state mismatch — possible CSRF attack")

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": self._code_verifier,
        }

        response = requests.post(
            self.token_url,
            data=data,
            timeout=30,
        )
        response.raise_for_status()

        token_data = response.json()
        self._token = OAuthToken(
            access_token=token_data["access_token"],
            token_type=token_data.get("token_type", "bearer"),
            expires_in=token_data.get("expires_in", 3600),
            refresh_token=token_data.get("refresh_token", ""),
            scope=token_data.get("scope", ""),
        )

        logger.info("OAuth token obtained, expires in %ds", self._token.expires_in)
        return self._token

    def refresh_token(self) -> OAuthToken:
        """Refresh expired access token.

        Returns:
            New OAuthToken

        Raises:
            ValueError: If no refresh token available
        """
        if not self._token or not self._token.refresh_token:
            raise ValueError("No refresh token available")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._token.refresh_token,
            "client_id": self.client_id,
        }

        response = requests.post(self.token_url, data=data, timeout=30)
        response.raise_for_status()

        token_data = response.json()
        self._token = OAuthToken(
            access_token=token_data["access_token"],
            token_type=token_data.get("token_type", "bearer"),
            expires_in=token_data.get("expires_in", 3600),
            refresh_token=token_data.get("refresh_token", self._token.refresh_token),
            scope=token_data.get("scope", ""),
        )

        logger.info("OAuth token refreshed")
        return self._token

    def get_valid_token(self) -> OAuthToken | None:
        """Get a valid (non-expired) token, refreshing if needed.

        Returns:
            OAuthToken or None if no token available
        """
        if self._token is None:
            return None

        if self._token.is_expired and self._token.refresh_token:
            try:
                return self.refresh_token()
            except Exception:
                logger.warning("Token refresh failed, re-authentication may be required")
                return None

        return self._token if not self._token.is_expired else None
