"""
csc_client.py - CSC API v2 client for remote digital signature creation

Implements the Cloud Signature Consortium API V2.2 (November 2025) for
remote signing via Qualified Trust Service Providers (QTSPs).

Standards:
- CSC API V2.2 (Cloud Signature Consortium, Nov 2025)
- ETSI TS 119 432 (Protocols for remote digital signature creation)

Endpoints implemented:
- POST /info - Service capabilities and metadata
- POST /credentials/list - List available signing certificates
- POST /credentials/info - Certificate details
- POST /credentials/authorize - Authorize credential use
- POST /signatures/signHash - Sign pre-computed hash(es)
- POST /signatures/signDoc - Sign complete document
"""

from typing import Any

import requests

# Re-export types for backward compatibility
from pdfsigner.core.remote.csc_types import (
    CSCAuthorizationResult,
    CSCCredentialInfo,
    CSCError,
    CSCServiceInfo,
    CSCSignAlgo,
    CSCSignHashResult,
)


class CSCClient:
    """CSC API v2 client for remote signing operations.

    Communicates with a QTSP's remote signing service using the
    Cloud Signature Consortium API v2 protocol.
    """

    def __init__(
        self,
        service_url: str,
        timeout: int = 30,
        verify_ssl: bool = True,
    ):
        """Initialize CSC client.

        Args:
            service_url: Base URL of the CSC service (e.g., https://qtsp.example.com/csc/v2)
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify TLS certificates
        """
        self.service_url = service_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Validate service URL (SSRF protection)
        from urllib.parse import urlparse

        parsed = urlparse(self.service_url)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"CSC service URL must use HTTPS: {self.service_url}")
        self._access_token: str | None = None
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def set_access_token(self, token: str) -> None:
        """Set OAuth2 access token for authenticated requests."""
        self._access_token = token
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _post(self, endpoint: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        """Make POST request to CSC endpoint.

        Args:
            endpoint: API endpoint (e.g., "/info")
            data: JSON request body

        Returns:
            JSON response as dict

        Raises:
            CSCError: If request fails
        """
        url = f"{self.service_url}{endpoint}"
        try:
            response = self._session.post(
                url,
                json=data or {},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_body: dict[str, Any] = {}
            try:
                error_body = e.response.json()
            except Exception:
                pass
            raise CSCError(
                f"CSC API error: {e.response.status_code}",
                status_code=e.response.status_code,
                error_code=error_body.get("error", ""),
                error_description=error_body.get("error_description", str(e)),
            ) from e
        except requests.exceptions.RequestException as e:
            raise CSCError(f"CSC request failed: {e}") from e

    # --- API Endpoints ---

    def get_info(self) -> CSCServiceInfo:
        """Get service information (POST /info).

        Returns:
            CSCServiceInfo with service capabilities
        """
        data = self._post("/info")
        return CSCServiceInfo(
            name=data.get("specs", ""),
            lang=data.get("lang", []),
            methods=data.get("methods", []),
            auth_type=data.get("authType", []),
            signature_formats=data.get("signatureFormats", []),
            description=data.get("description", ""),
            region=data.get("region", ""),
            logo=data.get("logo", ""),
        )

    def list_credentials(self) -> list[str]:
        """List available signing credentials (POST /credentials/list).

        Returns:
            List of credential IDs
        """
        data = self._post("/credentials/list")
        return data.get("credentialIDs", [])

    def get_credential_info(self, credential_id: str) -> CSCCredentialInfo:
        """Get credential details (POST /credentials/info).

        Args:
            credential_id: ID of the credential

        Returns:
            CSCCredentialInfo with certificate and key details
        """
        data = self._post(
            "/credentials/info",
            {
                "credentialID": credential_id,
                "certificates": "chain",
            },
        )

        cert_data = data.get("cert", {})
        key_data = data.get("key", {})

        return CSCCredentialInfo(
            credential_id=credential_id,
            description=data.get("description", ""),
            key_algo=key_data.get("algo", [""])[0] if key_data.get("algo") else "",
            key_len=key_data.get("len", 0),
            sign_algos=key_data.get("algo", []),
            certificates=cert_data.get("certificates", []),
            certificate_chain=cert_data.get("certificates", []),
            issuer_dn=cert_data.get("issuerDN", ""),
            subject_dn=cert_data.get("subjectDN", ""),
            valid_from=cert_data.get("validFrom", ""),
            valid_to=cert_data.get("validTo", ""),
            status=cert_data.get("status", ""),
            multisign=data.get("multisign", 1),
            scal=data.get("SCAL", "1"),
        )

    def authorize_credential(
        self,
        credential_id: str,
        num_signatures: int = 1,
        pin: str | None = None,
        otp: str | None = None,
    ) -> CSCAuthorizationResult:
        """Authorize credential for signing (POST /credentials/authorize).

        Args:
            credential_id: ID of the credential
            num_signatures: Number of signatures to authorize
            pin: User PIN (if required)
            otp: One-time password (if required)

        Returns:
            CSCAuthorizationResult with SAD token
        """
        request_data: dict[str, Any] = {
            "credentialID": credential_id,
            "numSignatures": num_signatures,
        }
        if pin:
            request_data["PIN"] = pin
        if otp:
            request_data["OTP"] = otp

        data = self._post("/credentials/authorize", request_data)

        return CSCAuthorizationResult(
            sad=data.get("SAD", ""),
            expires_in=data.get("expiresIn", 0),
        )

    def sign_hash(
        self,
        credential_id: str,
        sad: str,
        hashes: list[str],
        sign_algo: str = CSCSignAlgo.RSA_SHA256.value,
    ) -> CSCSignHashResult:
        """Sign hash values (POST /signatures/signHash).

        Args:
            credential_id: ID of the credential
            sad: Signature Activation Data from authorization
            hashes: List of Base64-encoded hash values to sign
            sign_algo: Signature algorithm OID

        Returns:
            CSCSignHashResult with Base64-encoded signatures
        """
        data = self._post(
            "/signatures/signHash",
            {
                "credentialID": credential_id,
                "SAD": sad,
                "hash": hashes,
                "signAlgo": sign_algo,
            },
        )

        return CSCSignHashResult(
            signatures=data.get("signatures", []),
        )

    def sign_doc(
        self,
        credential_id: str,
        sad: str,
        document: str,  # Base64-encoded document
        sign_algo: str = CSCSignAlgo.RSA_SHA256.value,
    ) -> dict[str, Any]:
        """Sign complete document (POST /signatures/signDoc).

        Args:
            credential_id: ID of the credential
            sad: Signature Activation Data
            document: Base64-encoded document to sign
            sign_algo: Signature algorithm OID

        Returns:
            Response dict with signed document
        """
        return self._post(
            "/signatures/signDoc",
            {
                "credentialID": credential_id,
                "SAD": sad,
                "document": document,
                "signAlgo": sign_algo,
            },
        )

    # --- Batch Signing ---

    def sign_batch(
        self,
        credential_id: str,
        sad: str,
        hashes: list[str],
        sign_algo: str = CSCSignAlgo.RSA_SHA256.value,
    ) -> list[str]:
        """Sign multiple hashes in a single batch operation.

        Uses CSC API v2 batch signing: one authorization (PIN/OTP)
        for multiple document hashes. The number of hashes must not
        exceed the credential's ``multisign`` limit.

        Args:
            credential_id: ID of the credential
            sad: Signature Activation Data (valid for N signatures)
            hashes: List of Base64-encoded hash values
            sign_algo: Signature algorithm OID

        Returns:
            List of Base64-encoded signatures (same order as hashes)

        Raises:
            CSCError: If signing fails or batch limit exceeded
        """
        result = self.sign_hash(credential_id, sad, hashes, sign_algo)
        return result.signatures

    def authorize_and_sign_batch(
        self,
        credential_id: str,
        hashes: list[str],
        sign_algo: str = CSCSignAlgo.RSA_SHA256.value,
        pin: str | None = None,
        otp: str | None = None,
    ) -> list[str]:
        """Complete batch signing flow: authorize once, sign N hashes.

        Combines credential authorization and batch hash signing into
        a single operation. The user provides PIN/OTP once for all
        documents.

        Args:
            credential_id: Credential to use
            hashes: List of Base64-encoded document hashes
            sign_algo: Signature algorithm OID
            pin: User PIN (if required by QTSP)
            otp: One-time password (if required by QTSP)

        Returns:
            List of Base64-encoded signatures
        """
        # 1. Authorize for N signatures
        auth = self.authorize_credential(
            credential_id=credential_id,
            num_signatures=len(hashes),
            pin=pin,
            otp=otp,
        )

        if not auth.sad:
            raise CSCError("Authorization failed: no SAD received")

        # 2. Sign all hashes with single SAD
        return self.sign_batch(
            credential_id=credential_id,
            sad=auth.sad,
            hashes=hashes,
            sign_algo=sign_algo,
        )

    def get_batch_limit(self, credential_id: str) -> int:
        """Get maximum batch size for a credential.

        Returns:
            Maximum number of signatures per authorization (multisign value)
        """
        info = self.get_credential_info(credential_id)
        return info.multisign
