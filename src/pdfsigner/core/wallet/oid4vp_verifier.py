"""
oid4vp_verifier.py - OpenID4VP Relying Party for EUDI Wallet

Implements basic OpenID for Verifiable Presentations (OpenID4VP)
protocol for requesting and verifying presentations from the
EU Digital Identity Wallet.

Standards:
- OpenID for Verifiable Presentations 1.0 (Draft 25)
- CIR (EU) 2024/2982 (EUDIW protocols and interfaces)

Note: This is an exploratory implementation. The Python ecosystem
for OpenID4VP is immature. Production use may require wrapping
Java/Kotlin reference implementations.
"""

import json
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


@dataclass
class PresentationRequest:
    """OpenID4VP Authorization Request."""

    request_uri: str = ""
    client_id: str = ""
    nonce: str = ""
    state: str = ""
    redirect_uri: str = ""
    presentation_definition: dict[str, Any] = field(default_factory=dict)

    def to_qr_data(self) -> str:
        """Generate QR code data for wallet scanning."""
        if self.request_uri:
            return self.request_uri

        params = {
            "client_id": self.client_id,
            "response_type": "vp_token",
            "nonce": self.nonce,
            "state": self.state,
            "redirect_uri": self.redirect_uri,
            "presentation_definition": json.dumps(self.presentation_definition),
        }
        return f"openid4vp://authorize?{urlencode(params)}"


@dataclass
class PresentationResponse:
    """OpenID4VP Authorization Response."""

    vp_token: str = ""
    presentation_submission: dict[str, Any] = field(default_factory=dict)
    state: str = ""
    is_valid: bool = False
    error: str = ""


class OID4VPVerifier:
    """OpenID4VP Relying Party (Verifier).

    Creates presentation requests and verifies responses from
    EUDI Wallet instances.
    """

    def __init__(
        self,
        client_id: str,
        redirect_uri: str = "http://localhost:8765/oid4vp/callback",
    ):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self._pending_requests: dict[str, PresentationRequest] = {}

    def create_pid_request(
        self,
        required_claims: list[str] | None = None,
        transaction_data: dict[str, Any] | None = None,
    ) -> PresentationRequest:
        """Create a presentation request for Person Identification Data.

        Args:
            required_claims: Required PID claims (default: basic identity)
            transaction_data: Optional transaction data for consent binding

        Returns:
            PresentationRequest with all parameters
        """
        if required_claims is None:
            required_claims = ["given_name", "family_name", "birth_date"]

        nonce = secrets.token_urlsafe(32)
        state = secrets.token_urlsafe(16)

        # Build Presentation Exchange definition
        fields = [
            {"path": [f"$.{claim}"], "filter": {"type": "string"}} for claim in required_claims
        ]

        presentation_definition = {
            "id": f"pid-request-{state}",
            "input_descriptors": [
                {
                    "id": "pid",
                    "name": "Person Identification Data",
                    "purpose": "Identity verification for document signing",
                    "format": {
                        "vc+sd-jwt": {"alg": ["ES256"]},
                    },
                    "constraints": {
                        "fields": fields,
                    },
                }
            ],
        }

        # Add transaction data if provided (for informed consent)
        if transaction_data:
            presentation_definition["transaction_data"] = transaction_data

        request = PresentationRequest(
            client_id=self.client_id,
            nonce=nonce,
            state=state,
            redirect_uri=self.redirect_uri,
            presentation_definition=presentation_definition,
        )

        self._pending_requests[state] = request
        return request

    def create_qeaa_request(
        self,
        credential_type: str,
        required_attributes: list[str] | None = None,
    ) -> PresentationRequest:
        """Create a presentation request for QEAA.

        Args:
            credential_type: QEAA type (e.g., "ProfessionalQualification")
            required_attributes: Required attribute names

        Returns:
            PresentationRequest for QEAA
        """
        if required_attributes is None:
            required_attributes = ["profession", "license_number"]

        nonce = secrets.token_urlsafe(32)
        state = secrets.token_urlsafe(16)

        fields = [
            {"path": [f"$.{attr}"], "filter": {"type": "string"}} for attr in required_attributes
        ]

        presentation_definition = {
            "id": f"qeaa-request-{state}",
            "input_descriptors": [
                {
                    "id": "qeaa",
                    "name": f"Qualified Attestation: {credential_type}",
                    "purpose": "Professional qualification verification for signing",
                    "format": {
                        "vc+sd-jwt": {"alg": ["ES256"]},
                    },
                    "constraints": {
                        "fields": fields,
                    },
                }
            ],
        }

        request = PresentationRequest(
            client_id=self.client_id,
            nonce=nonce,
            state=state,
            redirect_uri=self.redirect_uri,
            presentation_definition=presentation_definition,
        )

        self._pending_requests[state] = request
        return request

    def verify_response(
        self,
        vp_token: str,
        state: str,
    ) -> PresentationResponse:
        """Verify a presentation response from the wallet.

        Args:
            vp_token: The VP token (SD-JWT VC format)
            state: State parameter to correlate with request

        Returns:
            PresentationResponse with verification result
        """
        response = PresentationResponse(
            vp_token=vp_token,
            state=state,
        )

        # Verify state matches a pending request
        if state not in self._pending_requests:
            response.error = "Unknown state parameter"
            return response

        # Parse the VP token as SD-JWT VC
        from pdfsigner.core.wallet.sdjwt_verifier import verify_sd_jwt_vc

        vc_result = verify_sd_jwt_vc(vp_token)
        if not vc_result.is_valid:
            response.error = f"VP token verification failed: {', '.join(vc_result.issues)}"
            return response

        response.is_valid = True

        # Clean up pending request
        del self._pending_requests[state]

        return response

    def create_signing_request(
        self,
        document_hash: str,
        hash_algorithm: str = "SHA-256",
    ) -> PresentationRequest:
        """Create a request for wallet-assisted signing with transaction data.

        Includes the document hash as transaction data so the wallet
        can display it to the user for informed consent.

        Args:
            document_hash: Hex-encoded hash of the document to sign
            hash_algorithm: Hash algorithm used

        Returns:
            PresentationRequest with transaction data binding
        """
        transaction_data = {
            "type": "document_signing",
            "document_hash": document_hash,
            "hash_algorithm": hash_algorithm,
        }

        return self.create_pid_request(
            required_claims=["given_name", "family_name"],
            transaction_data=transaction_data,
        )
