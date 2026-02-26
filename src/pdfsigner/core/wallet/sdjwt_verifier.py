"""
sdjwt_verifier.py - SD-JWT VC verification for EUDI Wallet integration

Verifies Selective Disclosure JWT Verifiable Credentials (SD-JWT VC)
as used in the EU Digital Identity Wallet ecosystem.

Standards:
- RFC 9901 (SD-JWT - Selective Disclosure for JWTs)
- draft-ietf-oauth-sd-jwt-vc-14 (SD-JWT VC profile)
- CIR (EU) 2024/2982 (EUDIW protocols and interfaces)
"""

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SDJWTClaim:
    """A single claim from an SD-JWT VC."""

    name: str
    value: Any
    disclosed: bool = True


@dataclass
class SDJWTVCResult:
    """Result of SD-JWT VC verification."""

    is_valid: bool = False
    issuer: str = ""
    subject: str = ""
    claims: list[SDJWTClaim] = field(default_factory=list)
    credential_type: str = ""  # e.g., "PersonIdentificationData", "QEAA"
    issued_at: str = ""
    expires_at: str = ""
    key_binding_valid: bool = False
    issues: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload without signature verification.

    Args:
        token: JWT string (header.payload.signature)

    Returns:
        Decoded payload as dict
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")

    payload_bytes = _base64url_decode(parts[1])
    return json.loads(payload_bytes)


def _decode_disclosure(disclosure: str) -> tuple[str, str, Any] | None:
    """Decode an SD-JWT disclosure.

    Disclosures are base64url-encoded JSON arrays: [salt, claim_name, claim_value]

    Returns:
        Tuple of (salt, claim_name, claim_value) or None if invalid
    """
    try:
        decoded = _base64url_decode(disclosure)
        data = json.loads(decoded)
        if isinstance(data, list) and len(data) >= 3:
            return (str(data[0]), str(data[1]), data[2])
    except Exception:
        pass
    return None


def verify_sd_jwt_vc(sd_jwt_vc: str) -> SDJWTVCResult:
    """Verify an SD-JWT VC presentation.

    Parses the SD-JWT VC format:
    <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<KB-JWT>

    Note: This performs structural verification only. Cryptographic
    signature verification requires the issuer's public key and is
    not implemented here (would need integration with trust registry).

    Args:
        sd_jwt_vc: The complete SD-JWT VC string

    Returns:
        SDJWTVCResult with parsed and verified claims
    """
    result = SDJWTVCResult()

    try:
        # Split into components
        parts = sd_jwt_vc.split("~")
        if len(parts) < 1:
            result.issues.append("Empty SD-JWT VC")
            return result

        issuer_jwt = parts[0]
        disclosures = [p for p in parts[1:] if p]  # Filter empty strings

        # Check if last non-empty part is KB-JWT
        kb_jwt = None
        if disclosures and "." in disclosures[-1]:
            # Looks like a JWT (has dots) - might be KB-JWT
            potential_kb = disclosures[-1]
            try:
                kb_payload = _decode_jwt_payload(potential_kb)
                if "nonce" in kb_payload or "aud" in kb_payload:
                    kb_jwt = potential_kb
                    disclosures = disclosures[:-1]
            except Exception:
                pass

        # Decode issuer JWT payload
        payload = _decode_jwt_payload(issuer_jwt)
        result.raw_payload = payload
        result.issuer = payload.get("iss", "")
        result.subject = payload.get("sub", "")
        result.issued_at = payload.get("iat", "")
        result.expires_at = payload.get("exp", "")
        result.credential_type = payload.get("vct", payload.get("type", ""))

        # Build disclosure hash map
        sd_digests = payload.get("_sd", [])
        disclosure_map: dict[str, tuple[str, Any]] = {}

        for disc_str in disclosures:
            parsed = _decode_disclosure(disc_str)
            if parsed:
                salt, name, value = parsed
                # Compute hash
                disc_hash = (
                    base64.urlsafe_b64encode(hashlib.sha256(disc_str.encode()).digest())
                    .decode()
                    .rstrip("=")
                )
                disclosure_map[disc_hash] = (name, value)
                result.claims.append(
                    SDJWTClaim(
                        name=name,
                        value=value,
                        disclosed=True,
                    )
                )

        # Add non-selective claims from payload
        reserved_keys = {
            "iss",
            "sub",
            "iat",
            "exp",
            "nbf",
            "jti",
            "vct",
            "type",
            "_sd",
            "_sd_alg",
            "cnf",
            "status",
        }
        for key, value in payload.items():
            if key not in reserved_keys:
                result.claims.append(
                    SDJWTClaim(
                        name=key,
                        value=value,
                        disclosed=True,
                    )
                )

        # Verify Key Binding JWT
        if kb_jwt:
            try:
                kb_payload = _decode_jwt_payload(kb_jwt)
                # Basic structural check
                result.key_binding_valid = bool(kb_payload.get("nonce") or kb_payload.get("aud"))
            except Exception as e:
                result.issues.append(f"KB-JWT verification failed: {e}")

        result.is_valid = True

    except Exception as e:
        result.issues.append(f"SD-JWT VC parsing failed: {e}")
        logger.warning("SD-JWT VC verification failed: %s", e)

    return result


def extract_pid_claims(result: SDJWTVCResult) -> dict[str, Any]:
    """Extract Person Identification Data (PID) claims from verified SD-JWT VC.

    PID claims are defined in CIR (EU) 2024/2977.

    Args:
        result: Verified SD-JWT VC result

    Returns:
        Dictionary of PID claims
    """
    pid_fields = {
        "given_name",
        "family_name",
        "birth_date",
        "age_over_18",
        "age_in_years",
        "age_birth_year",
        "family_name_birth",
        "given_name_birth",
        "birth_place",
        "birth_country",
        "birth_state",
        "birth_city",
        "resident_address",
        "resident_country",
        "resident_state",
        "resident_city",
        "resident_postal_code",
        "resident_street",
        "gender",
        "nationality",
        "issuance_date",
        "expiry_date",
        "issuing_authority",
        "document_number",
        "administrative_number",
        "issuing_country",
        "issuing_jurisdiction",
    }

    pid: dict[str, Any] = {}
    for claim in result.claims:
        if claim.name in pid_fields:
            pid[claim.name] = claim.value

    return pid
