"""
validation_report.py - eIDAS signature validation report generator

Generates structured validation reports inspired by ETSI TS 119 102-2 V1.4.1.
Reports are produced in JSON format suitable for API responses and auditing.

Standards referenced:
- ETSI TS 119 102-2 V1.4.1 (Signature Validation Report)
- ETSI EN 319 102-1 V1.4.1 (Validation procedures - MainIndication/SubIndication)
- CIR (EU) 2025/1945 (Revocation freshness: 24h max)
- SOGIS v1.3 (Algorithm strength classification)
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pdfsigner.core.crypto.algorithm_policy import (
    AlgorithmAssessment,
    AlgorithmStrength,
    assess_algorithm,
)
from pdfsigner.core.validator.eidas_validator import (
    QualificationLevel,
    ValidationStatus,
    check_revocation_freshness,
)
from pdfsigner.core.validator.pdf_validator import (
    PAdESLevel,
    SignatureInfo,
    SignatureStatus,
    ValidationResult,
)

logger = logging.getLogger(__name__)


# --- ETSI EN 319 102-1 SubIndication values ---


class SubIndication(str, Enum):
    """Sub-indication per ETSI EN 319 102-1 Section 5.1.2."""

    # For TOTAL_FAILED
    FORMAT_FAILURE = "FORMAT_FAILURE"
    HASH_FAILURE = "HASH_FAILURE"
    SIG_CRYPTO_FAILURE = "SIG_CRYPTO_FAILURE"
    REVOKED = "REVOKED"
    SIG_CONSTRAINTS_FAILURE = "SIG_CONSTRAINTS_FAILURE"
    CHAIN_CONSTRAINTS_FAILURE = "CHAIN_CONSTRAINTS_FAILURE"
    CERTIFICATE_CHAIN_GENERAL_FAILURE = "CERTIFICATE_CHAIN_GENERAL_FAILURE"
    CRYPTO_CONSTRAINTS_FAILURE = "CRYPTO_CONSTRAINTS_FAILURE"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    POLICY_PROCESSING_ERROR = "POLICY_PROCESSING_ERROR"
    SIGNATURE_POLICY_NOT_AVAILABLE = "SIGNATURE_POLICY_NOT_AVAILABLE"
    TIMESTAMP_ORDER_FAILURE = "TIMESTAMP_ORDER_FAILURE"

    # For INDETERMINATE
    NO_SIGNING_CERTIFICATE_FOUND = "NO_SIGNING_CERTIFICATE_FOUND"
    NO_CERTIFICATE_CHAIN_FOUND = "NO_CERTIFICATE_CHAIN_FOUND"
    REVOKED_NO_POE = "REVOKED_NO_POE"
    REVOKED_CA_NO_POE = "REVOKED_CA_NO_POE"
    OUT_OF_BOUNDS_NO_POE = "OUT_OF_BOUNDS_NO_POE"
    OUT_OF_BOUNDS_NOT_REVOKED = "OUT_OF_BOUNDS_NOT_REVOKED"
    CRYPTO_CONSTRAINTS_FAILURE_NO_POE = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"
    NO_POE = "NO_POE"
    TRY_LATER = "TRY_LATER"
    SIGNED_DATA_NOT_FOUND = "SIGNED_DATA_NOT_FOUND"


# --- Report Builder ---


def _determine_main_indication(sig: SignatureInfo) -> ValidationStatus:
    """Determine MainIndication per ETSI EN 319 102-1.

    Args:
        sig: Signature info from core validator

    Returns:
        ValidationStatus enum value
    """
    if sig.status == SignatureStatus.VALID:
        # Even if valid, check for revocation
        if sig.revocation_status == "revoked":
            return ValidationStatus.TOTAL_FAILED
        return ValidationStatus.TOTAL_PASSED

    if sig.status == SignatureStatus.INVALID:
        return ValidationStatus.TOTAL_FAILED

    # UNKNOWN or INDETERMINATE
    return ValidationStatus.INDETERMINATE


def _determine_sub_indication(
    sig: SignatureInfo,
    algo_assessment: AlgorithmAssessment | None,
) -> SubIndication | None:
    """Determine SubIndication per ETSI EN 319 102-1.

    Only present when MainIndication is not TOTAL_PASSED.

    Args:
        sig: Signature info from core validator
        algo_assessment: Algorithm assessment result (may be None)

    Returns:
        SubIndication or None if TOTAL_PASSED
    """
    if sig.status == SignatureStatus.VALID and sig.revocation_status != "revoked":
        return None

    # Revocation failures
    if sig.revocation_status == "revoked":
        return SubIndication.REVOKED

    # Invalid signature (hash or crypto failure)
    if sig.status == SignatureStatus.INVALID:
        status_msg = sig.status_message.lower()
        if "modified" in status_msg or "integrity" in status_msg:
            return SubIndication.HASH_FAILURE
        return SubIndication.SIG_CRYPTO_FAILURE

    # Certificate chain issues
    if sig.chain_validation_result and not sig.chain_validation_result.is_valid:
        errors_str = " ".join(sig.chain_validation_result.errors).lower()
        if "expired" in errors_str:
            return SubIndication.EXPIRED
        if "not yet valid" in errors_str:
            return SubIndication.NOT_YET_VALID
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE

    # Algorithm weakness
    if algo_assessment and algo_assessment.overall_strength == AlgorithmStrength.WEAK:
        return SubIndication.CRYPTO_CONSTRAINTS_FAILURE

    # No certificate found
    if sig.certificate_serial == "":
        return SubIndication.NO_SIGNING_CERTIFICATE_FOUND

    # Default indeterminate
    return SubIndication.NO_POE


def _determine_signature_quality(sig: SignatureInfo) -> str:
    """Map eIDAS level to signature quality.

    Args:
        sig: Signature info with eidas_level field

    Returns:
        Quality string: "QES", "AdES-QC", "AdES", or "Basic"
    """
    if sig.eidas_level:
        return sig.eidas_level
    return QualificationLevel.BASIC.value


def _extract_certificate_info(
    sig: SignatureInfo, cert: x509.Certificate | None = None
) -> dict[str, Any]:
    """Extract structured certificate information.

    Args:
        sig: Signature info with certificate fields
        cert: Pre-parsed x509 certificate (avoids duplicate parsing)

    Returns:
        Dictionary with certificate details
    """
    cert_info: dict[str, Any] = {
        "subject": sig.signer_name,
        "issuer": sig.certificate_issuer,
        "serial_number": sig.certificate_serial,
        "valid_from": sig.certificate_valid_from.isoformat()
        if sig.certificate_valid_from
        else None,
        "valid_to": sig.certificate_valid_to.isoformat() if sig.certificate_valid_to else None,
        "algorithm": "unknown",
        "key_size": 0,
    }

    # Parse cert from bytes if not provided
    if cert is None and sig.certificate_bytes:
        try:
            cert = x509.load_der_x509_certificate(sig.certificate_bytes)
        except Exception as e:
            logger.debug("Failed to extract certificate algorithm info: %s", e)

    # Extract algorithm details from certificate
    if cert is not None:
        try:
            pub_key = cert.public_key()

            if isinstance(pub_key, rsa.RSAPublicKey):
                cert_info["algorithm"] = "RSA"
                cert_info["key_size"] = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                cert_info["algorithm"] = "ECDSA"
                cert_info["key_size"] = pub_key.key_size
                cert_info["curve"] = pub_key.curve.name
            else:
                cert_info["algorithm"] = type(pub_key).__name__
        except Exception as e:
            logger.debug("Failed to extract certificate algorithm info: %s", e)

    return cert_info


def _extract_algorithm_info(
    sig: SignatureInfo, cert: x509.Certificate | None = None
) -> AlgorithmAssessment | None:
    """Extract and assess algorithm strength from certificate.

    Args:
        sig: Signature info with certificate bytes
        cert: Pre-parsed x509 certificate (avoids duplicate parsing)

    Returns:
        AlgorithmAssessment or None if extraction fails
    """
    if cert is None and sig.certificate_bytes:
        try:
            cert = x509.load_der_x509_certificate(sig.certificate_bytes)
        except Exception as e:
            logger.debug("Failed to load certificate for algorithm assessment: %s", e)

    if cert is None:
        return None

    try:
        pub_key = cert.public_key()

        # Determine signature algorithm and hash
        sig_alg = cert.signature_algorithm_oid.dotted_string
        hash_alg = _oid_to_hash_name(cert.signature_hash_algorithm)

        # Determine key type and size
        key_alg = "unknown"
        key_size = 0
        curve_name: str | None = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            key_alg = "rsa"
            key_size = pub_key.key_size
            if "pss" in sig_alg.lower() or "pss" in str(cert.signature_algorithm_oid):
                key_alg = "rsapss"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_alg = "ecdsa"
            key_size = pub_key.key_size
            curve_name = pub_key.curve.name
        else:
            key_alg = type(pub_key).__name__.lower()

        return assess_algorithm(
            hash_alg=hash_alg,
            sig_alg=key_alg,
            key_size=key_size,
            curve_name=curve_name,
            for_creation=False,
        )

    except Exception as e:
        logger.debug("Failed to assess algorithm: %s", e)
        return None


def _oid_to_hash_name(hash_algo) -> str:
    """Convert hash algorithm object to name string.

    Args:
        hash_algo: Hash algorithm from cryptography library

    Returns:
        Lowercase hash name string
    """
    if hash_algo is None:
        return "unknown"
    name = hash_algo.name.lower()
    return name.replace("-", "")


def _build_revocation_info(sig: SignatureInfo) -> dict[str, Any]:
    """Build revocation status section.

    Includes freshness check per CIR 2025/1945 (24h max).

    Args:
        sig: Signature info with revocation fields

    Returns:
        Dictionary with revocation details
    """
    revocation: dict[str, Any] = {
        "status": sig.revocation_status or "not_checked",
        "message": sig.revocation_message or "Revocation check not performed",
        "method": "unknown",
        "freshness": None,
    }

    # Extract method from message
    if sig.revocation_message:
        msg_lower = sig.revocation_message.lower()
        if "ocsp" in msg_lower:
            revocation["method"] = "OCSP"
        elif "crl" in msg_lower:
            revocation["method"] = "CRL"

    # Check freshness (CIR 2025/1945: max 24 hours)
    if sig.revocation_status in ("valid", "revoked"):
        freshness = check_revocation_freshness(
            checked_at=datetime.now(UTC),
        )
        revocation["freshness"] = {
            "is_fresh": freshness.is_fresh,
            "max_age_hours": 24,
            "message": freshness.message,
        }

    return revocation


def _build_tsp_info(sig: SignatureInfo) -> dict[str, Any]:
    """Build Trust Service Provider information.

    Args:
        sig: Signature info with eIDAS TSP fields

    Returns:
        Dictionary with TSP details
    """
    return {
        "name": sig.eidas_tsp_name,
        "country": None,  # Not available in current SignatureInfo
        "qualified": sig.eidas_tsp_name is not None,
    }


def _build_signature_report(sig: SignatureInfo) -> dict[str, Any]:
    """Build a single signature's validation report section.

    Args:
        sig: Signature info from core validator

    Returns:
        Dictionary with full signature report
    """
    # Parse certificate once, pass to both helpers
    cert = None
    if sig.certificate_bytes:
        try:
            cert = x509.load_der_x509_certificate(sig.certificate_bytes)
        except Exception as e:
            logger.debug("Failed to load certificate for signature report: %s", e)

    # Algorithm assessment
    algo_assessment = _extract_algorithm_info(sig, cert)

    # Main and sub indication
    main_indication = _determine_main_indication(sig)
    sub_indication = _determine_sub_indication(sig, algo_assessment)

    # Build issues list
    issues: list[str] = []
    recommendations: list[str] = []

    if sig.status != SignatureStatus.VALID:
        issues.append(sig.status_message)

    if sig.revocation_status == "revoked":
        issues.append(f"Certificate revoked: {sig.revocation_message}")
    elif sig.revocation_status == "error":
        issues.append(f"Revocation check error: {sig.revocation_message}")
    elif sig.revocation_status == "unknown":
        issues.append("Revocation status unknown - no OCSP/CRL endpoints")
        recommendations.append("Configure certificate with OCSP/CRL distribution points")
    elif sig.revocation_status is None:
        recommendations.append("Enable revocation checking for production use")

    if sig.chain_validation_result and not sig.chain_validation_result.is_valid:
        for err in sig.chain_validation_result.errors:
            issues.append(f"Chain: {err}")

    if algo_assessment:
        issues.extend(algo_assessment.issues)
        recommendations.extend(algo_assessment.recommendations)

    # PAdES level recommendations
    pades_level = PAdESLevel.UNKNOWN.value
    if sig.ltv_info:
        pades_level = sig.ltv_info.pades_level.value
        if sig.ltv_info.pades_level == PAdESLevel.B_B:
            recommendations.append("Add timestamp for PAdES B-T long-term validity")
        elif sig.ltv_info.pades_level == PAdESLevel.B_T:
            recommendations.append("Add DSS with OCSP/CRL for PAdES B-LT long-term validation")
        elif sig.ltv_info.pades_level == PAdESLevel.B_LT:
            recommendations.append("Add archive timestamp for PAdES B-LTA maximum preservation")

    # eIDAS qualification recommendations
    sig_quality = _determine_signature_quality(sig)
    if sig_quality == QualificationLevel.BASIC.value:
        recommendations.append("Use a Qualified Certificate from an EU TSP for eIDAS compliance")

    # Algorithm assessment section
    algo_section: dict[str, Any] | None = None
    if algo_assessment:
        algo_section = {
            "hash_algorithm": algo_assessment.hash_algorithm,
            "hash_strength": algo_assessment.hash_strength.value,
            "signature_algorithm": algo_assessment.signature_algorithm,
            "key_size": algo_assessment.key_size,
            "key_strength": algo_assessment.key_strength.value,
            "overall_strength": algo_assessment.overall_strength.value,
        }

    return {
        "field_name": sig.field_name,
        "main_indication": main_indication.value,
        "sub_indication": sub_indication.value if sub_indication else None,
        "signature_quality": sig_quality,
        "signer_information": {
            "name": sig.signer_name,
            "email": sig.signer_email,
        },
        "signature_attributes": {
            "signing_time": sig.signing_time.isoformat() if sig.signing_time else None,
            "pades_level": pades_level,
            "covers_whole_document": sig.covers_whole_document,
            "has_timestamp": sig.is_timestamp_valid,
        },
        "certificate_info": _extract_certificate_info(sig, cert),
        "revocation_status": _build_revocation_info(sig),
        "algorithm_assessment": algo_section,
        "trust_service_provider": _build_tsp_info(sig),
        "issues": issues,
        "recommendations": recommendations,
    }


# --- Public API ---


def generate_eidas_report(
    validation_result: ValidationResult,
    pdf_path: Path | str,
) -> dict[str, Any]:
    """Generate a structured eIDAS validation report.

    Produces a JSON-serializable report inspired by ETSI TS 119 102-2
    containing MainIndication, SubIndication, algorithm assessment,
    revocation freshness, and eIDAS qualification level for each signature.

    Args:
        validation_result: Result from PDFValidator.validate()
        pdf_path: Path to the validated PDF

    Returns:
        Dictionary with full eIDAS validation report
    """
    pdf_path = Path(pdf_path)
    now = datetime.now(UTC)

    # Build per-signature reports
    signature_reports = [_build_signature_report(sig) for sig in validation_result.signatures]

    # Determine overall document indication
    if not validation_result.is_signed:
        overall_indication = ValidationStatus.INDETERMINATE.value
        overall_sub = SubIndication.SIGNED_DATA_NOT_FOUND.value
    elif validation_result.all_valid:
        # Check if any signature has revocation issues
        has_revocation_issue = any(
            sig.revocation_status == "revoked" for sig in validation_result.signatures
        )
        if has_revocation_issue:
            overall_indication = ValidationStatus.TOTAL_FAILED.value
            overall_sub = SubIndication.REVOKED.value
        else:
            overall_indication = ValidationStatus.TOTAL_PASSED.value
            overall_sub = None
    else:
        overall_indication = ValidationStatus.TOTAL_FAILED.value
        # Use the sub-indication from the first failing signature
        overall_sub = None
        for report in signature_reports:
            if report["main_indication"] != ValidationStatus.TOTAL_PASSED.value:
                overall_sub = report["sub_indication"]
                break

    # Determine highest eIDAS level
    quality_hierarchy = {"QES": 3, "AdES-QC": 2, "AdES": 1, "Basic": 0}
    highest_quality = "Basic"
    for report in signature_reports:
        quality = report.get("signature_quality", "Basic")
        if quality_hierarchy.get(quality, 0) > quality_hierarchy.get(highest_quality, 0):
            highest_quality = quality

    # Collect all issues and recommendations
    all_issues: list[str] = []
    all_recommendations: list[str] = []
    if validation_result.error:
        all_issues.append(validation_result.error)
    for report in signature_reports:
        all_issues.extend(report.get("issues", []))
        all_recommendations.extend(report.get("recommendations", []))

    # Deduplicate recommendations
    seen: set[str] = set()
    unique_recommendations: list[str] = []
    for rec in all_recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)

    return {
        "report_version": "1.0",
        "standard": "ETSI TS 119 102-2 V1.4.1",
        "validation_time": now.isoformat(),
        "document": {
            "filename": pdf_path.name,
            "path": str(pdf_path),
            "is_signed": validation_result.is_signed,
            "signature_count": validation_result.signature_count,
        },
        "overall": {
            "main_indication": overall_indication,
            "sub_indication": overall_sub,
            "eidas_level": highest_quality,
        },
        "signatures": signature_reports,
        "issues": all_issues,
        "recommendations": unique_recommendations,
    }


def generate_eidas_report_json(
    validation_result: ValidationResult,
    pdf_path: Path | str,
    indent: int = 2,
) -> str:
    """Generate eIDAS validation report as formatted JSON string.

    Args:
        validation_result: Result from PDFValidator.validate()
        pdf_path: Path to the validated PDF
        indent: JSON indentation level (default: 2)

    Returns:
        Formatted JSON string of the eIDAS report
    """
    report = generate_eidas_report(validation_result, pdf_path)
    return json.dumps(report, indent=indent, ensure_ascii=False, default=str)
