"""
validation_report_builders.py - Per-signature report builder functions

Contains all helper functions that build individual sections of the
eIDAS validation report (certificate info, algorithm assessment,
revocation status, etc.) and the main per-signature report builder.

Extracted from validation_report.py to keep each module under 400 lines.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from loguru import logger

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
)
from pdfsigner.core.validator.validation_report_types import SubIndication


def _determine_main_indication(sig: SignatureInfo) -> ValidationStatus:
    """Determine MainIndication per ETSI EN 319 102-1."""
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
    """Map eIDAS level to signature quality ("QES", "AdES-QC", "AdES", or "Basic")."""
    if sig.eidas_level:
        return sig.eidas_level
    return QualificationLevel.BASIC.value


def _extract_certificate_info(
    sig: SignatureInfo, cert: x509.Certificate | None = None
) -> dict[str, Any]:
    """Extract structured certificate information."""
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


def _oid_to_hash_name(hash_algo: Any) -> str:
    """Convert hash algorithm object to lowercase name string."""
    if hash_algo is None:
        return "unknown"
    name = hash_algo.name.lower()
    return name.replace("-", "")


def _extract_algorithm_info(
    sig: SignatureInfo, cert: x509.Certificate | None = None
) -> AlgorithmAssessment | None:
    """Extract and assess algorithm strength from certificate."""
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


def _build_revocation_info(sig: SignatureInfo) -> dict[str, Any]:
    """Build revocation status section with freshness check (CIR 2025/1945, 24h max)."""
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
    """Build Trust Service Provider information."""
    return {
        "name": sig.eidas_tsp_name,
        "country": None,  # Not available in current SignatureInfo
        "qualified": sig.eidas_tsp_name is not None,
    }


def _build_algo_section(algo_assessment: AlgorithmAssessment | None) -> dict[str, Any] | None:
    """Build algorithm assessment section dictionary."""
    if not algo_assessment:
        return None
    return {
        "hash_algorithm": algo_assessment.hash_algorithm,
        "hash_strength": algo_assessment.hash_strength.value,
        "signature_algorithm": algo_assessment.signature_algorithm,
        "key_size": algo_assessment.key_size,
        "key_strength": algo_assessment.key_strength.value,
        "overall_strength": algo_assessment.overall_strength.value,
    }


def _collect_issues_and_recommendations(
    sig: SignatureInfo,
    algo_assessment: AlgorithmAssessment | None,
) -> tuple[list[str], list[str], str]:
    """Collect issues, recommendations, and PAdES level from a signature."""
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
        pades_recommendations = {
            PAdESLevel.B_B: "Add timestamp for PAdES B-T long-term validity",
            PAdESLevel.B_T: "Add DSS with OCSP/CRL for PAdES B-LT long-term validation",
            PAdESLevel.B_LT: "Add archive timestamp for PAdES B-LTA maximum preservation",
        }
        rec = pades_recommendations.get(sig.ltv_info.pades_level)
        if rec:
            recommendations.append(rec)

    # eIDAS qualification recommendations
    sig_quality = _determine_signature_quality(sig)
    if sig_quality == QualificationLevel.BASIC.value:
        recommendations.append("Use a Qualified Certificate from an EU TSP for eIDAS compliance")

    return issues, recommendations, pades_level


def build_signature_report(sig: SignatureInfo) -> dict[str, Any]:
    """Build a single signature's validation report section."""
    # Parse certificate once, pass to all helpers
    cert = None
    if sig.certificate_bytes:
        try:
            cert = x509.load_der_x509_certificate(sig.certificate_bytes)
        except Exception as e:
            logger.debug("Failed to load certificate for signature report: %s", e)

    algo_assessment = _extract_algorithm_info(sig, cert)
    main_indication = _determine_main_indication(sig)
    sub_indication = _determine_sub_indication(sig, algo_assessment)
    issues, recommendations, pades_level = _collect_issues_and_recommendations(sig, algo_assessment)

    return {
        "field_name": sig.field_name,
        "main_indication": main_indication.value,
        "sub_indication": sub_indication.value if sub_indication else None,
        "signature_quality": _determine_signature_quality(sig),
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
        "algorithm_assessment": _build_algo_section(algo_assessment),
        "trust_service_provider": _build_tsp_info(sig),
        "issues": issues,
        "recommendations": recommendations,
    }
