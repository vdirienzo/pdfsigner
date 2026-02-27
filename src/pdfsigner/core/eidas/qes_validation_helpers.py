"""
qes_validation_helpers.py - Helper functions for QES validation

Extracted from qualified_validator.py to reduce file size.
Contains the core validation logic for individual signatures and certificates.

Author: Homero Thompson del Lago del Terror
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from loguru import logger

from pdfsigner.core.eidas.qualified_types import (
    QESValidationResult,
    SignatureValidation,
)
from pdfsigner.core.eidas.tsp_registry import QualificationStatus

if TYPE_CHECKING:
    from pdfsigner.core.eidas.qualified_validator import QualifiedSignatureValidator


def validate_single_signature(
    validator: QualifiedSignatureValidator,
    sig: Any,
) -> SignatureValidation:
    """Validate a single extracted signature.

    Args:
        validator: QualifiedSignatureValidator instance for registry/helper access.
        sig: ExtractedSignature object.

    Returns:
        SignatureValidation with detailed validation results.
    """
    validation = SignatureValidation(
        field_name=sig.field_name,
        signer_name=sig.signer_name,
        signing_time=sig.signing_time,
        signature_valid=sig.is_valid,
        timestamp_present=sig.has_timestamp,
    )

    try:
        # 1. Check certificate qualification
        validation.certificate_qualified = validator.check_qualified_certificate(
            sig.certificate_der
        )

        # 2. Check QSCD usage
        validation.qscd_used = validator.check_qscd(sig.certificate_der)

        # 3. Check TSP qualification
        tsp = validator.registry.find_tsp_by_certificate(sig.certificate_der)
        if tsp:
            validation.tsp_name = tsp.name
            validation.tsp_country = tsp.country
            validation.tsp_granted = tsp.status == QualificationStatus.QUALIFIED
        else:
            # Fallback: check by issuer DN
            issuer_dn = sig.issuer_dn
            tsp_status = validator.registry.check_certificate_issuer(issuer_dn)
            validation.tsp_granted = tsp_status == QualificationStatus.QUALIFIED

        # 4. Check revocation (optional but recommended)
        if validation.certificate_qualified:
            validation.not_revoked = validator._check_revocation(sig.certificate)
        else:
            validation.not_revoked = True  # Skip revocation check for non-qualified certs

        # 5. Determine qualification level
        validation.qualification_level = _determine_qualification_level(validation)

        # 6. Collect issues
        _collect_validation_issues(validation)

    except Exception as e:
        logger.warning(f"Signature validation failed for {sig.field_name}: {e}")
        validation.issues.append(f"Validation error: {str(e)}")

    return validation


def validate_certificate_qualification(
    validator: QualifiedSignatureValidator,
    cert_bytes: bytes,
) -> QESValidationResult:
    """Validate certificate qualification status.

    Args:
        validator: QualifiedSignatureValidator instance for registry/helper access.
        cert_bytes: DER-encoded X.509 certificate.

    Returns:
        QESValidationResult with certificate qualification details.
    """
    result = QESValidationResult(
        overall_status="TOTAL-PASSED",
        qualification_level="Basic",
    )

    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        # Create a validation entry
        cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        signer_name = str(cn_attr[0].value) if cn_attr else "Unknown"

        validation = SignatureValidation(
            field_name="certificate-only",
            signer_name=signer_name,
        )

        # Check if certificate is qualified
        validation.certificate_qualified = validator.check_qualified_certificate(cert_bytes)

        # Check if QSCD was used
        validation.qscd_used = validator.check_qscd(cert_bytes)

        # Check TSP qualification
        issuer_dn = cert.issuer.rfc4514_string()
        tsp_status = validator.registry.check_certificate_issuer(issuer_dn)
        validation.tsp_granted = tsp_status == QualificationStatus.QUALIFIED

        # Determine qualification level
        if validation.certificate_qualified and validation.qscd_used and validation.tsp_granted:
            result.qualification_level = "QES"
        elif validation.certificate_qualified:
            result.qualification_level = "AdES"
        else:
            result.qualification_level = "Basic"

        validation.qualification_level = result.qualification_level
        result.signature_validations.append(validation)

        # Generate recommendations
        _generate_cert_recommendations(result, validation, issuer_dn)

    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        result.issues.append(f"Certificate validation error: {str(e)}")
        result.overall_status = "INDETERMINATE"

    return result


def _determine_qualification_level(validation: SignatureValidation) -> str:
    """Determine the eIDAS qualification level from validation flags.

    Returns:
        Qualification level string: "QES", "AdES-QC", "AdES", or "Basic".
    """
    if (
        validation.certificate_qualified
        and validation.qscd_used
        and validation.tsp_granted
        and validation.not_revoked
        and validation.signature_valid
    ):
        return "QES"
    elif validation.certificate_qualified and validation.tsp_granted:
        return "AdES-QC"
    elif validation.certificate_qualified or validation.signature_valid:
        return "AdES"
    return "Basic"


def _collect_validation_issues(validation: SignatureValidation) -> None:
    """Append issue messages for any failed validation checks."""
    if not validation.signature_valid:
        validation.issues.append("Signature is cryptographically invalid")
    if not validation.certificate_qualified:
        validation.issues.append("Certificate is not a Qualified Certificate")
    if not validation.qscd_used:
        validation.issues.append("QSCD not indicated in certificate")
    if not validation.tsp_granted:
        validation.issues.append("TSP is not a qualified trust service provider")
    if not validation.not_revoked:
        validation.issues.append("Certificate may be revoked or revocation status unknown")


def _generate_cert_recommendations(
    result: QESValidationResult,
    validation: SignatureValidation,
    issuer_dn: str,
) -> None:
    """Generate recommendations for certificate-only validation."""
    if not validation.certificate_qualified:
        result.recommendations.append(
            "Certificate is not a Qualified Certificate (missing QcCompliance)"
        )
    if not validation.qscd_used:
        result.recommendations.append("Certificate does not indicate QSCD usage (missing QcSSCD)")
    if not validation.tsp_granted:
        result.recommendations.append(f"Certificate issuer '{issuer_dn}' is not a qualified TSP")
