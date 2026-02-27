"""
qualified_validator.py - Qualified Electronic Signature (QES) Validation

Author: Homero Thompson del Lago del Terror

Validates Qualified Electronic Signatures (QES) per eIDAS Articles 25-28.
Delegates signature-level and certificate-level validation to qes_validation_helpers.

QcStatements OIDs (RFC 3739):
- 0.4.0.1862.1.1: QcCompliance - Certificate is Qualified
- 0.4.0.1862.1.3: QcRetentionPeriod - Retention period
- 0.4.0.1862.1.4: QcSSCD - Qualified Signature Creation Device
- 0.4.0.1862.1.5: QcPDS - PKI Disclosure Statements
- 0.4.0.1862.1.6: QcType - Certificate type (esign, eseal, web)
- 0.4.0.1862.1.7: QcCClegislation - EU legislation
"""

from pathlib import Path
from typing import Any

from cryptography import x509
from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.certificate.revocation_checker import RevocationChecker, RevocationStatus
from pdfsigner.core.eidas.qc_statements_parser import parse_qc_statements
from pdfsigner.core.eidas.qes_validation_helpers import (
    validate_certificate_qualification,
    validate_single_signature,
)

# Re-export types for backward compatibility
from pdfsigner.core.eidas.qualified_types import (  # noqa: F401
    QESValidationResult,
    SignatureValidation,
)
from pdfsigner.core.eidas.tsp_registry import EUTSPRegistry


class QualifiedSignatureValidator:
    """Validate Qualified Electronic Signatures per eIDAS Article 25-28.

    A signature is considered a Qualified Electronic Signature (QES) if:
    1. It uses a Qualified Certificate (per Article 28)
    2. Created with a Qualified Signature Creation Device (QSCD, per Article 29)
    3. Issued by a Qualified Trust Service Provider (per Article 24)
    4. Certificate is not revoked (OCSP/CRL check)
    """

    def __init__(self, registry: EUTSPRegistry):
        """Initialize validator with TSP registry.

        Args:
            registry: EU TSP registry for qualification checks
        """
        self.registry = registry

    def validate_qes(self, pdf_path: str) -> QESValidationResult:
        """Full QES validation of signed PDF using production integration.

        Args:
            pdf_path: Path to signed PDF file

        Returns:
            QESValidationResult with validation details
        """
        result = QESValidationResult(
            overall_status="INDETERMINATE",
            qualification_level="Basic",
        )

        try:
            from pdfsigner.core.eidas.pdf_signature_extractor import get_signature_extractor

            extractor = get_signature_extractor()
            signatures = extractor.extract_signatures(pdf_path)

            if not signatures:
                result.overall_status = "INDETERMINATE"
                result.issues.append("No signatures found in PDF")
                return result

            for sig in signatures:
                sig_validation = self._validate_signature(sig)
                result.signature_validations.append(sig_validation)

            self._determine_overall_level(result)
            self._generate_recommendations(result)

        except FileNotFoundError as e:
            result.issues.append(f"File not found: {e}")
            result.overall_status = "INDETERMINATE"
        except Exception as e:
            logger.error(f"QES validation failed: {e}", exc_info=True)
            result.issues.append(f"Validation error: {str(e)}")
            result.overall_status = "INDETERMINATE"

        return result

    def _determine_overall_level(self, result: QESValidationResult) -> None:
        """Determine overall qualification level from individual validations."""
        if not result.signature_validations:
            result.qualification_level = "Basic"
            result.overall_status = "INDETERMINATE"
            return

        all_qes = all(
            v.qualification_level == "QES" and v.signature_valid
            for v in result.signature_validations
        )

        if all_qes:
            result.qualification_level = "QES"
            result.overall_status = "TOTAL-PASSED"
        else:
            any_ades_qc = any(
                v.qualification_level in ("QES", "AdES-QC") for v in result.signature_validations
            )
            result.qualification_level = "AdES" if any_ades_qc else "Basic"
            result.overall_status = "TOTAL-FAILED"

    def _validate_signature(self, sig) -> SignatureValidation:
        """Validate a single extracted signature. Delegates to qes_validation_helpers."""
        return validate_single_signature(self, sig)

    def _check_revocation(
        self, cert: x509.Certificate, issuer_cert: x509.Certificate | None = None
    ) -> bool:
        """Check certificate revocation status using OCSP/CRL.

        Args:
            cert: X.509 certificate to check
            issuer_cert: Issuer certificate (needed for OCSP)

        Returns:
            True if certificate is not revoked, False otherwise
        """
        try:
            settings = get_settings()
            if not settings.revocation_check_enabled:
                logger.debug("Revocation check disabled in settings")
                return True

            checker = RevocationChecker(
                prefer_ocsp=settings.revocation_prefer_ocsp,
                ocsp_timeout=settings.revocation_check_timeout,
                crl_timeout=settings.revocation_check_timeout,
                ocsp_cache_ttl=settings.revocation_cache_ttl,
            )
            check_result = checker.check_revocation(cert, issuer_cert)

            if check_result.status == RevocationStatus.GOOD:
                logger.debug("Certificate revocation check: GOOD (%s)", check_result.method)
                return True
            elif check_result.status == RevocationStatus.REVOKED:
                logger.warning(
                    "Certificate REVOKED: %s", check_result.revocation_reason or "no reason"
                )
                return False
            else:
                if hasattr(settings, "ltv_fail_open") and settings.ltv_fail_open:
                    logger.debug("Revocation check indeterminate, fail-open: True")
                    return True
                logger.warning("Revocation check indeterminate, fail-open: False")
                return False
        except Exception as e:
            logger.warning("Revocation check error (fail-closed): %s", e)
            return False

    def _generate_recommendations(self, result: QESValidationResult) -> None:
        """Generate recommendations based on validation results."""
        if result.qualification_level != "QES":
            result.recommendations.append(
                "To achieve QES qualification, ensure: "
                "1) Qualified Certificate, "
                "2) QSCD device, "
                "3) Qualified TSP, "
                "4) Valid signature"
            )

        missing_ts = [v for v in result.signature_validations if not v.timestamp_present]
        if missing_ts:
            result.recommendations.append(
                f"{len(missing_ts)} signature(s) lack timestamps for long-term validity (PAdES B-T)"
            )

        non_qualified_tsps = [
            v for v in result.signature_validations if not v.tsp_granted and v.tsp_name
        ]
        if non_qualified_tsps:
            result.recommendations.append(
                "Use certificates from EU qualified trust service providers for QES"
            )

    def validate_certificate(self, cert_bytes: bytes) -> QESValidationResult:
        """Validate certificate qualification status. Delegates to qes_validation_helpers."""
        return validate_certificate_qualification(self, cert_bytes)

    def check_qscd(self, certificate_bytes: bytes) -> bool:
        """Check if certificate indicates QSCD usage via QcStatements ASN.1."""
        try:
            result = parse_qc_statements(certificate_bytes)
            return result.has_qscd
        except Exception as e:
            logger.debug("Failed to check QSCD: %s", e)
            return False

    def check_qualified_certificate(self, certificate_bytes: bytes) -> bool:
        """Check if certificate is a Qualified Certificate via QcStatements ASN.1."""
        try:
            result = parse_qc_statements(certificate_bytes)
            return result.is_qualified
        except Exception as e:
            logger.debug("Failed to check qualified certificate: %s", e)
            return False

    def get_qc_statements(self, certificate_bytes: bytes) -> dict[str, Any]:
        """Extract QcStatements from certificate using real ASN.1 parsing."""
        try:
            result = parse_qc_statements(certificate_bytes)
            return result.raw_statements
        except Exception as e:
            logger.warning("Failed to parse QcStatements: %s", e)
            return {}

    def detect_signature_level(self, pdf_path: str) -> str:
        """Detect eIDAS signature level: Basic, AdES, QES."""
        try:
            if not Path(pdf_path).exists():
                return "Basic"
            result = self.validate_qes(pdf_path)
            return result.qualification_level
        except Exception as e:
            logger.error(f"Failed to detect signature level: {e}")
            return "Basic"

    def get_qc_type(self, certificate_bytes: bytes) -> str | None:
        """Get certificate type from QcStatements ASN.1."""
        try:
            result = parse_qc_statements(certificate_bytes)
            return result.qc_type
        except Exception as e:
            logger.debug("Failed to get QC type: %s", e)
            return None
