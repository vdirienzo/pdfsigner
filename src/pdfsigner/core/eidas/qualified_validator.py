"""
qualified_validator.py - Qualified Electronic Signature (QES) Validation with Production Integration

Author: Homero Thompson del Lago del Terror

Validates Qualified Electronic Signatures (QES) per eIDAS Articles 25-28 using
real EU Trusted Lists, signature extraction, and revocation checking.

Key features:
- QES validation based on EU Regulation 910/2014
- Qualified Certificate detection (QcStatements extension)
- QSCD (Qualified Signature Creation Device) verification
- TSP qualification checking via EU Trusted Lists
- OCSP/CRL revocation checking
- PDF signature extraction using pyHanko
- eIDAS signature level detection (Basic, AdES, QES)

QcStatements OIDs (RFC 3739):
- 0.4.0.1862.1.1: QcCompliance - Certificate is Qualified
- 0.4.0.1862.1.3: QcRetentionPeriod - Retention period
- 0.4.0.1862.1.4: QcSSCD - Qualified Signature Creation Device
- 0.4.0.1862.1.5: QcPDS - PKI Disclosure Statements
- 0.4.0.1862.1.6: QcType - Certificate type (esign, eseal, web)
- 0.4.0.1862.1.7: QcCClegislation - EU legislation
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from pdfsigner.config.settings import get_settings
from pdfsigner.core.certificate.revocation_checker import RevocationChecker, RevocationStatus
from pdfsigner.core.eidas.qc_statements_parser import parse_qc_statements
from pdfsigner.core.eidas.tsp_registry import EUTSPRegistry, QualificationStatus

logger = logging.getLogger(__name__)


# QcStatements OIDs per ETSI EN 319 412-5
QC_OIDS = {
    "0.4.0.1862.1.1": "QcCompliance",  # Certificate is Qualified
    "0.4.0.1862.1.3": "QcRetentionPeriod",  # Retention period
    "0.4.0.1862.1.4": "QcSSCD",  # Qualified Signature Creation Device
    "0.4.0.1862.1.5": "QcPDS",  # PKI Disclosure Statements
    "0.4.0.1862.1.6": "QcType",  # Certificate type
    "0.4.0.1862.1.7": "QcCClegislation",  # EU legislation
}

# Certificate types per QcType (0.4.0.1862.1.6)
QC_TYPES = {
    "0.4.0.1862.1.6.1": "esign",  # For electronic signatures
    "0.4.0.1862.1.6.2": "eseal",  # For electronic seals
    "0.4.0.1862.1.6.3": "web",  # For website authentication
}


@dataclass
class SignatureValidation:
    """Validation result for a single signature."""

    field_name: str = ""
    signer_name: str = ""
    signing_time: datetime | None = None
    certificate_qualified: bool = False
    qscd_used: bool = False
    tsp_granted: bool = False
    not_revoked: bool = False
    signature_valid: bool = False
    timestamp_present: bool = False
    tsp_name: str | None = None
    tsp_country: str | None = None
    qualification_level: str = "Basic"  # "QES", "AdES-QC", "AdES", "Basic"
    issues: list[str] = field(default_factory=list)


@dataclass
class QESValidationResult:
    """Result of Qualified Electronic Signature validation."""

    overall_status: str  # "TOTAL-PASSED", "TOTAL-FAILED", "INDETERMINATE"
    qualification_level: str  # "QES", "AdES", "Basic"
    signature_validations: list[SignatureValidation] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    validation_time: datetime = field(default_factory=datetime.now)

    # Legacy compatibility properties
    @property
    def is_qualified(self) -> bool:
        """Check if all signatures are QES qualified."""
        return self.qualification_level == "QES" and self.overall_status == "TOTAL-PASSED"

    @property
    def certificate_qualified(self) -> bool:
        """Check if at least one certificate is qualified."""
        return any(v.certificate_qualified for v in self.signature_validations)

    @property
    def device_qualified(self) -> bool:
        """Check if at least one signature used QSCD."""
        return any(v.qscd_used for v in self.signature_validations)

    @property
    def tsp_qualified(self) -> bool:
        """Check if at least one TSP is qualified."""
        return any(v.tsp_granted for v in self.signature_validations)

    @property
    def timestamp_qualified(self) -> bool:
        """Check if at least one signature has timestamp."""
        return any(v.timestamp_present for v in self.signature_validations)


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

        Raises:
            FileNotFoundError: If PDF file doesn't exist
        """
        result = QESValidationResult(
            overall_status="INDETERMINATE",
            qualification_level="Basic",
        )

        try:
            # 1. Extract signatures from PDF
            from pdfsigner.core.eidas.pdf_signature_extractor import get_signature_extractor

            extractor = get_signature_extractor()
            signatures = extractor.extract_signatures(pdf_path)

            if not signatures:
                result.overall_status = "INDETERMINATE"
                result.issues.append("No signatures found in PDF")
                return result

            # 2. Validate each signature
            for sig in signatures:
                sig_validation = self._validate_signature(sig)
                result.signature_validations.append(sig_validation)

            # 3. Determine overall qualification level
            if not result.signature_validations:
                result.qualification_level = "Basic"
                result.overall_status = "INDETERMINATE"
            else:
                # All signatures must be QES for overall QES
                all_qes = all(
                    v.qualification_level == "QES" and v.signature_valid
                    for v in result.signature_validations
                )

                if all_qes:
                    result.qualification_level = "QES"
                    result.overall_status = "TOTAL-PASSED"
                else:
                    # Check for AdES-QC
                    any_ades_qc = any(
                        v.qualification_level in ("QES", "AdES-QC")
                        for v in result.signature_validations
                    )
                    if any_ades_qc:
                        result.qualification_level = "AdES"
                    else:
                        result.qualification_level = "Basic"

                    result.overall_status = "TOTAL-FAILED"

            # 4. Generate recommendations
            self._generate_recommendations(result)

        except FileNotFoundError as e:
            result.issues.append(f"File not found: {e}")
            result.overall_status = "INDETERMINATE"
        except Exception as e:
            logger.error(f"QES validation failed: {e}", exc_info=True)
            result.issues.append(f"Validation error: {str(e)}")
            result.overall_status = "INDETERMINATE"

        return result

    def _validate_signature(self, sig) -> SignatureValidation:
        """Validate a single extracted signature.

        Args:
            sig: ExtractedSignature object

        Returns:
            SignatureValidation with detailed validation results
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
            validation.certificate_qualified = self.check_qualified_certificate(sig.certificate_der)

            # 2. Check QSCD usage
            validation.qscd_used = self.check_qscd(sig.certificate_der)

            # 3. Check TSP qualification
            tsp = self.registry.find_tsp_by_certificate(sig.certificate_der)
            if tsp:
                validation.tsp_name = tsp.name
                validation.tsp_country = tsp.country
                validation.tsp_granted = tsp.status == QualificationStatus.QUALIFIED
            else:
                # Fallback: check by issuer DN
                issuer_dn = sig.issuer_dn
                tsp_status = self.registry.check_certificate_issuer(issuer_dn)
                validation.tsp_granted = tsp_status == QualificationStatus.QUALIFIED

            # 4. Check revocation (optional but recommended)
            if validation.certificate_qualified:
                validation.not_revoked = self._check_revocation(sig.certificate)
            else:
                validation.not_revoked = True  # Skip revocation check for non-qualified certs

            # 5. Determine qualification level
            if (
                validation.certificate_qualified
                and validation.qscd_used
                and validation.tsp_granted
                and validation.not_revoked
                and validation.signature_valid
            ):
                validation.qualification_level = "QES"
            elif validation.certificate_qualified and validation.tsp_granted:
                validation.qualification_level = "AdES-QC"
            elif validation.certificate_qualified or validation.signature_valid:
                validation.qualification_level = "AdES"
            else:
                validation.qualification_level = "Basic"

            # 6. Collect issues
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

        except Exception as e:
            logger.warning(f"Signature validation failed for {sig.field_name}: {e}")
            validation.issues.append(f"Validation error: {str(e)}")

        return validation

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
            result = checker.check_revocation(cert, issuer_cert)

            if result.status == RevocationStatus.GOOD:
                logger.debug("Certificate revocation check: GOOD (%s)", result.method)
                return True
            elif result.status == RevocationStatus.REVOKED:
                logger.warning("Certificate REVOKED: %s", result.revocation_reason or "no reason")
                return False
            else:
                # UNKNOWN or ERROR - respect fail_open setting
                if hasattr(settings, "ltv_fail_open") and settings.ltv_fail_open:
                    logger.debug("Revocation check indeterminate, fail-open: True")
                    return True
                logger.warning("Revocation check indeterminate, fail-open: False")
                return False
        except Exception as e:
            logger.debug("Revocation check failed: %s", e)
            return True  # Fail open on exception

    def _generate_recommendations(self, result: QESValidationResult) -> None:
        """Generate recommendations based on validation results.

        Args:
            result: QESValidationResult to update with recommendations
        """
        if result.qualification_level != "QES":
            result.recommendations.append(
                "To achieve QES qualification, ensure: "
                "1) Qualified Certificate, "
                "2) QSCD device, "
                "3) Qualified TSP, "
                "4) Valid signature"
            )

        # Check for missing timestamps
        missing_ts = [v for v in result.signature_validations if not v.timestamp_present]
        if missing_ts:
            result.recommendations.append(
                f"{len(missing_ts)} signature(s) lack timestamps for long-term validity (PAdES B-T)"
            )

        # Check for non-qualified TSPs
        non_qualified_tsps = [
            v for v in result.signature_validations if not v.tsp_granted and v.tsp_name
        ]
        if non_qualified_tsps:
            result.recommendations.append(
                "Use certificates from EU qualified trust service providers for QES"
            )

    def validate_certificate(self, cert_bytes: bytes) -> QESValidationResult:
        """Validate certificate qualification status.

        Args:
            cert_bytes: DER-encoded X.509 certificate

        Returns:
            QESValidationResult with certificate qualification details
        """
        result = QESValidationResult(
            overall_status="TOTAL-PASSED",
            qualification_level="Basic",
        )

        try:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

            # Create a validation entry
            validation = SignatureValidation(
                field_name="certificate-only",
                signer_name=self._extract_common_name(cert),
            )

            # Check if certificate is qualified
            validation.certificate_qualified = self.check_qualified_certificate(cert_bytes)

            # Check if QSCD was used
            validation.qscd_used = self.check_qscd(cert_bytes)

            # Check TSP qualification
            issuer_dn = cert.issuer.rfc4514_string()
            tsp_status = self.registry.check_certificate_issuer(issuer_dn)
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
            if not validation.certificate_qualified:
                result.recommendations.append(
                    "Certificate is not a Qualified Certificate (missing QcCompliance)"
                )

            if not validation.qscd_used:
                result.recommendations.append(
                    "Certificate does not indicate QSCD usage (missing QcSSCD)"
                )

            if not validation.tsp_granted:
                result.recommendations.append(
                    f"Certificate issuer '{issuer_dn}' is not a qualified TSP"
                )

        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            result.issues.append(f"Certificate validation error: {str(e)}")
            result.overall_status = "INDETERMINATE"

        return result

    def _extract_common_name(self, cert: x509.Certificate) -> str:
        """Extract common name from certificate subject.

        Args:
            cert: X.509 certificate

        Returns:
            Common name string
        """
        try:
            cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attr:
                return cn_attr[0].value
        except Exception as e:
            logger.debug("Failed to extract CN: %s", e)

        return "Unknown"

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
        """Extract QcStatements from certificate using real ASN.1 parsing.

        Args:
            certificate_bytes: DER-encoded X.509 certificate

        Returns:
            Dictionary mapping QC statement names to their values
        """
        try:
            result = parse_qc_statements(certificate_bytes)
            return result.raw_statements
        except Exception as e:
            logger.warning("Failed to parse QcStatements: %s", e)
            return {}

    def detect_signature_level(self, pdf_path: str) -> str:
        """Detect eIDAS signature level: Basic, AdES, QES.

        Args:
            pdf_path: Path to signed PDF file

        Returns:
            Signature level string: "QES", "AdES", or "Basic"
        """
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
