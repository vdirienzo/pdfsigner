"""
pdf_validator.py - PDF digital signature validator

Author: Homero Thompson del Lago del Terror

Verifies existing signatures in PDF documents and extracts
information about signers.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from loguru import logger
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints

from pdfsigner.config.settings import get_settings
from pdfsigner.core.certificate import (
    CertificateChainValidator,
    TrustStore,
)
from pdfsigner.core.certificate.revocation_checker import (
    RevocationChecker,
    RevocationStatus,
)
from pdfsigner.core.validator.signature_validation import (
    check_eidas_qualification,
    create_error_info,
    create_hybrid_pdf_info,
    detect_pades_level,
    extract_cn,
    extract_email,
    extract_page_number,
)

# Re-export types for backward compatibility
from pdfsigner.core.validator.validator_types import (  # noqa: F401
    LTVInfo,
    PAdESLevel,
    SignatureInfo,
    SignatureStatus,
    ValidationResult,
)

# Argentine compliance validator (optional import)
try:
    from pdfsigner.core.argentina import (
        ArgentineCertificateValidator,
        ArgentineValidationResult,
        get_argentine_validator,
    )

    ARGENTINE_VALIDATOR_AVAILABLE = True
except ImportError:
    ARGENTINE_VALIDATOR_AVAILABLE = False
    ArgentineCertificateValidator = None  # type: ignore
    ArgentineValidationResult = None  # type: ignore


class PDFValidator:
    """
    PDF digital signature validator.

    Verifies integrity and authenticity of existing
    signatures in a PDF document.
    """

    def __init__(self):
        """Initialize validator."""
        self.trust_store = TrustStore()
        self.chain_validator = CertificateChainValidator(self.trust_store)
        self._argentine_validator: ArgentineCertificateValidator | None = None

    def _check_revocation_status(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate | None,
    ) -> tuple[str | None, str | None]:
        """Check certificate revocation status if enabled.

        Returns:
            Tuple of (status_string, message) or (None, None) if disabled
        """
        settings = get_settings()
        if not settings.revocation_check_enabled:
            return None, None

        try:
            checker = RevocationChecker(
                prefer_ocsp=settings.revocation_prefer_ocsp,
                ocsp_timeout=settings.revocation_check_timeout,
                crl_timeout=settings.revocation_check_timeout,
                ocsp_cache_ttl=settings.revocation_cache_ttl,
            )
            result = checker.check_revocation(cert, issuer_cert)

            status_map = {
                RevocationStatus.GOOD: "valid",
                RevocationStatus.REVOKED: "revoked",
                RevocationStatus.UNKNOWN: "unknown",
                RevocationStatus.ERROR: "error",
            }

            if result.status == RevocationStatus.REVOKED:
                msg = f"REVOKED on {result.revocation_time}"
                if result.revocation_reason:
                    msg += f" ({result.revocation_reason})"
            elif result.status == RevocationStatus.ERROR:
                msg = result.error_message or "Check failed"
            elif result.status == RevocationStatus.UNKNOWN:
                msg = "No OCSP/CRL endpoints"
            else:
                msg = f"Valid ({result.method})"

            return status_map.get(result.status, "unknown"), msg

        except Exception as e:
            logger.warning(f"Revocation check failed: {e}")
            return "error", str(e)

    def check_argentine_compliance(
        self,
        cert_der: bytes,
        enabled: bool = True,
    ) -> ArgentineValidationResult | None:
        """Check certificate compliance with Argentine Ley 25.506.

        Args:
            cert_der: Certificate in DER format
            enabled: Whether to perform the check (from settings)

        Returns:
            ArgentineValidationResult if enabled and available, None otherwise
        """
        if not enabled or not ARGENTINE_VALIDATOR_AVAILABLE:
            return None

        try:
            if self._argentine_validator is None:
                self._argentine_validator = get_argentine_validator()
            return self._argentine_validator.validate(cert_der)
        except Exception as e:
            logger.warning(f"Argentine compliance check failed: {e}")
            return None

    def validate(self, pdf_path: Path | str) -> ValidationResult:
        """Validate all signatures in a PDF.

        Args:
            pdf_path: Path to PDF file

        Returns:
            ValidationResult with information about all signatures
        """
        pdf_path = Path(pdf_path)
        signatures: list[SignatureInfo] = []

        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f, strict=False)
                sig_fields = self._get_signature_fields(reader)

                if not sig_fields:
                    return ValidationResult(
                        file_path=pdf_path,
                        is_signed=False,
                        signature_count=0,
                        all_valid=True,
                        signatures=[],
                    )

                all_valid = True
                for field_name in sig_fields:
                    sig_info = self._validate_signature(reader, field_name, pdf_path)
                    signatures.append(sig_info)
                    if sig_info.status != SignatureStatus.VALID:
                        all_valid = False

                logger.info(
                    f"Validation completed: {pdf_path.name} - "
                    f"{len(signatures)} signature(s), valid: {all_valid}"
                )

                return ValidationResult(
                    file_path=pdf_path,
                    is_signed=True,
                    signature_count=len(signatures),
                    all_valid=all_valid,
                    signatures=signatures,
                )

        except Exception as e:
            logger.error(f"Error validating {pdf_path.name}: {e}")
            return ValidationResult(
                file_path=pdf_path,
                is_signed=False,
                signature_count=0,
                all_valid=False,
                signatures=[],
                error=str(e),
            )

    def _get_signature_fields(self, reader: PdfFileReader) -> list[str]:
        """Get signature field names from PDF."""
        sig_fields = []
        try:
            if reader.embedded_signatures:
                for sig in reader.embedded_signatures:
                    sig_fields.append(sig.field_name)
        except Exception as e:
            logger.warning(f"Error getting signature fields: {e}")
        return sig_fields

    def _validate_signature(
        self, reader: PdfFileReader, field_name: str, pdf_path: Path
    ) -> SignatureInfo:
        """Validate a specific signature."""
        try:
            sig = None
            for s in reader.embedded_signatures:
                if s.field_name == field_name:
                    sig = s
                    break

            if sig is None:
                return create_error_info(field_name, "Signature not found")

            status = validate_pdf_signature(
                embedded_sig=sig,
                key_usage_settings=KeyUsageConstraints(
                    key_usage={"digital_signature", "non_repudiation"},
                ),
            )

            cert = sig.signer_cert
            signer_name = extract_cn(cert.subject.human_friendly)
            signer_email = extract_email(cert)
            issuer = extract_cn(cert.issuer.human_friendly)
            cert_bytes = cert.dump()

            # Validate certificate chain
            chain_result = None
            try:
                crypto_cert = x509.load_der_x509_certificate(cert_bytes)
                chain_result = self.chain_validator.validate_chain(crypto_cert)
                logger.debug(
                    f"Chain validation for {field_name}: {chain_result.status.value}, "
                    f"chain length: {len(chain_result.chain)}"
                )
            except Exception as chain_err:
                logger.warning(
                    f"Could not validate certificate chain for {field_name}: {chain_err}"
                )

            # Check revocation status
            revocation_status, revocation_message = None, None
            if chain_result and chain_result.chain:
                issuer_cert = chain_result.chain[1] if len(chain_result.chain) > 1 else None
                revocation_status, revocation_message = self._check_revocation_status(
                    chain_result.chain[0], issuer_cert
                )

            # eIDAS qualification check (optional)
            eidas_level, eidas_tsp_name = None, None
            settings = get_settings()
            if settings.eidas_enabled:
                eidas_level, eidas_tsp_name = check_eidas_qualification(cert_bytes)

            # Check Argentine compliance (optional)
            argentine_result = None
            if hasattr(settings, "argentine_compliance_enabled"):
                argentine_result = self.check_argentine_compliance(
                    cert_bytes, enabled=settings.argentine_compliance_enabled
                )

            # Determine status
            if status.valid:
                sig_status = SignatureStatus.VALID
                status_msg = "Valid signature"
            elif status.intact:
                sig_status = SignatureStatus.INDETERMINATE
                status_msg = "Intact signature but couldn't verify chain"
            else:
                sig_status = SignatureStatus.INVALID
                status_msg = "Invalid signature or modified document"

            page_number = extract_page_number(reader, sig)

            has_timestamp = (
                status.timestamp_validity is not None and status.timestamp_validity.valid
            )
            ltv_info = detect_pades_level(pdf_path, reader, has_timestamp)

            return SignatureInfo(
                signer_name=signer_name,
                signer_email=signer_email,
                signing_time=status.timestamp_validity.timestamp
                if status.timestamp_validity
                else None,
                is_timestamp_valid=status.timestamp_validity is not None
                and status.timestamp_validity.valid,
                certificate_issuer=issuer,
                certificate_serial=format(cert.serial_number, "x"),
                certificate_valid_from=cert.not_valid_before,
                certificate_valid_to=cert.not_valid_after,
                status=sig_status,
                status_message=status_msg,
                field_name=field_name,
                covers_whole_document=status.coverage.value >= 2,
                is_modification_allowed=status.modification_level is not None,
                page_number=page_number,
                certificate_bytes=cert_bytes,
                chain_validation_result=chain_result,
                revocation_status=revocation_status,
                revocation_message=revocation_message,
                ltv_info=ltv_info,
                argentine_compliance_result=argentine_result,
                eidas_level=eidas_level,
                eidas_tsp_name=eidas_tsp_name,
            )

        except Exception as e:
            error_str = str(e)
            logger.warning(f"Error validating signature {field_name}: {error_str}")

            if "hybrid-reference" in error_str.lower():
                return create_hybrid_pdf_info(field_name, sig)

            return create_error_info(field_name, error_str)

    # Thin wrappers for backward compatibility with tests
    def _extract_cn(self, subject: str) -> str:
        """Extract Common Name (CN) from subject."""
        return extract_cn(subject)

    def _extract_email(self, cert) -> str | None:
        """Extract email from certificate if exists."""
        return extract_email(cert)

    def _create_error_info(self, field_name: str, error: str) -> SignatureInfo:
        """Create SignatureInfo for errors."""
        return create_error_info(field_name, error)

    def _create_hybrid_pdf_info(self, field_name: str, sig) -> SignatureInfo:
        """Create SignatureInfo for hybrid-reference PDFs."""
        return create_hybrid_pdf_info(field_name, sig)

    def get_signature_count(self, pdf_path: Path | str) -> int:
        """Quickly count signatures in a PDF.

        Args:
            pdf_path: Path to PDF

        Returns:
            Number of signatures
        """
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f, strict=False)
                return len(list(reader.embedded_signatures))
        except Exception:
            return 0

    def is_signed(self, pdf_path: Path | str) -> bool:
        """Quickly check if a PDF is signed.

        Args:
            pdf_path: Path to PDF

        Returns:
            True if it has at least one signature
        """
        return self.get_signature_count(pdf_path) > 0
