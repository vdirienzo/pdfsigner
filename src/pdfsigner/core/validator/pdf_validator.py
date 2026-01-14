"""
pdf_validator.py - PDF digital signature validator

Author: Homero Thompson del Lago del Terror

Verifies existing signatures in PDF documents and extracts
information about signers.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints


class SignatureStatus(Enum):
    """Signature validation status."""

    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    INDETERMINATE = "indeterminate"


@dataclass
class SignatureInfo:
    """Signature information in PDF."""

    signer_name: str
    signer_email: str | None
    signing_time: datetime | None
    is_timestamp_valid: bool
    certificate_issuer: str
    certificate_serial: str
    certificate_valid_from: datetime | None
    certificate_valid_to: datetime | None
    status: SignatureStatus
    status_message: str
    field_name: str
    covers_whole_document: bool
    is_modification_allowed: bool
    page_number: int | None  # Page where visible signature is located (if applicable)


@dataclass
class ValidationResult:
    """PDF validation result."""

    file_path: Path
    is_signed: bool
    signature_count: int
    all_valid: bool
    signatures: list[SignatureInfo]
    error: str | None = None


class PDFValidator:
    """
    PDF digital signature validator.

    Verifies integrity and authenticity of existing
    signatures in a PDF document.
    """

    def __init__(self):
        """Initialize validator."""
        pass

    def validate(self, pdf_path: Path | str) -> ValidationResult:
        """
        Validate all signatures in a PDF.

        Args:
            pdf_path: Path to PDF file

        Returns:
            ValidationResult with information about all signatures
        """
        pdf_path = Path(pdf_path)
        signatures: list[SignatureInfo] = []

        try:
            with open(pdf_path, "rb") as f:
                # strict=False allows hybrid-reference PDFs (mixed xref tables/streams)
                reader = PdfFileReader(f, strict=False)

                # Get signature fields
                sig_fields = self._get_signature_fields(reader)

                if not sig_fields:
                    return ValidationResult(
                        file_path=pdf_path,
                        is_signed=False,
                        signature_count=0,
                        all_valid=True,
                        signatures=[],
                    )

                # Validate each signature
                all_valid = True
                for field_name in sig_fields:
                    sig_info = self._validate_signature(reader, field_name)
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

    def _validate_signature(self, reader: PdfFileReader, field_name: str) -> SignatureInfo:
        """Validate a specific signature."""
        try:
            # Find signature
            sig = None
            for s in reader.embedded_signatures:
                if s.field_name == field_name:
                    sig = s
                    break

            if sig is None:
                return self._create_error_info(field_name, "Signature not found")

            # Validate signature
            # Note: strict=False in PdfFileReader allows hybrid-reference PDFs
            status = validate_pdf_signature(
                embedded_sig=sig,
                key_usage_settings=KeyUsageConstraints(
                    key_usage={"digital_signature", "non_repudiation"},
                ),
            )

            # Extract certificate information
            cert = sig.signer_cert
            signer_name = self._extract_cn(cert.subject.human_friendly)
            signer_email = self._extract_email(cert)
            issuer = self._extract_cn(cert.issuer.human_friendly)

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
                covers_whole_document=status.coverage.value >= 2,  # ENTIRE_REVISION or more
                is_modification_allowed=status.modification_level is not None,
                page_number=None,  # TODO: extract from annotation
            )

        except Exception as e:
            error_str = str(e)
            logger.warning(f"Error validating signature {field_name}: {error_str}")

            # Check for hybrid-reference file error and provide clear message
            if "hybrid-reference" in error_str.lower():
                return self._create_hybrid_pdf_info(field_name, sig)

            return self._create_error_info(field_name, error_str)

    def _create_hybrid_pdf_info(self, field_name: str, sig) -> SignatureInfo:
        """Create SignatureInfo for hybrid-reference PDFs.

        Hybrid PDFs mix classic xref tables with xref streams. The signature
        is present but cannot be fully verified due to this format limitation.
        We extract what information we can from the certificate.
        """
        signer_name = "Unknown"
        signer_email = None
        issuer = "Unknown"
        serial = ""
        valid_from = None
        valid_to = None

        # Try to extract certificate info even if validation failed
        if sig and sig.signer_cert:
            try:
                cert = sig.signer_cert
                signer_name = self._extract_cn(cert.subject.human_friendly)
                signer_email = self._extract_email(cert)
                issuer = self._extract_cn(cert.issuer.human_friendly)
                serial = format(cert.serial_number, "x")
                valid_from = cert.not_valid_before
                valid_to = cert.not_valid_after
            except Exception:
                pass

        return SignatureInfo(
            signer_name=signer_name,
            signer_email=signer_email,
            signing_time=None,
            is_timestamp_valid=False,
            certificate_issuer=issuer,
            certificate_serial=serial,
            certificate_valid_from=valid_from,
            certificate_valid_to=valid_to,
            status=SignatureStatus.INDETERMINATE,
            status_message="Cannot fully verify (hybrid PDF format)",
            field_name=field_name,
            covers_whole_document=False,
            is_modification_allowed=False,
            page_number=None,
        )

    def _create_error_info(self, field_name: str, error: str) -> SignatureInfo:
        """Create SignatureInfo for errors."""
        return SignatureInfo(
            signer_name="Unknown",
            signer_email=None,
            signing_time=None,
            is_timestamp_valid=False,
            certificate_issuer="Unknown",
            certificate_serial="",
            certificate_valid_from=None,
            certificate_valid_to=None,
            status=SignatureStatus.UNKNOWN,
            status_message=f"Error: {error}",
            field_name=field_name,
            covers_whole_document=False,
            is_modification_allowed=False,
            page_number=None,
        )

    def _extract_cn(self, subject: str) -> str:
        """Extract Common Name (CN) from subject."""
        # subject comes as "CN=Name,O=Org,..."
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                return part[3:]
        return subject

    def _extract_email(self, cert) -> str | None:
        """Extract email from certificate if exists."""
        try:
            for ext in cert.extensions:
                if ext.oid.dotted_string == "2.5.29.17":  # Subject Alt Name
                    for name in ext.value:
                        if hasattr(name, "value") and "@" in str(name.value):
                            return str(name.value)
        except Exception:
            pass
        return None

    def get_signature_count(self, pdf_path: Path | str) -> int:
        """
        Quickly count signatures in a PDF.

        Args:
            pdf_path: Path to PDF

        Returns:
            Number of signatures
        """
        try:
            with open(pdf_path, "rb") as f:
                # strict=False allows hybrid-reference PDFs (mixed xref tables/streams)
                reader = PdfFileReader(f, strict=False)
                return len(list(reader.embedded_signatures))
        except Exception:
            return 0

    def is_signed(self, pdf_path: Path | str) -> bool:
        """
        Quickly check if a PDF is signed.

        Args:
            pdf_path: Path to PDF

        Returns:
            True if it has at least one signature
        """
        return self.get_signature_count(pdf_path) > 0
