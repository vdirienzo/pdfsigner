"""
pdf_signature_extractor.py - PDF signature extraction using pyHanko

Author: Homero Thompson del Lago del Terror

Extracts digital signatures from PDF documents using pyHanko, providing
detailed information about signature certificates, timestamps, and coverage.

This module bridges pyHanko's signature validation with eIDAS qualification checks.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature

logger = logging.getLogger(__name__)


@dataclass
class ExtractedSignature:
    """Signature extracted from PDF.

    Attributes:
        field_name: Name of the signature field
        signing_time: Self-reported signing time from signature
        signer_name: Common name from certificate
        certificate_der: DER-encoded signer certificate
        certificate: Parsed certificate object
        signature_bytes: Raw signature PKCS#7 bytes
        has_timestamp: Whether signature includes a timestamp
        timestamp_token: DER-encoded timestamp token (if present)
        coverage: Coverage of signature ("full" or "partial")
        issuer_dn: Distinguished name of certificate issuer
        subject_dn: Distinguished name of certificate subject
        certificate_chain: List of certificates in chain (DER format)
        is_valid: Whether signature is cryptographically valid
    """

    field_name: str
    signing_time: datetime | None
    signer_name: str
    certificate_der: bytes
    certificate: x509.Certificate
    signature_bytes: bytes
    has_timestamp: bool
    timestamp_token: bytes | None = None
    coverage: str = "full"
    issuer_dn: str = ""
    subject_dn: str = ""
    certificate_chain: list[bytes] | None = None
    is_valid: bool = False


class PDFSignatureExtractor:
    """Extract and analyze PDF signatures using pyHanko.

    Provides a high-level interface for extracting signature information
    from PDF documents, including certificates, timestamps, and validation status.
    """

    def __init__(self):
        """Initialize PDF signature extractor."""
        pass

    def extract_signatures(self, pdf_path: str | Path) -> list[ExtractedSignature]:
        """Extract all signatures from a PDF file.

        Args:
            pdf_path: Path to PDF file

        Returns:
            List of ExtractedSignature objects

        Raises:
            FileNotFoundError: If PDF file doesn't exist
            ValueError: If PDF cannot be parsed
        """
        pdf_path = Path(pdf_path)
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        signatures = []

        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Get all signature fields
                sig_fields = reader.embedded_signatures

                logger.info("Found %d signature(s) in PDF", len(sig_fields))

                for sig_field in sig_fields:
                    try:
                        extracted = self._extract_signature_info(sig_field)
                        if extracted:
                            signatures.append(extracted)
                    except Exception as e:
                        logger.warning(
                            "Failed to extract signature from field %s: %s",
                            sig_field.field_name,
                            e,
                        )
                        continue

        except Exception as e:
            raise ValueError(f"Failed to read PDF signatures: {e}") from e

        return signatures

    def _extract_signature_info(self, sig_field) -> ExtractedSignature | None:
        """Extract information from a signature field.

        Args:
            sig_field: pyHanko EmbeddedPdfSignature object

        Returns:
            ExtractedSignature object or None if extraction fails
        """
        try:
            # Get signer certificate
            signer_cert = sig_field.signer_cert
            cert_der = signer_cert.dump()

            # Parse certificate with cryptography
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Extract common name from certificate subject
            signer_name = self._extract_common_name(cert)

            # Get signing time (self-reported)
            signing_time = sig_field.self_reported_timestamp

            # Check for timestamp
            has_timestamp = False
            timestamp_token = None

            try:
                ts_validation = sig_field.external_timestamp_validation
                if ts_validation is not None:
                    has_timestamp = True
                    # Extract timestamp token if available
                    if hasattr(sig_field, "external_timestamp") and sig_field.external_timestamp:
                        timestamp_token = sig_field.external_timestamp.dump()
            except (AttributeError, ValueError):
                # Some signatures may not have timestamps
                pass

            # Get signature coverage
            coverage = self._determine_coverage(sig_field)

            # Get issuer and subject DNs
            issuer_dn = cert.issuer.rfc4514_string()
            subject_dn = cert.subject.rfc4514_string()

            # Get certificate chain if available
            cert_chain = None
            try:
                if hasattr(sig_field, "cert_registry") and sig_field.cert_registry:
                    cert_chain = [c.dump() for c in sig_field.cert_registry]
            except (AttributeError, ValueError):
                pass

            # Validate signature cryptographically
            is_valid = self._validate_signature_crypto(sig_field)

            return ExtractedSignature(
                field_name=sig_field.field_name,
                signing_time=signing_time,
                signer_name=signer_name,
                certificate_der=cert_der,
                certificate=cert,
                signature_bytes=sig_field.pkcs7_content,
                has_timestamp=has_timestamp,
                timestamp_token=timestamp_token,
                coverage=coverage,
                issuer_dn=issuer_dn,
                subject_dn=subject_dn,
                certificate_chain=cert_chain,
                is_valid=is_valid,
            )

        except Exception as e:
            logger.error("Failed to extract signature info: %s", e)
            return None

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
                value = cn_attr[0].value
                return value if isinstance(value, str) else value.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug("Failed to extract CN: %s", e)

        return "Unknown"

    def _determine_coverage(self, sig_field) -> str:
        """Determine signature coverage (full or partial).

        Args:
            sig_field: pyHanko EmbeddedPdfSignature object

        Returns:
            "full" if signature covers entire document, "partial" otherwise
        """
        try:
            # Check if signature covers the whole document
            coverage = sig_field.coverage
            if coverage is not None and hasattr(coverage, "covers_whole_document"):
                return "full" if coverage.covers_whole_document else "partial"
        except (AttributeError, ValueError):
            pass

        # Default to full coverage (most common case)
        return "full"

    def _validate_signature_crypto(self, sig_field) -> bool:
        """Validate signature cryptographically.

        Args:
            sig_field: pyHanko EmbeddedPdfSignature object

        Returns:
            True if signature is cryptographically valid
        """
        try:
            # Use pyHanko's validation
            validation_result = validate_pdf_signature(sig_field)

            # Check if signature is intact
            return validation_result.intact

        except Exception as e:
            logger.warning("Signature validation failed: %s", e)
            return False

    def get_signature_count(self, pdf_path: str | Path) -> int:
        """Get the number of signatures in a PDF.

        Args:
            pdf_path: Path to PDF file

        Returns:
            Number of signatures

        Raises:
            FileNotFoundError: If PDF file doesn't exist
        """
        pdf_path = Path(pdf_path)
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)
                return len(reader.embedded_signatures)
        except Exception as e:
            logger.error("Failed to count signatures: %s", e)
            return 0

    def has_signatures(self, pdf_path: str | Path) -> bool:
        """Check if PDF has any signatures.

        Args:
            pdf_path: Path to PDF file

        Returns:
            True if PDF has at least one signature
        """
        try:
            return self.get_signature_count(pdf_path) > 0
        except FileNotFoundError:
            return False


# Singleton instance
_signature_extractor: PDFSignatureExtractor | None = None


def get_signature_extractor() -> PDFSignatureExtractor:
    """Get or create singleton PDFSignatureExtractor instance.

    Returns:
        PDFSignatureExtractor singleton
    """
    global _signature_extractor
    if _signature_extractor is None:
        _signature_extractor = PDFSignatureExtractor()
    return _signature_extractor
