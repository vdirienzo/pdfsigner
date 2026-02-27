"""seal_validator.py - Electronic Seal Validation (eIDAS Article 35-40)

Validation logic for electronic seals, including cryptographic verification,
QcStatements parsing, and TSP registry lookups for qualification levels.

References:
- eIDAS Regulation (EU) No 910/2014 Articles 35-40
- ETSI EN 319 412-5 (QcStatements)
- ETSI EN 319 411-1/2 (Trust Service Providers)
"""

from datetime import UTC, datetime
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.reader import PdfFileReader

from pdfsigner.core.eidas.seal_types import (
    OrganizationInfo,
    SealQualificationLevel,
    SealType,
    SealValidationResult,
)


class SealValidator:
    """Validates electronic seals on PDF documents.

    Performs cryptographic verification using pyHanko's validation engine,
    then checks if the signing certificate is a seal certificate (QcType = eseal).
    """

    def validate_seal(self, pdf_path: Path) -> SealValidationResult:
        """Validate electronic seal on a PDF document.

        Performs real cryptographic verification of the seal signature
        using pyHanko's validation engine, then checks if the signing
        certificate is a seal certificate (QcType = eseal).

        Args:
            pdf_path: Path to sealed PDF

        Returns:
            SealValidationResult with validation details

        Raises:
            FileNotFoundError: If PDF doesn't exist
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        logger.info(f"Validating seal on {pdf_path}")

        try:
            from pyhanko.sign.validation import validate_pdf_signature

            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f, strict=False)

                if not reader.embedded_signatures:
                    return SealValidationResult(
                        valid=False,
                        seal_type=SealType.BASIC,
                        organization=OrganizationInfo(name="Unknown", country=""),
                        sealed_at=datetime.now(UTC),
                        certificate_valid=False,
                        timestamp_valid=False,
                        integrity_intact=False,
                        issues=["No signatures found in PDF"],
                    )

                # Validate the last signature (most likely the seal)
                last_sig = list(reader.embedded_signatures)[-1]
                status = validate_pdf_signature(embedded_sig=last_sig)

                # Extract certificate info
                cert = last_sig.signer_cert
                cert_der = cert.dump()

                # Check if it's a seal certificate
                is_eseal = self.is_seal_certificate(cert_der)

                # Determine seal type and qualification
                seal_type = SealType.BASIC
                if is_eseal:
                    qual = self.determine_seal_qualification(cert_der)
                    if qual.value == "QESeal":
                        seal_type = SealType.QUALIFIED
                    elif qual.value in ("AdESeal-QC", "AdESeal"):
                        seal_type = SealType.ADVANCED

                # Extract organization info from certificate
                org = self._extract_org_from_cert(cert)

                # Check timestamp
                has_timestamp = (
                    status.timestamp_validity is not None and status.timestamp_validity.valid
                )

                sealed_at = (
                    status.timestamp_validity.timestamp
                    if status.timestamp_validity
                    else datetime.now(UTC)
                )

                issues = []
                if not status.valid:
                    issues.append("Seal signature is cryptographically invalid")
                if not is_eseal:
                    issues.append("Signing certificate is not an eseal type (QcType != eseal)")
                if not has_timestamp:
                    issues.append("Seal lacks qualified timestamp")

                return SealValidationResult(
                    valid=status.valid and status.intact,
                    seal_type=seal_type,
                    organization=org,
                    sealed_at=sealed_at,
                    certificate_valid=status.valid,
                    timestamp_valid=has_timestamp,
                    integrity_intact=status.intact,
                    issues=issues,
                )

        except Exception as e:
            logger.error("Seal validation failed: %s", e)
            return SealValidationResult(
                valid=False,
                seal_type=SealType.BASIC,
                organization=OrganizationInfo(name="Unknown", country=""),
                sealed_at=datetime.now(UTC),
                certificate_valid=False,
                timestamp_valid=False,
                integrity_intact=False,
                issues=[f"Validation error: {e}"],
            )

    def _extract_org_from_cert(self, cert) -> OrganizationInfo:
        """Extract organization info from pyHanko certificate object.

        Parses the certificate subject to extract organization name and
        country code using the human-friendly representation.

        Args:
            cert: asn1crypto Certificate object (from pyHanko signer_cert)

        Returns:
            OrganizationInfo with extracted data
        """
        try:
            subject = cert.subject.human_friendly
            name = "Unknown"
            country = ""

            for part in subject.split(","):
                part = part.strip()
                if part.startswith("O="):
                    name = part[2:]
                elif part.startswith("C="):
                    country = part[2:]

            return OrganizationInfo(name=name, country=country)
        except Exception:
            return OrganizationInfo(name="Unknown", country="")

    def is_seal_certificate(self, certificate_bytes: bytes) -> bool:
        """Check if certificate is a seal certificate (QcType = eseal).

        Uses real ASN.1 parsing of QcStatements extension per
        ETSI EN 319 412-5 to detect eseal type certificates
        (OID 0.4.0.1862.1.6.2).

        Args:
            certificate_bytes: DER-encoded X.509 certificate

        Returns:
            True if certificate has QcType = eseal
        """
        try:
            from pdfsigner.core.eidas.qc_statements_parser import parse_qc_statements

            result = parse_qc_statements(certificate_bytes)
            if not result.has_qc_statements:
                return False
            return result.qc_type == "eseal" or "eseal" in result.qc_types
        except Exception as e:
            logger.warning("Failed to check seal certificate: %s", e)
            return False

    def determine_seal_qualification(self, certificate_bytes: bytes) -> SealQualificationLevel:
        """Determine seal qualification level from certificate.

        Uses QcStatements parsing and TSP registry lookup to classify
        the seal per eIDAS qualification levels.

        Args:
            certificate_bytes: DER-encoded X.509 certificate

        Returns:
            SealQualificationLevel
        """
        try:
            from pdfsigner.core.eidas.qc_statements_parser import parse_qc_statements
            from pdfsigner.core.eidas.tsp_registry import QualificationStatus, get_tsp_registry

            qc = parse_qc_statements(certificate_bytes)
            if not qc.has_qc_statements or qc.qc_type != "eseal":
                return SealQualificationLevel.BASIC

            registry = get_tsp_registry(use_mock_data=False)
            from cryptography import x509 as crypto_x509
            from cryptography.hazmat.backends import default_backend

            cert = crypto_x509.load_der_x509_certificate(certificate_bytes, default_backend())
            issuer_dn = cert.issuer.rfc4514_string()
            tsp_status = registry.check_certificate_issuer(issuer_dn)
            tsp_qualified = tsp_status == QualificationStatus.QUALIFIED

            if qc.is_qualified and qc.has_qscd and tsp_qualified:
                return SealQualificationLevel.QESEAL
            elif qc.is_qualified and tsp_qualified:
                return SealQualificationLevel.ADESEAL_QC
            elif qc.is_qualified:
                return SealQualificationLevel.ADESEAL
            return SealQualificationLevel.BASIC
        except Exception as e:
            logger.warning("Failed to determine seal qualification: %s", e)
            return SealQualificationLevel.BASIC


def generate_circular_seal(
    organization: str,
    country: str,
    date: datetime,
    size: tuple[int, int] = (200, 200),
    background_color: str = "#1a365d",
    text_color: str = "#ffffff",
    logo_path: Path | None = None,
) -> bytes:
    """Generate circular seal stamp image.

    Layout:
    +-------------------------+
    |   * ORGANIZATION *      |
    |  +-----------------+    |
    |  |                 |    |
    |  |     [LOGO]      |    |
    |  |                 |    |
    |  +-----------------+    |
    |    COUNTRY . DATE       |
    +-------------------------+

    Args:
        organization: Organization name
        country: ISO 3166-1 alpha-2 country code
        date: Date of sealing
        size: Image size in pixels (width, height)
        background_color: Background color (hex)
        text_color: Text color (hex)
        logo_path: Optional path to logo image

    Returns:
        PNG image bytes

    Note:
        For MVP without PIL/Pillow dependency, returns SVG as bytes.
        Production should use PIL/Pillow for proper image generation.
    """
    width, height = size
    date_str = date.strftime("%Y-%m-%d")

    # Generate simple SVG seal (MVP version)
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
    <!-- Background circle -->
    <circle cx="{width / 2}" cy="{height / 2}" r="{min(width, height) / 2 - 5}"
            fill="{background_color}" stroke="{text_color}" stroke-width="3"/>

    <!-- Organization name (top arc) -->
    <text x="{width / 2}" y="{height / 4}"
          font-family="Arial, sans-serif" font-size="16" font-weight="bold"
          fill="{text_color}" text-anchor="middle">
        ★ {__import__("html").escape(organization[:20])} ★
    </text>

    <!-- Country and date (bottom) -->
    <text x="{width / 2}" y="{height * 3 / 4}"
          font-family="Arial, sans-serif" font-size="14"
          fill="{text_color}" text-anchor="middle">
        {country} · {date_str}
    </text>

    <!-- Center logo area or seal text -->
    <circle cx="{width / 2}" cy="{height / 2}" r="{min(width, height) / 4}"
            fill="none" stroke="{text_color}" stroke-width="1" stroke-dasharray="3,3"/>

    <text x="{width / 2}" y="{height / 2 + 5}"
          font-family="Arial, sans-serif" font-size="18" font-weight="bold"
          fill="{text_color}" text-anchor="middle">
        SEAL
    </text>
</svg>'''

    return svg.encode("utf-8")
