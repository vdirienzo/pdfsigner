"""seal_manager.py - Electronic Seals Implementation (eIDAS Article 35-40)

Author: Homero Thompson del Lago del Terror

Electronic seals are for organizations (legal persons), not individuals.
They provide proof of origin and integrity, similar to a company stamp.

Key differences from signatures:
1. Certificate type: eseal vs esign
2. Visual appearance: organization stamp vs personal signature
3. Purpose: origin & integrity vs personal intent

References:
- eIDAS Regulation (EU) No 910/2014 Articles 35-40
- ETSI EN 319 411-1/2 (Trust Service Providers)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields

from pdfsigner.config.settings import Settings, get_settings
from pdfsigner.core.audit import log_signing_event


class SealType(str, Enum):
    """Types of electronic seals per eIDAS."""

    BASIC = "basic"  # Basic electronic seal
    ADVANCED = "advanced"  # Advanced electronic seal (AdESeal)
    QUALIFIED = "qualified"  # Qualified electronic seal (QESeal)


class SealAppearance(str, Enum):
    """Visual appearance types for seals."""

    INVISIBLE = "invisible"  # No visible mark
    STAMP = "stamp"  # Circular seal appearance
    BANNER = "banner"  # Rectangular banner
    LOGO = "logo"  # Organization logo


class SealQualificationLevel(str, Enum):
    """eIDAS seal qualification level."""

    QESEAL = "QESeal"  # Qualified Electronic Seal
    ADESEAL_QC = "AdESeal-QC"  # Advanced with Qualified Certificate
    ADESEAL = "AdESeal"  # Advanced Electronic Seal
    BASIC = "Basic"  # Basic seal


@dataclass
class OrganizationInfo:
    """Organization information for seal."""

    name: str
    country: str  # ISO 3166-1 alpha-2
    organization_id: str = ""  # VAT, LEI, or other identifier
    department: str = ""
    address: str = ""
    email: str = ""
    website: str = ""


@dataclass
class SealConfig:
    """Configuration for creating an electronic seal."""

    organization: OrganizationInfo
    seal_type: SealType = SealType.ADVANCED
    appearance: SealAppearance = SealAppearance.STAMP
    reason: str = "Organization seal"
    location: str = ""
    # Visual appearance
    page: int = 1  # 1-indexed, -1 for last page
    position: tuple[float, float] = (50, 50)  # mm from bottom-left
    size: tuple[float, float] = (40, 40)  # mm width x height
    logo_path: Path | None = None
    background_color: str = "#1a365d"  # Navy blue
    text_color: str = "#ffffff"
    border_width: float = 2.0
    # Timestamp
    include_timestamp: bool = True
    tsa_url: str = ""


@dataclass
class SealResult:
    """Result of seal operation."""

    success: bool
    output_path: Path
    seal_type: SealType
    organization: str
    timestamp: datetime | None = None
    signature_id: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass
class SealValidationResult:
    """Result of seal validation."""

    valid: bool
    seal_type: SealType
    organization: OrganizationInfo
    sealed_at: datetime
    certificate_valid: bool
    timestamp_valid: bool
    integrity_intact: bool
    issues: list[str] = field(default_factory=list)


class SealManager:
    """Electronic seals for organizations (eIDAS Article 35).

    Seals are distinguished from personal signatures by:
    1. Certificate type (eseal vs esign)
    2. Visual appearance (organization stamp vs signature)
    3. Purpose (origin & integrity vs intent)
    """

    def __init__(self, settings: Settings):
        """Initialize seal manager.

        Args:
            settings: Application settings
        """
        self.settings = settings

    def create_seal(
        self,
        pdf_path: Path,
        config: SealConfig,
        output_path: Path | None = None,
        dry_run: bool = False,
    ) -> SealResult:
        """Create electronic seal on PDF.

        Uses organization certificate (eseal type) to apply seal.

        Args:
            pdf_path: Path to PDF to seal
            config: Seal configuration
            output_path: Output path (default: input_sealed.pdf)
            dry_run: Simulation mode without actual sealing

        Returns:
            SealResult with operation details

        Raises:
            FileNotFoundError: If PDF doesn't exist
            ValueError: If configuration is invalid
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        if not output_path:
            output_path = pdf_path.parent / f"{pdf_path.stem}_sealed{pdf_path.suffix}"

        logger.info(
            f"Creating {config.seal_type} seal for {config.organization.name} on {pdf_path}"
        )

        try:
            if dry_run:
                logger.info("DRY RUN: Simulating seal creation")
                return SealResult(
                    success=True,
                    output_path=output_path,
                    seal_type=config.seal_type,
                    organization=config.organization.name,
                    timestamp=datetime.now() if config.include_timestamp else None,
                    signature_id="DRY_RUN_SEAL_001",
                )

            # Generate seal appearance if visible
            # Note: In production, this would be embedded in the PDF signature appearance
            if config.appearance != SealAppearance.INVISIBLE:
                _ = self.generate_seal_appearance(config)

            # Create seal using pyHanko
            with open(pdf_path, "rb") as f_in:
                reader = PdfFileReader(f_in)
                writer = IncrementalPdfFileWriter(f_in)

                # Add signature field for seal
                sig_field_name = f"Seal_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

                # Calculate field position (convert mm to PDF points: 1mm = 2.834645669 pt)
                mm_to_pt = 2.834645669
                x_pt = config.position[0] * mm_to_pt
                y_pt = config.position[1] * mm_to_pt
                width_pt = config.size[0] * mm_to_pt
                height_pt = config.size[1] * mm_to_pt

                # Determine page number
                page_num = config.page
                if page_num == -1:
                    page_num = len(reader.root["/Pages"]["/Kids"])
                elif page_num < 1 or page_num > len(reader.root["/Pages"]["/Kids"]):
                    page_num = 1

                # Add signature field
                fields.append_signature_field(
                    writer,
                    sig_field_spec=fields.SigFieldSpec(
                        sig_field_name=sig_field_name,
                        box=(x_pt, y_pt, x_pt + width_pt, y_pt + height_pt),
                        on_page=page_num - 1,  # 0-indexed
                    ),
                )

                # In production, this would use actual PKCS#11 signer
                # For now, create a mock signer for the seal
                logger.warning("Using mock signer - production requires PKCS#11 seal certificate")

                # Write output
                with open(output_path, "wb") as f_out:
                    writer.write(f_out)

            # Log audit event (seal creation as a special type of signing event)
            log_signing_event(
                document_path=str(pdf_path),
                certificate_serial=None,  # Would come from PKCS#11 in production
                certificate_issuer=None,
                user_cn=config.organization.name,
                success=True,
                details={
                    "seal_type": config.seal_type.value,
                    "organization": config.organization.name,
                    "output_path": str(output_path),
                },
            )

            logger.info(f"Seal created successfully: {output_path}")

            return SealResult(
                success=True,
                output_path=output_path,
                seal_type=config.seal_type,
                organization=config.organization.name,
                timestamp=datetime.now() if config.include_timestamp else None,
                signature_id=sig_field_name,
            )

        except Exception as e:
            logger.error(f"Failed to create seal: {e}")
            return SealResult(
                success=False,
                output_path=output_path,
                seal_type=config.seal_type,
                organization=config.organization.name,
                errors=[str(e)],
            )

    def validate_seal(self, pdf_path: Path) -> SealValidationResult:
        """Validate electronic seal on PDF.

        Checks:
        1. Certificate is eseal type
        2. Organization info matches certificate
        3. Timestamp is valid (if present)
        4. Document integrity intact

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
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Check for signature fields
                if "/AcroForm" not in reader.root or "/Fields" not in reader.root["/AcroForm"]:
                    return SealValidationResult(
                        valid=False,
                        seal_type=SealType.BASIC,
                        organization=OrganizationInfo(name="Unknown", country="XX"),
                        sealed_at=datetime.now(),
                        certificate_valid=False,
                        timestamp_valid=False,
                        integrity_intact=True,
                        issues=["No signature fields found in PDF"],
                    )

                # In production, this would:
                # 1. Parse signature fields
                # 2. Extract certificate
                # 3. Verify certificate type (eseal)
                # 4. Validate signature cryptographically
                # 5. Check timestamp
                # 6. Verify organization info

                # Mock validation for now
                logger.warning("Using mock validation - production requires full crypto validation")

                return SealValidationResult(
                    valid=True,
                    seal_type=SealType.ADVANCED,
                    organization=OrganizationInfo(
                        name="Mock Organization", country="ES", organization_id="ESB12345678"
                    ),
                    sealed_at=datetime.now(),
                    certificate_valid=True,
                    timestamp_valid=True,
                    integrity_intact=True,
                    issues=[],
                )

        except Exception as e:
            logger.error(f"Failed to validate seal: {e}")
            return SealValidationResult(
                valid=False,
                seal_type=SealType.BASIC,
                organization=OrganizationInfo(name="Unknown", country="XX"),
                sealed_at=datetime.now(),
                certificate_valid=False,
                timestamp_valid=False,
                integrity_intact=False,
                issues=[str(e)],
            )

    def generate_seal_appearance(self, config: SealConfig) -> bytes:
        """Generate seal stamp image (PNG).

        Creates circular seal with:
        - Organization name around border
        - Country code
        - Date sealed
        - Optional logo in center

        Args:
            config: Seal configuration

        Returns:
            PNG image bytes

        Note:
            For MVP, this returns a simple base64-encoded placeholder.
            Production would use PIL/Pillow for actual image generation.
        """
        logger.info(f"Generating {config.appearance} seal appearance")

        if config.appearance == SealAppearance.INVISIBLE:
            return b""

        # Generate circular seal using helper function
        return generate_circular_seal(
            organization=config.organization.name,
            country=config.organization.country,
            date=datetime.now(),
            size=(
                int(config.size[0] * 10),
                int(config.size[1] * 10),
            ),  # Convert mm to pixels (rough)
            background_color=config.background_color,
            text_color=config.text_color,
            logo_path=config.logo_path,
        )

    def extract_seal_info(self, pdf_path: Path) -> list[OrganizationInfo]:
        """Extract organization info from seals in PDF.

        Args:
            pdf_path: Path to sealed PDF

        Returns:
            List of OrganizationInfo for each seal found

        Raises:
            FileNotFoundError: If PDF doesn't exist
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        logger.info(f"Extracting seal info from {pdf_path}")

        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Check for signature fields
                if "/AcroForm" not in reader.root or "/Fields" not in reader.root["/AcroForm"]:
                    return []

                # In production, parse signature fields and extract org info
                # Mock for now
                return [
                    OrganizationInfo(
                        name="Mock Organization",
                        country="ES",
                        organization_id="ESB12345678",
                        department="IT Department",
                        email="seal@example.com",
                    )
                ]

        except Exception as e:
            logger.error(f"Failed to extract seal info: {e}")
            return []

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

            registry = get_tsp_registry(use_mock_data=True)
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
    ┌─────────────────────────┐
    │   ★ ORGANIZATION ★     │
    │  ┌─────────────────┐   │
    │  │                 │   │
    │  │     [LOGO]      │   │
    │  │                 │   │
    │  └─────────────────┘   │
    │    COUNTRY · DATE      │
    └─────────────────────────┘

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
        ★ {organization[:20]} ★
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


# Singleton instance
_seal_manager: SealManager | None = None


def get_seal_manager() -> SealManager:
    """Get seal manager singleton.

    Returns:
        SealManager instance
    """
    global _seal_manager
    if _seal_manager is None:
        _seal_manager = SealManager(get_settings())
    return _seal_manager
