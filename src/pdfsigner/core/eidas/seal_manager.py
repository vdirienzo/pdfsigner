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

from datetime import UTC, datetime
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields

from pdfsigner.config.settings import Settings, get_settings
from pdfsigner.core.audit import log_signing_event
from pdfsigner.core.eidas.seal_types import (  # noqa: F401
    OrganizationInfo,
    SealAppearance,
    SealConfig,
    SealQualificationLevel,
    SealResult,
    SealType,
    SealValidationResult,
)

# Re-export types for backward compatibility
from pdfsigner.core.eidas.seal_validator import (  # noqa: F401
    SealValidator,
    generate_circular_seal,
)


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
        self._pkcs11_signer = None
        self._validator = None  # Lazy-initialized SealValidator

    def _get_validator(self) -> SealValidator:
        """Get or create SealValidator instance (lazy initialization)."""
        if self._validator is None:
            self._validator = SealValidator()
        return self._validator

    def set_pkcs11_signer(self, signer) -> None:
        """Set PKCS#11 signer for real seal creation.

        Args:
            signer: pyHanko PKCS11Signer instance configured with seal certificate
        """
        self._pkcs11_signer = signer
        logger.info("PKCS#11 signer configured for seal creation")

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
                    timestamp=datetime.now(UTC) if config.include_timestamp else None,
                    signature_id="DRY_RUN_SEAL_001",
                )

            # Generate seal appearance if visible
            # Note: In production, this would be embedded in the PDF signature appearance
            if config.appearance != SealAppearance.INVISIBLE:
                _ = self.generate_seal_appearance(config)

            # Create seal using pyHanko
            seal_signed = False
            with open(pdf_path, "rb") as f_in:
                reader = PdfFileReader(f_in)
                writer = IncrementalPdfFileWriter(f_in)

                # Add signature field for seal
                sig_field_name = f"Seal_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"

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

                # Try to sign with PKCS#11 seal certificate
                try:
                    from pyhanko.sign import signers as seal_signers
                    from pyhanko.sign.fields import SigSeedSubFilter
                    from pyhanko.sign.timestamps import HTTPTimeStamper

                    if self._pkcs11_signer is not None:
                        # Build timestamper if configured
                        timestamper = None
                        if config.include_timestamp and config.tsa_url:
                            timestamper = HTTPTimeStamper(url=config.tsa_url, timeout=30)

                        sig_metadata = seal_signers.PdfSignatureMetadata(
                            field_name=sig_field_name,
                            md_algorithm="sha256",
                            subfilter=SigSeedSubFilter.PADES,
                            reason=config.reason or "Organization seal",
                            location=config.location or None,
                        )

                        pdf_signer_obj = seal_signers.PdfSigner(
                            sig_metadata,
                            signer=self._pkcs11_signer,
                            timestamper=timestamper,
                        )

                        with open(output_path, "wb") as f_out:
                            pdf_signer_obj.sign_pdf(writer, output=f_out)

                        seal_signed = True
                        logger.info("Seal created with PKCS#11 certificate")
                    else:
                        seal_signed = False
                        logger.warning(
                            "No PKCS#11 seal certificate available. "
                            "Writing unsigned seal field "
                            "(use set_pkcs11_signer() to enable real seals)"
                        )
                        with open(output_path, "wb") as f_out:
                            writer.write(f_out)
                except Exception as sign_err:
                    logger.error("PKCS#11 seal signing failed: %s", sign_err)
                    seal_signed = False
                    with open(output_path, "wb") as f_out:
                        writer.write(f_out)

            # Log audit event
            log_signing_event(
                document_path=str(pdf_path),
                certificate_serial=None,
                certificate_issuer=None,
                user_cn=config.organization.name,
                success=seal_signed,
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
                timestamp=datetime.now(UTC) if config.include_timestamp else None,
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
        """Validate electronic seal on a PDF document.

        Delegates to SealValidator for cryptographic verification.

        Args:
            pdf_path: Path to sealed PDF

        Returns:
            SealValidationResult with validation details

        Raises:
            FileNotFoundError: If PDF doesn't exist
        """
        return self._get_validator().validate_seal(pdf_path)

    def _extract_org_from_cert(self, cert) -> OrganizationInfo:
        """Extract organization info from pyHanko certificate object.

        Delegates to SealValidator.

        Args:
            cert: asn1crypto Certificate object (from pyHanko signer_cert)

        Returns:
            OrganizationInfo with extracted data
        """
        return self._get_validator()._extract_org_from_cert(cert)

    def generate_seal_appearance(self, config: SealConfig) -> bytes:
        """Generate seal stamp image (PNG).

        Args:
            config: Seal configuration

        Returns:
            PNG image bytes
        """
        logger.info(f"Generating {config.appearance} seal appearance")

        if config.appearance == SealAppearance.INVISIBLE:
            return b""

        # Generate circular seal using helper function
        return generate_circular_seal(
            organization=config.organization.name,
            country=config.organization.country,
            date=datetime.now(UTC),
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
            NotImplementedError: Always -- use validate_seal() instead
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        raise NotImplementedError(
            "extract_seal_info requires pyHanko signature extraction. "
            "Use validate_seal() for seal verification."
        )

    def is_seal_certificate(self, certificate_bytes: bytes) -> bool:
        """Check if certificate is a seal certificate (QcType = eseal).

        Delegates to SealValidator.

        Args:
            certificate_bytes: DER-encoded X.509 certificate

        Returns:
            True if certificate has QcType = eseal
        """
        return self._get_validator().is_seal_certificate(certificate_bytes)

    def determine_seal_qualification(self, certificate_bytes: bytes) -> SealQualificationLevel:
        """Determine seal qualification level from certificate.

        Delegates to SealValidator.

        Args:
            certificate_bytes: DER-encoded X.509 certificate

        Returns:
            SealQualificationLevel
        """
        return self._get_validator().determine_seal_qualification(certificate_bytes)


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
