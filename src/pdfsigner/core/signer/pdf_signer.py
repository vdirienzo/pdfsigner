"""
pdf_signer.py - PDF signer with PAdES-LTV

Author: Homero Thompson del Lago del Terror

Implements PAdES-LTV digital signature using pyHanko
with USB token support via PKCS#11/NSS.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter, append_signature_field

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.signer.signature_field import create_signature_field_specs
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.exceptions import PDFCorruptedError, PDFProtectedError


@dataclass
class SignatureAppearance:
    """Visible signature appearance configuration."""

    visible: bool = False
    page: int | str = "last"  # Page number or "last", "first", "all"
    width_mm: float = 50
    height_mm: float = 20
    position_preference: PositionPreference = PositionPreference.AUTO
    image_path: Path | None = None
    show_date: bool = True
    show_name: bool = True
    qr_enabled: bool = False
    qr_position: str = "left"


@dataclass
class SigningResult:
    """Result of a signing operation."""

    success: bool
    input_path: Path
    output_path: Path | None
    error: str | None = None
    signed_at: datetime | None = None


class PDFSigner:
    """
    PDF signer with PAdES-LTV.

    Uses pyHanko to create valid digital signatures
    according to the PAdES-LTV standard.
    """

    def __init__(
        self,
        nss_handler: NSSHandler,
        lta_handler: LTAHandler | None = None,
    ):
        """
        Initializes the signer.

        Args:
            nss_handler: Authenticated NSS handler
            lta_handler: LTA handler for timestamp (optional)
        """
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        self._signer: signers.Signer | None = None

    def _create_signer(self, cert_id: bytes | None = None) -> signers.Signer:
        """Creates the pyHanko signer with the token certificate."""
        # Import here to avoid linter removing unused import
        from pyhanko.sign.pkcs11 import PKCS11Signer

        # Use pyHanko's PKCS11Signer with our authenticated session
        # This properly handles the PKCS#11 protocol
        signer = PKCS11Signer(
            pkcs11_session=self.nss_handler._session,
            cert_id=cert_id,
        )

        return signer

    def _validate_pdf(self, pdf_path: Path) -> None:
        """Validates that the PDF can be signed."""
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f)

                # Verify it's not corrupted
                if reader.root is None:
                    raise PDFCorruptedError(pdf_path.name)

                # Verify permissions
                if reader.security_handler is not None:
                    # PDF is encrypted
                    perms = reader.security_handler.permissions
                    if perms is not None and not perms.can_modify:
                        raise PDFProtectedError(pdf_path.name)

        except PDFCorruptedError:
            raise
        except PDFProtectedError:
            raise
        except Exception as e:
            raise PDFCorruptedError(pdf_path.name) from e

    def _get_output_path(self, input_path: Path) -> Path:
        """Generates the output path for the signed PDF."""
        settings = get_settings()
        suffix = settings.output_suffix
        return input_path.with_stem(f"{input_path.stem}{suffix}")

    def _build_stamp_style(
        self,
        appearance: "SignatureAppearance",
        input_path: Path | None = None,
        signer_name: str | None = None,
    ):
        """
        Builds the visual stamp style for visible signatures.

        Args:
            appearance: Signature appearance configuration
            input_path: Path to PDF (needed for QR hash calculation)
            signer_name: Name of signer from certificate (for QR)

        Returns:
            TextStampStyle if visible signature, None otherwise
        """
        if not appearance.visible:
            return None

        # Import here to avoid circular imports and allow lazy loading
        from pyhanko import stamp
        from pyhanko.pdf_utils import images

        # If QR is enabled, generate composed stamp image
        if appearance.qr_enabled and input_path:
            try:
                from pdfsigner.core.stamp.qr_generator import QRData, calculate_document_hash
                from pdfsigner.core.stamp.stamp_composer import compose_stamp_with_qr

                # Calculate document hash
                doc_hash = calculate_document_hash(input_path)

                # Get signer name (fallback to generic)
                name = signer_name or "Digital Signature"

                # Create QR data
                qr_data = QRData(
                    document_hash=doc_hash,
                    signer_name=name,
                )

                # Compose stamp with QR
                stamp_image_path = compose_stamp_with_qr(
                    signer_name=name,
                    timestamp=datetime.now(),
                    qr_data=qr_data,
                    qr_position=appearance.qr_position,
                )

                logger.debug(f"Generated QR stamp: {stamp_image_path}")

                # Use composed image as background with minimal text
                return stamp.TextStampStyle(
                    stamp_text="",
                    background=images.PdfImage(str(stamp_image_path)),
                )

            except Exception as e:
                logger.warning(f"Could not generate QR stamp: {e}, falling back to text")

        # Standard text-only stamp
        text_parts = []

        if appearance.show_name:
            text_parts.append("Signed by: %(signer)s")

        if appearance.show_date:
            text_parts.append("Date: %(ts)s")

        # If no parts configured, use default
        if not text_parts:
            text_parts = ["Digitally signed"]

        stamp_text = "\n".join(text_parts)

        # Build stamp style
        style_kwargs = {"stamp_text": stamp_text}

        # Add background image if configured
        if appearance.image_path and appearance.image_path.exists():
            try:
                style_kwargs["background"] = images.PdfImage(str(appearance.image_path))
                logger.debug(f"Using stamp background: {appearance.image_path}")
            except Exception as e:
                logger.warning(f"Could not load stamp image: {e}")

        return stamp.TextStampStyle(**style_kwargs)

    def sign_pdf(
        self,
        input_path: Path,
        output_path: Path | None = None,
        appearance: SignatureAppearance | None = None,
        cert_id: bytes | None = None,
    ) -> SigningResult:
        """
        Signs a PDF.

        Args:
            input_path: Path to the PDF to sign
            output_path: Output path (None = automatic)
            appearance: Appearance configuration
            cert_id: Certificate ID to use (None = default)

        Returns:
            Signing operation result
        """
        input_path = Path(input_path)
        output_path = output_path or self._get_output_path(input_path)
        appearance = appearance or SignatureAppearance()

        logger.info(f"Signing: {input_path.name}")

        try:
            # Validate PDF
            self._validate_pdf(input_path)

            # Count existing signatures to generate unique field names
            validator = PDFValidator()
            existing_sig_count = validator.get_signature_count(input_path)

            # Create signer
            signer = self._create_signer(cert_id)

            # Get timestamper if available
            timestamper = None
            if self.lta_handler and self.lta_handler.tsa_config.url:
                timestamper = self.lta_handler.get_timestamper()

            # Open PDF
            with open(input_path, "rb") as f:
                writer = IncrementalPdfFileWriter(f)

                # Add signature field(s) if visible
                field_specs = create_signature_field_specs(
                    input_path,
                    appearance.visible,
                    appearance.page,
                    appearance.width_mm,
                    appearance.height_mm,
                    appearance.position_preference,
                    existing_signature_count=existing_sig_count,
                )
                for field_spec in field_specs:
                    append_signature_field(writer, field_spec)

                # Main signature field name (first one, or generate one for invisible)
                if field_specs:
                    sig_field_name = field_specs[0].sig_field_name
                else:
                    # pyHanko requires a field name even for invisible signatures
                    # Use unique name based on existing signatures
                    sig_field_name = f"Signature{existing_sig_count + 1}"

                # Extract signer name from certificate for QR
                # Note: pyHanko uses asn1crypto, not cryptography.x509
                signer_name = None
                if signer.signing_cert:
                    # asn1crypto API: subject.native returns dict with 'common_name'
                    subject_dict = signer.signing_cert.subject.native
                    signer_name = subject_dict.get("common_name")

                # Build stamp style for visible signatures
                stamp_style = self._build_stamp_style(
                    appearance,
                    input_path=input_path,
                    signer_name=signer_name,
                )

                # Create signature metadata
                sig_metadata = signers.PdfSignatureMetadata(
                    field_name=sig_field_name,
                    md_algorithm="sha256",
                    subfilter=SigSeedSubFilter.PADES,
                )

                # Sign using PdfSigner to support stamp_style
                pdf_signer = signers.PdfSigner(
                    sig_metadata,
                    signer=signer,
                    stamp_style=stamp_style,
                    timestamper=timestamper,
                )

                with open(output_path, "wb") as out:
                    pdf_signer.sign_pdf(
                        writer,
                        output=out,
                    )

            logger.info(f"PDF signed successfully: {output_path.name}")

            return SigningResult(
                success=True,
                input_path=input_path,
                output_path=output_path,
                signed_at=datetime.now(),
            )

        except (PDFCorruptedError, PDFProtectedError) as e:
            logger.error(f"PDF error: {e}")
            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )
        except Exception as e:
            import traceback

            logger.error(f"Error signing PDF: {e}\n{traceback.format_exc()}")
            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )
