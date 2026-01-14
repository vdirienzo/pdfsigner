"""
pdf_signer.py - PDF signer with PAdES-LTV

Author: Homero Thompson del Lago del Terror

Implements PAdES-LTV digital signature using pyHanko
with USB token support via PKCS#11/NSS.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import append_signature_field

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.signer.signature_field import create_signature_field_specs
from pdfsigner.core.token.nss_handler import NSSHandler
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
        priv_key, cert_der = self.nss_handler.get_signing_key_and_cert(cert_id)

        # Load certificate
        cert = x509.load_der_x509_certificate(cert_der)

        # Create PKCS#11 signer
        # pyHanko expects a SimpleSigner or PKCS11Signer
        # Since we're using python-pkcs11, we create a wrapper
        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=priv_key,
            cert_registry=None,
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

            # Create signer
            signer = self._create_signer(cert_id)

            # Configure signature
            sig_kwargs = {}

            # Add timestamper if available
            if self.lta_handler and self.lta_handler.tsa_config.url:
                sig_kwargs["timestamper"] = self.lta_handler.get_timestamper()
                sig_kwargs["embed_validation_info"] = True

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
                )
                for field_spec in field_specs:
                    append_signature_field(writer, field_spec)

                # Main signature field name (first one, or None for invisible)
                sig_field_name = field_specs[0].sig_field_name if field_specs else None

                # Sign
                with open(output_path, "wb") as out:
                    signers.sign_pdf(
                        writer,
                        signers.PdfSignatureMetadata(
                            field_name=sig_field_name,
                            md_algorithm="sha256",
                            subfilter=signers.SigSeedSubFilter.PADES,
                        ),
                        signer=signer,
                        output=out,
                        **sig_kwargs,
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
            logger.error(f"Error signing PDF: {e}")
            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )
