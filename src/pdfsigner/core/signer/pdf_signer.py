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
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
from pdfsigner.core.pdf_analyzer.position_finder import PositionFinder, PositionPreference
from pdfsigner.core.signer.lta_handler import LTAHandler
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

    def _mm_to_points(self, mm: float) -> float:
        """Converts millimeters to PDF points."""
        return mm * 72 / 25.4

    def _parse_page_range(self, page_str: str, total_pages: int) -> list[int]:
        """
        Parses a page range string into a list of page indices.

        Supports formats:
        - "1,3,4" -> pages 1, 3, 4
        - "1-3" -> pages 1, 2, 3
        - "1-3,5,7-9" -> pages 1, 2, 3, 5, 7, 8, 9

        Args:
            page_str: Page range string (1-based)
            total_pages: Total number of pages

        Returns:
            List of page indices (0-based), sorted and deduplicated
        """
        pages = set()

        for part in page_str.replace(" ", "").split(","):
            if not part:
                continue

            if "-" in part:
                # Range like "1-3"
                try:
                    start, end = part.split("-", 1)
                    start_num = int(start)
                    end_num = int(end)
                    for p in range(start_num, end_num + 1):
                        if 1 <= p <= total_pages:
                            pages.add(p - 1)  # Convert to 0-based
                except ValueError:
                    continue
            else:
                # Single page like "3"
                try:
                    p = int(part)
                    if 1 <= p <= total_pages:
                        pages.add(p - 1)  # Convert to 0-based
                except ValueError:
                    continue

        return sorted(pages)

    def _get_pages_to_sign(
        self,
        total_pages: int,
        page_setting: int | str,
    ) -> list[int]:
        """
        Determines which pages should have visible signature stamps.

        Args:
            total_pages: Total number of pages in the PDF
            page_setting: "last", "first", "all", page number, or range "1,3,4" / "1-3"

        Returns:
            List of page indices (0-based)
        """
        if page_setting == "all":
            return list(range(total_pages))
        elif page_setting == "last":
            return [total_pages - 1]
        elif page_setting == "first":
            return [0]
        elif isinstance(page_setting, int):
            return [min(page_setting, total_pages - 1)]
        elif isinstance(page_setting, str):
            # Try to parse as custom range "1,3,4" or "1-3"
            parsed = self._parse_page_range(page_setting, total_pages)
            if parsed:
                return parsed
            # Fallback to last page
            return [total_pages - 1]
        else:
            return [total_pages - 1]

    def _create_signature_field_specs(
        self,
        pdf_path: Path,
        appearance: SignatureAppearance,
    ) -> list[SigFieldSpec]:
        """
        Creates visible signature field specifications.

        For "all" pages, creates a stamp on every page.
        The first field is the actual signature field,
        others are visual stamps referencing it.

        Args:
            pdf_path: Path to the PDF
            appearance: Signature appearance settings

        Returns:
            List of SigFieldSpec (empty if invisible signature)
        """
        if not appearance.visible:
            return []

        field_specs = []

        with ContentAnalyzer(pdf_path) as analyzer:
            total_pages = analyzer.page_count
            pages_to_sign = self._get_pages_to_sign(total_pages, appearance.page)

            finder = PositionFinder(analyzer)
            sig_width = self._mm_to_points(appearance.width_mm)
            sig_height = self._mm_to_points(appearance.height_mm)

            for idx, page_num in enumerate(pages_to_sign):
                # Find optimal position for this page
                position = finder.find_position(
                    page_num,
                    sig_width,
                    sig_height,
                    appearance.position_preference,
                )

                box = (
                    position.x,
                    position.y,
                    position.x + position.width,
                    position.y + position.height,
                )

                # First field is the main signature, others are visual copies
                field_name = "Signature1" if idx == 0 else f"SignatureStamp{idx}"

                field_specs.append(
                    SigFieldSpec(
                        sig_field_name=field_name,
                        on_page=page_num,
                        box=box,
                    )
                )

        return field_specs

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
                field_specs = self._create_signature_field_specs(input_path, appearance)
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
