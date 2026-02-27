"""
pdf_signer.py - PDF signer with PAdES-LTV

Author: Homero Thompson del Lago del Terror

Implements PAdES-LTV digital signature using pyHanko
with USB token support via PKCS#11/NSS.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter, append_signature_field

from pdfsigner.config.settings import get_settings
from pdfsigner.core.audit import log_signing_event
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager
from pdfsigner.core.signer.dss_manager import DSSManager
from pdfsigner.core.signer.lta_handler import LTAHandler
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


class SigningMode(str, Enum):
    """Signing mode for PDFSigner."""

    LOCAL_PKCS11 = "local_pkcs11"  # Default: PKCS#11 hardware token
    REMOTE_CSC = "remote_csc"  # Remote QTSP via CSC API v2


class PDFSigner:
    """
    PDF signer with PAdES-LTV.

    Uses pyHanko to create valid digital signatures
    according to the PAdES-LTV standard.

    Supports two signing modes:
    - LOCAL_PKCS11: Traditional PKCS#11 hardware token (default)
    - REMOTE_CSC: Remote QTSP via CSC API v2
    """

    def __init__(
        self,
        nss_handler: NSSHandler | None = None,
        lta_handler: LTAHandler | None = None,
        signing_mode: SigningMode | None = None,
    ):
        """
        Initializes the signer.

        Args:
            nss_handler: Authenticated NSS handler (required for LOCAL_PKCS11)
            lta_handler: LTA handler for timestamp (optional)
            signing_mode: Signing mode (default: LOCAL_PKCS11)
        """
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        self.signing_mode = signing_mode or SigningMode.LOCAL_PKCS11
        self._signer: signers.Signer | None = None
        self._remote_signer = None  # Set by create_remote()
        self._dss_manager: DSSManager | None = None

    @classmethod
    def create_remote(
        cls,
        service_url: str,
        credential_id: str,
        access_token: str,
        lta_handler: LTAHandler | None = None,
        **kwargs,
    ) -> "PDFSigner":
        """Create a PDFSigner configured for remote signing via CSC API.

        Args:
            service_url: QTSP CSC API base URL
            credential_id: Remote credential ID
            access_token: OAuth2 access token
            lta_handler: LTA handler for timestamp (optional)
            **kwargs: Additional args for RemoteSigningConfig
                (pin, otp, sign_algo, timeout, verify_ssl)

        Returns:
            PDFSigner in REMOTE_CSC mode
        """
        from pdfsigner.core.remote.remote_signer import (
            RemoteSigningConfig,
            create_remote_signer,
        )

        config = RemoteSigningConfig(
            service_url=service_url,
            credential_id=credential_id,
            access_token=access_token,
            **kwargs,
        )
        remote_signer = create_remote_signer(config)

        instance = cls(
            nss_handler=None,
            lta_handler=lta_handler,
            signing_mode=SigningMode.REMOTE_CSC,
        )
        instance._remote_signer = remote_signer
        return instance

    def _create_signer(self, cert_id: bytes | None = None) -> signers.Signer:
        """Creates the pyHanko signer with the token certificate."""
        # Import here to avoid linter removing unused import
        from pyhanko.sign.pkcs11 import PKCS11Signer

        # Use pyHanko's PKCS11Signer with our authenticated session
        # This properly handles the PKCS#11 protocol
        signer = PKCS11Signer(
            pkcs11_session=self.nss_handler.get_session(),
            cert_id=cert_id,
        )

        return signer

    def _validate_pdf(self, pdf_path: Path) -> None:
        """Validates that the PDF can be signed."""
        try:
            with open(pdf_path, "rb") as f:
                reader = PdfFileReader(f, strict=False)

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

    def _render_template_stamp(
        self,
        template_name: str,
        signer_name: str | None,
        input_path: Path | None,
        appearance: "SignatureAppearance",
        organization: str | None = None,
    ) -> Path | None:
        """
        Render a signature stamp using a template.

        Args:
            template_name: Name of template to use
            signer_name: Certificate CN for {signer_name} variable
            input_path: PDF path (for QR hash if template has QR layer)
            appearance: Signature appearance config
            organization: Organization from certificate for {org} variable

        Returns:
            Path to rendered PNG or None if failed
        """
        try:
            from pdfsigner.core.signature import (
                get_builtin_templates_dir,
                load_template,
                render_template,
            )

            template = load_template(template_name)
            if not template:
                logger.warning(f"Template not found: {template_name}")
                return None

            # Prepare variables for substitution
            variables = {
                "signer_name": signer_name or "Digital Signature",
                "date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M"),
                "org": organization or "",
            }

            # Check if template has QR layer and generate QR if needed
            qr_image = None
            has_qr_layer = any(layer.type == "qr" for layer in template.layers)
            if has_qr_layer and input_path:
                try:
                    from pdfsigner.core.stamp.qr_generator import (
                        QRData,
                        calculate_document_hash,
                        generate_qr_image,
                    )

                    doc_hash = calculate_document_hash(input_path)
                    qr_data = QRData(
                        document_hash=doc_hash,
                        signer_name=signer_name or "Digital Signature",
                    )
                    qr_image = generate_qr_image(qr_data)
                except Exception as e:
                    logger.warning(f"Could not generate QR for template: {e}")

            templates_dir = get_builtin_templates_dir()
            stamp_path = render_template(
                template,
                variables=variables,
                templates_dir=templates_dir,
                qr_image=qr_image,
            )

            logger.debug(f"Rendered template stamp: {stamp_path}")
            return stamp_path

        except Exception as e:
            logger.error(f"Failed to render template '{template_name}': {e}")
            return None

    def _add_visual_stamps_to_pdf(
        self,
        input_path: Path,
        output_path: Path,
        stamp_positions: list,
        stamp_image_path: Path,
    ) -> None:
        """
        Adds visual stamp images to PDF pages without digital signature.

        Uses PyMuPDF to insert stamp images as annotations on specified pages.
        This is used for multi-page signing where only the first page gets the
        actual digital signature, and other pages get visual copies.

        Args:
            input_path: Source PDF path
            output_path: Output PDF path (can be same as input for temp files)
            stamp_positions: List of StampPosition objects with page/coordinates
            stamp_image_path: Path to the stamp PNG image
        """
        import fitz  # PyMuPDF

        doc = fitz.open(input_path)
        try:
            for pos in stamp_positions:
                if pos.page < len(doc):
                    page = doc[pos.page]
                    # PDF coordinates: origin at bottom-left, but fitz uses top-left
                    # The position from position_finder is already in PDF coords (bottom-left)
                    # fitz.Rect uses (x0, y0, x1, y1) with origin at TOP-LEFT
                    page_height = page.rect.height
                    rect = fitz.Rect(
                        pos.x,
                        page_height - pos.y - pos.height,  # Convert Y from bottom to top
                        pos.x + pos.width,
                        page_height - pos.y,
                    )
                    page.insert_image(rect, filename=str(stamp_image_path))
                    logger.debug(f"Added visual stamp to page {pos.page + 1}")

            doc.save(output_path)
        finally:
            doc.close()

    def _create_stretch_layout(self):
        """Create the standard stretch layout for stamp styles."""
        from pyhanko.pdf_utils.layout import (
            AxisAlignment,
            InnerScaling,
            Margins,
            SimpleBoxLayoutRule,
        )

        return SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MIN,
            y_align=AxisAlignment.ALIGN_MIN,
            inner_content_scaling=InnerScaling.STRETCH_TO_FIT,
            margins=Margins(left=0, right=0, top=0, bottom=0),
        )

    def _build_stamp_style(
        self,
        appearance: "SignatureAppearance",
        input_path: Path | None = None,
        signer_name: str | None = None,
        organization: str | None = None,
        template_override: str | None = None,
    ):
        """
        Builds the visual stamp style for visible signatures.

        Args:
            appearance: Signature appearance configuration
            input_path: Path to PDF (needed for QR hash calculation)
            organization: Organization name from certificate (for {org} variable)
            signer_name: Name of signer from certificate (for QR)
            template_override: Template name to use instead of settings default

        Returns:
            TextStampStyle if visible signature, None otherwise
        """
        if not appearance.visible:
            return None

        # Import here to avoid circular imports and allow lazy loading
        from pyhanko import stamp
        from pyhanko.pdf_utils import images

        # Use override template if provided, otherwise check settings
        if template_override is not None:
            template_name = template_override
        else:
            settings = get_settings()
            template_name = settings.signature_template

        has_template = bool(template_name)

        if has_template:
            stamp_path = self._render_template_stamp(
                template_name,
                signer_name,
                input_path,
                appearance,
                organization=organization,
            )
            if stamp_path:
                try:
                    bg_layout = self._create_stretch_layout()
                    return stamp.TextStampStyle(
                        stamp_text="",
                        background=images.PdfImage(str(stamp_path)),
                        background_opacity=1.0,  # Full opacity for crisp image
                        background_layout=bg_layout,
                        border_width=0,  # No additional border
                    )
                except Exception as e:
                    logger.warning(f"Failed to use template stamp: {e}, falling back to text")
            # If template fails, fall through to text-only (NOT QR manual)

        # If QR is enabled (and no template), generate composed stamp image
        # Note: When using templates, QR is controlled by template layers, not this code
        if not has_template and appearance.qr_enabled and input_path:
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
                    timestamp=datetime.now(UTC),
                    qr_data=qr_data,
                    qr_position=appearance.qr_position,
                )

                logger.debug(f"Generated QR stamp: {stamp_image_path}")

                bg_layout = self._create_stretch_layout()
                return stamp.TextStampStyle(
                    stamp_text="",
                    background=images.PdfImage(str(stamp_image_path)),
                    background_opacity=1.0,
                    background_layout=bg_layout,
                    border_width=0,
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

    def _prepare_signing_context(
        self,
        input_path: Path,
        cert_id: bytes | None,
    ) -> tuple[signers.Signer, object | None, str | None, str | None, int]:
        """
        Prepare signing context: signer, timestamper, and certificate info.

        Args:
            input_path: Path to the PDF to sign
            cert_id: Certificate ID to use (None = default)

        Returns:
            Tuple of (signer, timestamper, signer_name, organization, existing_sig_count)
        """
        self._validate_pdf(input_path)

        validator = PDFValidator()
        existing_sig_count = validator.get_signature_count(input_path)

        signer = self._create_signer(cert_id)

        timestamper = None
        if self.lta_handler and self.lta_handler.tsa_config.url:
            timestamper = self.lta_handler.get_timestamper()

        # Extract signer info from certificate (asn1crypto API)
        signer_name = None
        organization = None
        if signer.signing_cert:
            subject_dict = signer.signing_cert.subject.native
            signer_name = subject_dict.get("common_name")
            organization = subject_dict.get("organization_name")

        return signer, timestamper, signer_name, organization, existing_sig_count

    def _preprocess_pdf_with_stamps(
        self,
        input_path: Path,
        visual_stamps: list,
        template_override: str | None,
        signer_name: str | None,
        appearance: "SignatureAppearance",
        organization: str | None,
    ) -> tuple[Path, Path | None]:
        """
        Add visual stamps to additional pages if needed.

        Args:
            input_path: Original PDF path
            visual_stamps: List of stamp positions for non-signature pages
            template_override: Template name override
            signer_name: Certificate CN
            appearance: Signature appearance configuration
            organization: Organization from certificate

        Returns:
            Tuple of (pdf_to_sign, temp_pdf_path or None)
        """
        if not visual_stamps:
            return input_path, None

        import os
        import tempfile

        template_name = template_override or get_settings().signature_template or "default"
        stamp_image_path = self._render_template_stamp(
            template_name,
            signer_name,
            input_path,
            appearance,
            organization=organization,
        )

        if not stamp_image_path:
            return input_path, None

        temp_fd, temp_pdf_str = tempfile.mkstemp(suffix=".pdf")
        temp_pdf_path = Path(temp_pdf_str)
        os.close(temp_fd)

        self._add_visual_stamps_to_pdf(
            input_path,
            temp_pdf_path,
            visual_stamps,
            stamp_image_path,
        )

        logger.debug(f"Added visual stamps to {len(visual_stamps)} additional page(s)")
        return temp_pdf_path, temp_pdf_path

    def _execute_signing(
        self,
        pdf_to_sign: Path,
        output_path: Path,
        input_path: Path,
        field_result,
        signer: signers.Signer,
        timestamper,
        appearance: "SignatureAppearance",
        signer_name: str | None,
        organization: str | None,
        existing_sig_count: int,
        template_override: str | None,
        reason: str | None = None,
        location: str | None = None,
        contact_info: str | None = None,
    ) -> None:
        """
        Execute the actual PDF signing operation.

        Args:
            pdf_to_sign: PDF to sign (original or preprocessed)
            output_path: Where to save signed PDF
            input_path: Original input path (for stamp rendering)
            field_result: Signature field specification
            signer: pyHanko signer
            timestamper: TSA timestamper or None
            appearance: Signature appearance configuration
            signer_name: Certificate CN
            organization: Organization from certificate
            existing_sig_count: Number of existing signatures
            template_override: Template name override
            reason: Signature reason (e.g., "I approve this document")
            location: Signature location (e.g., "Buenos Aires, Argentina")
            contact_info: Contact information (e.g., "email@company.com")
        """
        # strict=False allows hybrid-reference PDFs (mixed xref tables/streams)
        with open(pdf_to_sign, "rb") as f:
            writer = IncrementalPdfFileWriter(f, strict=False)

            if field_result.field_spec:
                append_signature_field(writer, field_result.field_spec)
                sig_field_name = field_result.field_spec.sig_field_name
            else:
                sig_field_name = f"Signature{existing_sig_count + 1}"

            stamp_style = self._build_stamp_style(
                appearance,
                input_path=input_path,
                signer_name=signer_name,
                organization=organization,
                template_override=template_override,
            )

            sig_metadata = signers.PdfSignatureMetadata(
                field_name=sig_field_name,
                md_algorithm="sha256",
                subfilter=SigSeedSubFilter.PADES,
                reason=reason or None,
                location=location or None,
                contact_info=contact_info or None,
            )

            pdf_signer = signers.PdfSigner(
                sig_metadata,
                signer=signer,
                stamp_style=stamp_style,
                timestamper=timestamper,
            )

            with open(output_path, "wb") as out:
                pdf_signer.sign_pdf(writer, output=out)

    def _extract_cert_chain(self, signer: signers.Signer) -> list:
        """
        Extract certificate chain from signer in cryptography format.

        Converts the signing certificate and any intermediate certificates
        from asn1crypto (pyHanko format) to cryptography format for use
        with DSSManager.

        Args:
            signer: pyHanko signer with certificate info

        Returns:
            List of cryptography certificates from signing cert to root
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_chain = []

        # Add signing certificate
        if signer.signing_cert:
            try:
                cert_der = signer.signing_cert.dump()
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                cert_chain.append(cert)
                logger.debug("Extracted signing certificate for LTV")
            except Exception as e:
                logger.warning(f"Could not extract signing certificate: {e}")

        # Add intermediate certificates from cert_registry
        if hasattr(signer, "cert_registry") and signer.cert_registry:
            try:
                # The cert_registry is a SimpleCertificateStore
                # Iterate through all certificates
                for cert_ref in signer.cert_registry:
                    try:
                        cert_der = cert_ref.dump()
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        # Avoid duplicates
                        if cert not in cert_chain:
                            cert_chain.append(cert)
                            logger.debug("Extracted intermediate certificate for LTV")
                    except Exception as e:
                        logger.warning(f"Could not load certificate from registry: {e}")
            except Exception as e:
                logger.warning(f"Could not iterate cert_registry: {e}")

        logger.info(f"Extracted {len(cert_chain)} certificate(s) for LTV")
        return cert_chain

    def _embed_ltv_info(self, pdf_path: Path, cert_chain: list) -> None:
        """
        Embed DSS with OCSP/CRL for LTV validation.

        Collects validation information (OCSP responses, CRLs) for the
        certificate chain and embeds them into the signed PDF as a
        Document Security Store (DSS).

        Args:
            pdf_path: Path to the signed PDF
            cert_chain: List of certificates (cryptography format)

        Raises:
            Exception: If DSS embedding fails and ltv_fail_open is False
        """
        settings = get_settings()

        # Reuse DSSManager across batch operations (no per-file state)
        if self._dss_manager is None:
            self._dss_manager = DSSManager(
                ocsp_timeout=settings.ltv_ocsp_timeout,
                crl_timeout=settings.ltv_crl_timeout,
                prefer_ocsp=settings.ltv_prefer_ocsp,
            )
        dss_manager = self._dss_manager

        logger.info("Collecting validation info for LTV")
        validation_info = dss_manager.collect_validation_info(cert_chain)

        if not validation_info.is_empty():
            logger.info("Embedding DSS into signed PDF")
            dss_manager.embed_dss(pdf_path, validation_info)
            logger.debug(
                f"DSS embedded: {len(validation_info.ocsp_responses)} OCSP, "
                f"{len(validation_info.crls)} CRLs, "
                f"{len(validation_info.certificates)} certs"
            )
        else:
            logger.warning("No validation info collected for LTV")

    def _log_signing_success(
        self,
        signer: signers.Signer,
        signer_name: str | None,
        input_path: Path,
        output_path: Path,
        template_override: str | None,
        reason: str | None,
        location: str | None,
    ) -> None:
        """Log audit event for successful signing."""
        certificate_serial = None
        certificate_issuer = None
        try:
            if signer.signing_cert:
                certificate_serial = hex(signer.signing_cert.serial_number)
                certificate_issuer = signer.signing_cert.issuer.human_friendly
        except (TypeError, AttributeError):
            pass

        log_signing_event(
            document_path=str(input_path),
            certificate_serial=certificate_serial,
            certificate_issuer=certificate_issuer,
            user_cn=signer_name,
            success=True,
            details={
                "template": template_override or get_settings().signature_template or "none",
                "output": str(output_path),
                "reason": reason,
                "location": location,
            },
        )

    def _log_signing_failure(
        self,
        input_path: Path,
        error: Exception,
        signer: signers.Signer | None = None,
        signer_name: str | None = None,
    ) -> None:
        """Log audit event for failed signing."""
        certificate_serial = None
        certificate_issuer = None
        user_cn = None
        try:
            if signer is not None and signer.signing_cert:
                certificate_serial = hex(signer.signing_cert.serial_number)
                certificate_issuer = signer.signing_cert.issuer.human_friendly
                user_cn = signer_name
        except (TypeError, AttributeError):
            pass

        log_signing_event(
            document_path=str(input_path),
            certificate_serial=certificate_serial,
            certificate_issuer=certificate_issuer,
            user_cn=user_cn,
            success=False,
            error=str(error),
            details={"error_type": type(error).__name__, "error_message": str(error)},
        )

    def sign_pdf(
        self,
        input_path: Path,
        output_path: Path | None = None,
        appearance: SignatureAppearance | None = None,
        cert_id: bytes | None = None,
        template_override: str | None = None,
        reason: str | None = None,
        location: str | None = None,
        contact_info: str | None = None,
        embed_ltv: bool | None = None,
    ) -> SigningResult:
        """
        Signs a PDF.

        Args:
            input_path: Path to the PDF to sign
            output_path: Output path (None = automatic)
            appearance: Appearance configuration
            cert_id: Certificate ID to use (None = default)
            template_override: Template name to use instead of settings default
            reason: Signature reason (e.g., "I approve this document")
            location: Signature location (e.g., "Buenos Aires, Argentina")
            contact_info: Contact information (e.g., "email@company.com")
            embed_ltv: Enable LTV (None = use settings.ltv_enabled)

        Returns:
            Signing operation result
        """
        input_path = Path(input_path)
        output_path = output_path or self._get_output_path(input_path)
        appearance = appearance or SignatureAppearance()

        logger.info(f"Signing: {input_path.name}")

        signer = None
        signer_name = None

        try:
            # Phase 1: Prepare signing context
            signer, timestamper, signer_name, organization, existing_sig_count = (
                self._prepare_signing_context(input_path, cert_id)
            )

            # Phase 2: Create signature fields
            from pdfsigner.core.signer.signature_field import create_signature_field_with_stamps

            field_result = create_signature_field_with_stamps(
                input_path,
                appearance.visible,
                appearance.page,
                appearance.width_mm,
                appearance.height_mm,
                appearance.position_preference,
                existing_signature_count=existing_sig_count,
            )

            # Phase 3: Preprocess PDF with visual stamps if multi-page
            pdf_to_sign, temp_pdf_path = self._preprocess_pdf_with_stamps(
                input_path,
                field_result.visual_stamps,
                template_override,
                signer_name,
                appearance,
                organization,
            )

            # Phase 4: Execute signing
            try:
                self._execute_signing(
                    pdf_to_sign,
                    output_path,
                    input_path,
                    field_result,
                    signer,
                    timestamper,
                    appearance,
                    signer_name,
                    organization,
                    existing_sig_count,
                    template_override,
                    reason=reason,
                    location=location,
                    contact_info=contact_info,
                )
            finally:
                if temp_pdf_path and temp_pdf_path.exists():
                    temp_pdf_path.unlink()

            # Phase 5: Embed LTV validation info (DSS)
            settings = get_settings()
            should_embed_ltv = embed_ltv if embed_ltv is not None else settings.ltv_enabled
            if should_embed_ltv:
                try:
                    cert_chain = self._extract_cert_chain(signer)
                    if cert_chain:
                        self._embed_ltv_info(output_path, cert_chain)
                        logger.info("LTV validation info embedded successfully")
                    else:
                        logger.warning("No certificate chain available for LTV")
                except Exception as e:
                    if settings.ltv_fail_open:
                        logger.warning(f"LTV embedding failed (continuing): {e}")
                    else:
                        raise

            # Phase 6: Add archive timestamp (PAdES B-LTA)
            if settings.archive_ts_enabled and settings.archive_ts_auto:
                try:
                    # Build TSA URL list (primary first, then fallbacks)
                    tsa_urls = []
                    if settings.tsa_url:
                        tsa_urls.append(settings.tsa_url)
                    tsa_urls.extend(settings.archive_ts_tsa_urls)

                    if tsa_urls:
                        archive_manager = ArchiveTimestampManager(
                            tsa_urls=tsa_urls,
                            timeout=settings.ltv_ocsp_timeout,  # reuse timeout
                        )
                        archive_manager.add_archive_timestamp(output_path)
                        logger.info("Archive timestamp added successfully (PAdES B-LTA)")
                    else:
                        logger.warning("Archive timestamp skipped: no TSA URL configured")
                except Exception as e:
                    if settings.ltv_fail_open:
                        logger.warning(f"Archive timestamp failed (continuing): {e}")
                    else:
                        raise

            logger.info(f"PDF signed successfully: {output_path.name}")

            self._log_signing_success(
                signer,
                signer_name,
                input_path,
                output_path,
                template_override,
                reason,
                location,
            )

            return SigningResult(
                success=True,
                input_path=input_path,
                output_path=output_path,
                signed_at=datetime.now(UTC),
            )

        except (PDFCorruptedError, PDFProtectedError) as e:
            logger.error(f"PDF error: {e}")

            self._log_signing_failure(input_path, e)

            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )
        except Exception as e:
            import traceback

            logger.error(f"Error signing PDF: {e}\n{traceback.format_exc()}")

            self._log_signing_failure(input_path, e, signer=signer, signer_name=signer_name)

            return SigningResult(
                success=False,
                input_path=input_path,
                output_path=None,
                error=str(e),
            )
