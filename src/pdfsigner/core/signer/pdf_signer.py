"""
pdf_signer.py - PDF signer with PAdES-LTV (orchestrator)

Delegates to stamp_builder and signing_pipeline modules.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager
from pdfsigner.core.signer.dss_manager import DSSManager
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.signer.signing_pipeline import (
    embed_ltv_info,
    execute_signing,
    extract_cert_chain,
    log_signing_failure,
    log_signing_success,
    preprocess_pdf_with_stamps,
)
from pdfsigner.core.signer.stamp_builder import build_stamp_style, render_template_stamp
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
        """Initialize the signer with NSS handler and optional LTA/mode."""
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
        """Create a PDFSigner configured for remote signing via CSC API."""
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
        from pyhanko.sign.pkcs11 import PKCS11Signer

        return PKCS11Signer(
            pkcs11_session=self.nss_handler.get_session(),
            cert_id=cert_id,
        )

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

    # -- Thin wrappers for backward compatibility with tests --

    def _render_template_stamp(self, *args, **kwargs) -> Path | None:
        """Delegate to stamp_builder.render_template_stamp."""
        return render_template_stamp(*args, **kwargs)

    def _build_stamp_style(self, *args, **kwargs):
        """Delegate to stamp_builder.build_stamp_style."""
        return build_stamp_style(*args, **kwargs)

    def _preprocess_pdf_with_stamps(self, *args, **kwargs) -> tuple[Path, Path | None]:
        """Delegate to signing_pipeline.preprocess_pdf_with_stamps."""
        return preprocess_pdf_with_stamps(*args, **kwargs)

    def _execute_signing(self, *args, **kwargs) -> None:
        """Delegate to signing_pipeline.execute_signing."""
        return execute_signing(*args, **kwargs)

    def _extract_cert_chain(self, signer: signers.Signer) -> list:
        """Delegate to signing_pipeline.extract_cert_chain."""
        return extract_cert_chain(signer)

    def _embed_ltv_info(self, pdf_path: Path, cert_chain: list) -> None:
        """Delegate to signing_pipeline.embed_ltv_info."""
        self._dss_manager = embed_ltv_info(pdf_path, cert_chain, self._dss_manager)

    def _log_signing_success(self, *args, **kwargs) -> None:
        """Delegate to signing_pipeline.log_signing_success."""
        log_signing_success(*args, **kwargs)

    def _log_signing_failure(self, *args, **kwargs) -> None:
        """Delegate to signing_pipeline.log_signing_failure."""
        log_signing_failure(*args, **kwargs)

    def _prepare_signing_context(
        self,
        input_path: Path,
        cert_id: bytes | None,
    ) -> tuple[signers.Signer, object | None, str | None, str | None, int]:
        """Prepare signing context: signer, timestamper, and certificate info."""
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
        """Signs a PDF with PAdES-LTV. Main public API."""
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
            from pdfsigner.core.signer.signature_field import (
                create_signature_field_with_stamps,
            )

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
