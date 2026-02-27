"""
signing_pipeline.py - Signing pipeline execution steps

Author: Homero Thompson del Lago del Terror

Contains the execution steps for the PDF signing pipeline:
- PDF preprocessing with visual stamps
- Signature execution with pyHanko
- Certificate chain extraction for LTV
- DSS/LTV embedding
- Audit logging for signing events
"""

from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter, append_signature_field

from pdfsigner.config.settings import get_settings
from pdfsigner.core.audit import log_signing_event
from pdfsigner.core.signer.dss_manager import DSSManager
from pdfsigner.core.signer.stamp_builder import (
    add_visual_stamps_to_pdf,
    build_stamp_style,
    render_template_stamp,
)

if TYPE_CHECKING:
    from pdfsigner.core.signer.pdf_signer import SignatureAppearance


def preprocess_pdf_with_stamps(
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
    stamp_image_path = render_template_stamp(
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

    add_visual_stamps_to_pdf(
        input_path,
        temp_pdf_path,
        visual_stamps,
        stamp_image_path,
    )

    logger.debug(f"Added visual stamps to {len(visual_stamps)} additional page(s)")
    return temp_pdf_path, temp_pdf_path


def execute_signing(
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
        location: Signature location (e.g., "New York, NY")
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

        stamp_style = build_stamp_style(
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


def extract_cert_chain(signer: signers.Signer) -> list:
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


def embed_ltv_info(
    pdf_path: Path,
    cert_chain: list,
    dss_manager: DSSManager | None = None,
) -> DSSManager:
    """
    Embed DSS with OCSP/CRL for LTV validation.

    Collects validation information (OCSP responses, CRLs) for the
    certificate chain and embeds them into the signed PDF as a
    Document Security Store (DSS).

    Args:
        pdf_path: Path to the signed PDF
        cert_chain: List of certificates (cryptography format)
        dss_manager: Existing DSSManager to reuse (for batch operations)

    Returns:
        The DSSManager instance (for reuse in batch operations)

    Raises:
        Exception: If DSS embedding fails and ltv_fail_open is False
    """
    settings = get_settings()

    # Reuse DSSManager across batch operations (no per-file state)
    if dss_manager is None:
        dss_manager = DSSManager(
            ocsp_timeout=settings.ltv_ocsp_timeout,
            crl_timeout=settings.ltv_crl_timeout,
            prefer_ocsp=settings.ltv_prefer_ocsp,
        )

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

    return dss_manager


def log_signing_success(
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


def log_signing_failure(
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
