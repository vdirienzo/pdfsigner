"""
signature_validation.py - Signature validation helper functions

Author: Homero Thompson del Lago del Terror

Standalone helper functions extracted from PDFValidator to keep
each module under 400 lines. These are pure functions that do not
require PDFValidator state.
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger
from pyhanko.pdf_utils.reader import PdfFileReader

from pdfsigner.core.validator.validator_types import (
    LTVInfo,
    PAdESLevel,
    SignatureInfo,
    SignatureStatus,
)


def extract_cn(subject: str) -> str:
    """Extract Common Name (CN) from subject string.

    Args:
        subject: Subject string like "CN=Name,O=Org,..."

    Returns:
        The CN value or full subject if no CN found
    """
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:]
    return subject


def extract_email(cert) -> str | None:
    """Extract email from certificate if exists.

    Args:
        cert: Certificate object with extensions attribute

    Returns:
        Email address or None
    """
    try:
        for ext in cert.extensions:
            if ext.oid.dotted_string == "2.5.29.17":  # Subject Alt Name
                for name in ext.value:
                    if hasattr(name, "value") and "@" in str(name.value):
                        return str(name.value)
    except Exception as e:
        logger.debug(f"Could not extract email from certificate: {e}")
    return None


def extract_page_number(reader: PdfFileReader, sig) -> int | None:
    """Extract page number where signature annotation is located.

    Args:
        reader: PDF reader with document
        sig: EmbeddedPdfSignature object

    Returns:
        Page number (1-indexed) or None if not found
    """
    try:
        sig_field = sig.sig_field
        if not sig_field:
            return None

        sig_field_obj = sig_field.get_object()

        # Strategy 1: Check for direct /P reference to page
        if "/P" in sig_field_obj:
            page_ref = sig_field_obj.raw_get("/P")
            pages = reader.root["/Pages"]["/Kids"]
            for page_num, page in enumerate(pages):
                if page.reference == page_ref:
                    return page_num + 1

        # Strategy 2: Iterate pages and check /Annots array
        pages = reader.root["/Pages"]["/Kids"]
        for page_num, page in enumerate(pages):
            if "/Annots" in page:
                annots = page["/Annots"]
                if hasattr(annots, "get_object"):
                    annots = annots.get_object()
                for annot in annots:
                    annot_ref = annot if hasattr(annot, "reference") else annot
                    if annot_ref.reference == sig_field.reference:
                        return page_num + 1

        return None

    except Exception as e:
        logger.debug(f"Could not extract page number from signature annotation: {e}")
        return None


def create_error_info(field_name: str, error: str) -> SignatureInfo:
    """Create SignatureInfo for errors."""
    return SignatureInfo(
        signer_name="Unknown",
        signer_email=None,
        signing_time=None,
        is_timestamp_valid=False,
        certificate_issuer="Unknown",
        certificate_serial="",
        certificate_valid_from=None,
        certificate_valid_to=None,
        status=SignatureStatus.UNKNOWN,
        status_message=f"Error: {error}",
        field_name=field_name,
        covers_whole_document=False,
        is_modification_allowed=False,
        page_number=None,
        certificate_bytes=None,
        chain_validation_result=None,
        revocation_status=None,
        revocation_message=None,
        ltv_info=None,
    )


def create_hybrid_pdf_info(field_name: str, sig) -> SignatureInfo:
    """Create SignatureInfo for hybrid-reference PDFs.

    Hybrid PDFs mix classic xref tables with xref streams. The signature
    is present but cannot be fully verified due to this format limitation.
    We extract what information we can from the certificate.
    """
    signer_name = "Unknown"
    signer_email = None
    issuer = "Unknown"
    serial = ""
    valid_from = None
    valid_to = None
    cert_bytes = None

    if sig and sig.signer_cert:
        try:
            cert = sig.signer_cert
            signer_name = extract_cn(cert.subject.human_friendly)
            signer_email = extract_email(cert)
            issuer = extract_cn(cert.issuer.human_friendly)
            serial = format(cert.serial_number, "x")
            valid_from = cert.not_valid_before
            valid_to = cert.not_valid_after
            cert_bytes = cert.dump()
        except Exception as e:
            logger.debug(f"Could not extract certificate details: {e}")

    return SignatureInfo(
        signer_name=signer_name,
        signer_email=signer_email,
        signing_time=None,
        is_timestamp_valid=False,
        certificate_issuer=issuer,
        certificate_serial=serial,
        certificate_valid_from=valid_from,
        certificate_valid_to=valid_to,
        status=SignatureStatus.INDETERMINATE,
        status_message="Cannot fully verify (hybrid PDF format)",
        field_name=field_name,
        covers_whole_document=False,
        is_modification_allowed=False,
        page_number=None,
        certificate_bytes=cert_bytes,
        chain_validation_result=None,
        revocation_status=None,
        revocation_message=None,
        ltv_info=None,
    )


def check_dss_present(reader: PdfFileReader) -> tuple[bool, bool, bool]:
    """Check if PDF has Document Security Store (DSS).

    Args:
        reader: PDF reader

    Returns:
        Tuple of (has_dss, has_ocsp_in_dss, has_crl_in_dss)
    """
    try:
        dss_dict = reader.root.get("/DSS")
        if dss_dict is None:
            return False, False, False

        dss_obj = dss_dict.get_object() if hasattr(dss_dict, "get_object") else dss_dict
        has_ocsp = "/OCSPs" in dss_obj and len(dss_obj.get("/OCSPs", [])) > 0
        has_crl = "/CRLs" in dss_obj and len(dss_obj.get("/CRLs", [])) > 0

        logger.debug(f"DSS found: OCSP={has_ocsp}, CRL={has_crl}")
        return True, has_ocsp, has_crl

    except Exception as e:
        logger.debug(f"Error checking DSS: {e}")
        return False, False, False


def get_archive_timestamps(pdf_path: Path) -> list:
    """Get archive timestamps from PDF.

    Args:
        pdf_path: Path to PDF

    Returns:
        List of archive timestamps
    """
    try:
        from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager

        ts_manager = ArchiveTimestampManager(tsa_urls=[])
        return ts_manager.get_archive_timestamps(pdf_path)
    except Exception as e:
        logger.debug(f"Error getting archive timestamps: {e}")
        return []


def detect_pades_level(
    pdf_path: Path,
    reader: PdfFileReader,
    has_timestamp: bool,
) -> LTVInfo:
    """Detect PAdES compliance level of a signature.

    Args:
        pdf_path: Path to PDF
        reader: PDF reader
        has_timestamp: Whether signature has a timestamp

    Returns:
        LTVInfo with detected level and details
    """
    ltv_info = LTVInfo()

    has_dss, has_ocsp, has_crl = check_dss_present(reader)
    ltv_info.has_dss = has_dss
    ltv_info.has_ocsp_in_dss = has_ocsp
    ltv_info.has_crl_in_dss = has_crl

    archive_timestamps = get_archive_timestamps(pdf_path)
    ltv_info.archive_timestamps = archive_timestamps
    ltv_info.has_archive_timestamp = len(archive_timestamps) > 0

    if ltv_info.has_archive_timestamp:
        ltv_info.pades_level = PAdESLevel.B_LTA
    elif has_dss:
        ltv_info.pades_level = PAdESLevel.B_LT
    elif has_timestamp:
        ltv_info.pades_level = PAdESLevel.B_T
    else:
        ltv_info.pades_level = PAdESLevel.B_B

    logger.debug(f"Detected PAdES level: {ltv_info.pades_level.value}")
    return ltv_info


def check_eidas_qualification(cert_der: bytes) -> tuple[str | None, str | None]:
    """Check eIDAS qualification level of signing certificate.

    Args:
        cert_der: Certificate in DER format

    Returns:
        Tuple of (qualification_level, tsp_name) or (None, None)
    """
    try:
        from pdfsigner.core.eidas.qualified_validator import QualifiedSignatureValidator
        from pdfsigner.core.eidas.tsp_registry import get_tsp_registry

        registry = get_tsp_registry(use_mock_data=False)
        validator = QualifiedSignatureValidator(registry)
        result = validator.validate_certificate(cert_der)

        tsp_name = None
        if result.signature_validations:
            tsp_name = result.signature_validations[0].tsp_name

        return result.qualification_level, tsp_name
    except Exception as e:
        logger.warning("eIDAS qualification check failed: %s", e)
        return None, None
