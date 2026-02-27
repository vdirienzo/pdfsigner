"""
deprecation_checker.py - SOGIS algorithm deprecation checking for archive timestamps

Extracted from archive_ts_scheduler.py to reduce file size.
Inspects PDFs for algorithm deprecation status per SOGIS v1.3 guidelines.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager

_DEPRECATION_RESULT = "algorithm_approaching_deprecation"


def check_deprecation_reason(
    manager: ArchiveTimestampManager,
    pdf_path: Path,
) -> str | None:
    """Check if a PDF's signatures use algorithms approaching SOGIS deprecation.

    Inspects archive timestamps for hash algorithm deprecation and
    attempts to read the signature's key size to detect RSA-2048
    deprecation (expired 2025-12-31 per SOGIS v1.3).

    Args:
        manager: ArchiveTimestampManager instance for reading timestamps.
        pdf_path: Path to the PDF to check.

    Returns:
        ``"algorithm_approaching_deprecation"`` if any algorithm is
        within 365 days of deprecation or already deprecated,
        otherwise ``None``.
    """
    from pdfsigner.core.crypto.algorithm_policy import check_algorithm_deprecation

    try:
        # Check timestamp hash algorithms
        result = _check_timestamp_algorithms(manager, pdf_path, check_algorithm_deprecation)
        if result:
            return result

        # Check signature field certificates
        result = _check_signature_certificates(pdf_path, check_algorithm_deprecation)
        if result:
            return result

    except Exception as e:
        logger.debug("Deprecation check failed for %s: %s", pdf_path.name, e)

    return None


def _check_timestamp_algorithms(manager, pdf_path: Path, check_fn) -> str | None:
    """Check archive timestamp hash algorithms for deprecation."""
    timestamps = manager.get_archive_timestamps(pdf_path)

    for ts in timestamps:
        hash_alg = ts.hash_algorithm.lower()
        warnings = check_fn(
            hash_alg=hash_alg,
            sig_alg="rsa",
            key_size=2048,
        )
        for w in warnings:
            if w.severity in ("critical", "warning"):
                logger.info(
                    "Algorithm deprecation detected in %s: %s",
                    pdf_path.name,
                    w.message,
                )
                return _DEPRECATION_RESULT

    return None


def _check_signature_certificates(pdf_path: Path, check_fn) -> str | None:
    """Inspect signature fields for RSA key size deprecation."""
    from pyhanko.pdf_utils.reader import PdfFileReader

    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f, strict=False)

        if "/AcroForm" not in reader.root:
            return None

        acro_form = reader.root["/AcroForm"]
        if "/Fields" not in acro_form:
            return None

        for field_ref in acro_form["/Fields"]:
            field_obj = field_ref.get_object()
            if field_obj.get("/FT") != "/Sig":
                continue

            sig_value = field_obj.get("/V")
            if sig_value is None:
                continue

            sig_dict = sig_value.get_object() if hasattr(sig_value, "get_object") else sig_value

            # Only check actual signatures (not timestamps)
            subfilter = sig_dict.get("/SubFilter")
            if subfilter in ("/ETSI.RFC3161", "/adbe.x509.rfc3161"):
                continue

            contents = sig_dict.get("/Contents")
            if not contents:
                continue

            result = _check_cert_key_deprecation(contents, pdf_path, check_fn)
            if result:
                return result

    return None


def _check_cert_key_deprecation(contents, pdf_path: Path, check_fn) -> str | None:
    """Parse CMS signature and check certificate key size deprecation."""
    try:
        from asn1crypto import cms

        content_info = cms.ContentInfo.load(contents)
        signed_data = content_info["content"]
        certs = signed_data["certificates"]

        for cert_choice in certs:
            cert = cert_choice.chosen
            pub_key_info = cert["tbs_certificate"]["subject_public_key_info"]
            alg_oid = pub_key_info["algorithm"]["algorithm"].native

            key_size = 0
            if alg_oid == "rsa":
                key_bits = pub_key_info["public_key"].parsed
                if key_bits is not None:
                    modulus = key_bits["modulus"].native
                    key_size = modulus.bit_length()

            hash_name = _extract_hash_name(cert)

            if key_size > 0:
                warnings = check_fn(
                    hash_alg=hash_name,
                    sig_alg="rsa",
                    key_size=key_size,
                )
                for w in warnings:
                    if w.severity in ("critical", "warning"):
                        logger.info(
                            "Algorithm deprecation in %s: %s",
                            pdf_path.name,
                            w.message,
                        )
                        return _DEPRECATION_RESULT

    except Exception as e:
        logger.debug(
            "Could not parse signature cert in %s: %s",
            pdf_path.name,
            e,
        )

    return None


def _extract_hash_name(cert) -> str:
    """Extract hash algorithm name from certificate signature algorithm."""
    sig_hash = cert["tbs_certificate"]["signature"]["algorithm"].native
    sig_hash_str = str(sig_hash)
    if "sha384" in sig_hash_str:
        return "sha384"
    elif "sha512" in sig_hash_str:
        return "sha512"
    elif "sha1" in sig_hash_str:
        return "sha1"
    return "sha256"
