"""
sign.py - CLI signature command

Author: Homero Thompson del Lago del Terror

Implements the 'sign' command for PDF signing.
Supports real mode and dry-run.
"""

import argparse
from pathlib import Path

from loguru import logger

from pdfsigner.cli.utils import collect_pdf_files, get_pin_from_user
from pdfsigner.config.settings import get_settings
from pdfsigner.core.signer.batch_manager import BatchManager
from pdfsigner.core.signer.lta_handler import create_lta_handler_from_settings
from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.core.token.cert_selector import CertificateSelector
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import PDFSignerError

# Global flag for dry-run (set from main.py)
_dry_run_mode = False


def set_dry_run_mode(enabled: bool) -> None:
    """Enable/disable dry-run mode globally."""
    global _dry_run_mode
    _dry_run_mode = enabled


def cmd_sign(args: argparse.Namespace) -> int:
    """Signature command."""
    try:
        pdf_files = collect_pdf_files(args.files, args.recursive)

        if not pdf_files:
            logger.error("No PDF files to sign")
            return 1

        logger.info(f"Files to sign: {len(pdf_files)}")

        # Determine if we're in dry-run mode
        dry_run = _dry_run_mode or get_settings().dry_run

        if dry_run:
            return _sign_dry_run(args, pdf_files)
        else:
            return _sign_real(args, pdf_files)

    except PDFSignerError as e:
        logger.error(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nCancelled")
        return 130


def _sign_dry_run(args: argparse.Namespace, pdf_files: list[Path]) -> int:
    """Sign in simulation mode (dry-run)."""
    from pdfsigner.core.mock import MockBatchManager, MockNSSHandler, create_mock_certificate

    print("\n" + "=" * 60)
    print("⚠️  DRY-RUN MODE - SIMULATION WITHOUT REAL TOKEN")
    print("=" * 60)
    print("Files will be copied with _signed suffix")
    print("but will NOT contain real digital signature.\n")

    logger.info("[DRY-RUN] Simulating token connection...")
    nss_handler = MockNSSHandler()
    nss_handler.initialize()

    tokens = nss_handler.get_available_tokens()
    logger.info(f"[DRY-RUN] Simulated token: {tokens[0]}")
    nss_handler.connect_token()

    print("[DRY-RUN] Enter any PIN with 4+ digits to simulate:")
    pin = get_pin_from_user()
    nss_handler.authenticate(pin)
    logger.info("[DRY-RUN] Simulated authentication successful")

    certs = nss_handler.get_certificates()
    cert = certs[0] if certs else create_mock_certificate()
    print(f"\n[DRY-RUN] Using simulated certificate: {cert.display_name}")

    page = _parse_page(args.page)
    batch_manager = MockBatchManager()

    # If QR is requested but not visible, enable visible automatically
    qr_enabled = getattr(args, "qr_code", False)
    visible = args.visible or qr_enabled

    if qr_enabled and not args.visible:
        print("[DRY-RUN] QR code requires visible signature, enabling --visible")

    def progress_callback(progress):
        pct = progress.current / progress.total * 100
        current = progress.current_file or "Completed"
        status = f"[{progress.status}]" if progress.status else ""
        print(f"\r[DRY-RUN] [{pct:5.1f}%] {current:<40} {status}", end="", flush=True)

    print()
    result = batch_manager.sign_batch(
        files=pdf_files,
        pin=pin,
        visible=visible,
        page=page,
        qr_enabled=qr_enabled,
        progress_callback=progress_callback,
    )
    print()

    nss_handler.close()

    print("\n" + "-" * 60)
    if result.all_successful:
        print(f"✓ [DRY-RUN] {result.successful} file(s) copied with _signed suffix")
        print("\n⚠️  Note: Files are NOT actually signed.")
        print("   Copies were created to simulate the process.")
        return 0
    else:
        print(f"[DRY-RUN] {result.successful} copied, {result.failed} failed")
        for path, error in result.get_failed_files():
            print(f"  ✗ {path.name}: {error}")
        return 1


def _sign_real(args: argparse.Namespace, pdf_files: list[Path]) -> int:
    """Real signing with USB token."""
    logger.info("Connecting to USB token...")
    nss_handler = NSSHandler()
    nss_handler.initialize()

    tokens = nss_handler.get_available_tokens()
    if not tokens:
        logger.error("USB token not detected")
        return 1

    logger.info(f"Token found: {tokens[0]}")
    nss_handler.connect_token()

    pin = get_pin_from_user()
    nss_handler.authenticate(pin)
    logger.info("Authentication successful")

    cert_selector = CertificateSelector(nss_handler)
    certs = cert_selector.get_valid_certificates()

    if len(certs) > 1 and not args.cert:
        print("\nAvailable certificates:")
        for i, cert in enumerate(certs, 1):
            status = "⚠" if cert.is_expiring_soon else "✓"
            print(f"  {i}. [{status}] {cert.display_name} ({cert.days_until_expiry} days)")
        print(f"\nUsing default certificate: {certs[0].display_name}")
        print("Use --cert N to select another\n")

    cert_index = (args.cert - 1) if args.cert else 0
    if cert_index >= len(certs):
        logger.error(f"Certificate {args.cert} does not exist")
        nss_handler.close()
        return 1

    cert = certs[cert_index]
    logger.info(f"Using certificate: {cert.display_name}")

    try:
        lta_handler = create_lta_handler_from_settings()
    except Exception as e:
        logger.warning(f"TSA not available: {e}")
        lta_handler = None

    page = _parse_page(args.page)

    # If QR is requested but not visible, enable visible automatically
    qr_enabled = getattr(args, "qr_code", False)
    visible = args.visible or qr_enabled  # QR requires visible signature

    if qr_enabled and not args.visible:
        logger.info("QR code requires visible signature, enabling --visible")

    appearance = SignatureAppearance(
        visible=visible,
        page=page,
        qr_enabled=qr_enabled,
    )

    batch_manager = BatchManager(nss_handler, lta_handler)

    def progress_callback(progress):
        pct = (progress.completed + progress.failed) / progress.total * 100
        current = progress.current_file or "Completed"
        print(f"\r[{pct:5.1f}%] {current:<50}", end="", flush=True)

    print()
    result = batch_manager.sign_batch(
        pdf_files=pdf_files,
        appearance=appearance,
        cert_id=cert.info.pkcs11_id,
        progress_callback=progress_callback,
    )
    print()

    nss_handler.close()

    if result.all_successful:
        print(f"\n✓ {result.successful} file(s) signed successfully")
        return 0
    else:
        print(f"\n{result.successful} successful, {result.failed} failed")
        for path, error in result.get_failed_files():
            print(f"  ✗ {path.name}: {error}")
        return 1


def _parse_page(page: str) -> str | int:
    """Parse page argument."""
    if page in ("last", "first"):
        return page
    try:
        return int(page) - 1
    except ValueError:
        return "last"
