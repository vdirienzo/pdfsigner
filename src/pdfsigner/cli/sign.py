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
from pdfsigner.core.audit import AuditEventType, get_audit_logger
from pdfsigner.core.phi import get_phi_scanner
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
        pct = progress.percentage
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


def _scan_phi_for_files(files: list[Path], skip_confirmation: bool = False) -> bool:
    """
    Scan files for PHI and ask for confirmation if detected.

    Args:
        files: List of PDF files to scan
        skip_confirmation: If True, skip user confirmation

    Returns:
        True if should proceed with signing, False to abort
    """
    scanner = get_phi_scanner()
    audit_logger = get_audit_logger()
    total_phi_count = 0
    files_with_phi = []

    print("\n" + "=" * 60)
    print("🔍 Scanning for Protected Health Information (PHI)")
    print("=" * 60 + "\n")

    for pdf_file in files:
        print(f"Scanning: {pdf_file.name}...", end=" ", flush=True)
        result = scanner.scan_pdf(pdf_file)

        if result.error:
            print(f"⚠️  Error: {result.error}")
            continue

        if result.has_phi:
            print(f"⚠️  PHI detected ({result.total_matches} matches)")
            files_with_phi.append((pdf_file, result))
            total_phi_count += result.total_matches

            # Log PHI types detected
            for phi_type, count in result.by_type.items():
                print(f"    - {phi_type}: {count} matches")
        else:
            print("✓ No PHI detected")

    if not files_with_phi:
        print("\n✓ No PHI detected in any files. Safe to proceed.\n")
        return True

    # Display summary
    print("\n" + "=" * 60)
    print("⚠️  WARNING: PHI DETECTED")
    print("=" * 60)
    print(f"Files with PHI: {len(files_with_phi)}/{len(files)}")
    print(f"Total PHI instances: {total_phi_count}")
    print(f"Overall confidence: {files_with_phi[0][1].overall_confidence.value}")
    print("\nPHI Types detected:")
    all_types: dict[str, int] = {}
    for _, result in files_with_phi:
        for phi_type, count in result.by_type.items():
            all_types[phi_type] = all_types.get(phi_type, 0) + count
    for phi_type, count in sorted(all_types.items()):
        print(f"  - {phi_type}: {count}")

    # Log audit event
    from pdfsigner.core.audit.audit_event import AuditEvent

    audit_logger.log_event(
        AuditEvent(
            event_type=AuditEventType.PHI_DETECTED,
            user_id="cli-user",
            details={
                "files_scanned": len(files),
                "files_with_phi": len(files_with_phi),
                "total_matches": total_phi_count,
                "phi_types": list(all_types.keys()),
            },
        )
    )

    # Ask for confirmation
    if skip_confirmation:
        print("\n--yes flag provided, proceeding with signing...\n")
        return True

    print("\n" + "-" * 60)
    print("⚠️  IMPORTANT: Signing documents with PHI may have compliance implications.")
    print("   Ensure you have proper authorization and the documents will be")
    print("   properly secured after signing.")
    print("-" * 60)

    while True:
        response = input("\nProceed with signing? [y/N]: ").strip().lower()
        if response in ("y", "yes"):
            logger.info("User confirmed to proceed despite PHI detection")
            return True
        elif response in ("n", "no", ""):
            logger.info("User aborted signing due to PHI detection")
            print("Signing cancelled by user.")
            return False
        else:
            print("Please enter 'y' or 'n'")


def _sign_real(args: argparse.Namespace, pdf_files: list[Path]) -> int:
    """Real signing with USB token."""
    # Check if PHI scanning is requested
    if getattr(args, "scan_phi", False):
        skip_confirmation = getattr(args, "yes", False)
        if not _scan_phi_for_files(pdf_files, skip_confirmation):
            return 130  # User cancelled

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

    # Get metadata fields from CLI args
    reason = getattr(args, "reason", None)
    location = getattr(args, "location", None)
    contact_info = getattr(args, "contact", None)

    batch_manager = BatchManager(nss_handler, lta_handler)

    def progress_callback(progress):
        pct = progress.percentage
        current = progress.current_file or "Completed"
        print(f"\r[{pct:5.1f}%] {current:<50}", end="", flush=True)

    print()
    result = batch_manager.sign_batch(
        pdf_files=pdf_files,
        appearance=appearance,
        cert_id=cert.info.pkcs11_id,
        progress_callback=progress_callback,
        reason=reason,
        location=location,
        contact_info=contact_info,
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
