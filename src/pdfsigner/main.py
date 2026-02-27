#!/usr/bin/env python3
"""
main.py - CLI entry point for PDFSigner

Author: Homero Thompson del Lago del Terror

CLI for signing and validating PDFs with USB token.
"""

import argparse
import sys
from pathlib import Path

from loguru import logger

from pdfsigner.cli import (
    cmd_archive_ts,
    cmd_decrypt,
    cmd_encrypt,
    cmd_list_certs,
    cmd_redact,
    cmd_scan_pii,
    cmd_sign,
    cmd_validate,
)
from pdfsigner.cli.sign import set_dry_run_mode
from pdfsigner.config.settings import get_settings


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for CLI."""
    settings = get_settings()
    logger.remove()
    level = "DEBUG" if verbose else settings.log_level
    logger.add(sys.stderr, level=level)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PDFSigner - Digital signature of PDFs with USB token",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulation mode without real token (for testing)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: sign
    sign_parser = subparsers.add_parser("sign", help="Sign PDFs")
    sign_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    sign_parser.add_argument("--visible", action="store_true", help="Visible signature")
    sign_parser.add_argument("--page", default="last", help="Page (last/first/N)")
    sign_parser.add_argument("--cert", type=int, help="Certificate number to use")
    sign_parser.add_argument("-r", "--recursive", action="store_true", help="Search in subfolders")
    sign_parser.add_argument(
        "--qr-code", action="store_true", help="Include QR verification code in stamp"
    )
    sign_parser.add_argument(
        "--reason", type=str, help="Signature reason (e.g., 'I approve this document')"
    )
    sign_parser.add_argument(
        "--location", type=str, help="Signature location (e.g., 'New York, NY')"
    )
    sign_parser.add_argument(
        "--contact", type=str, help="Contact information (e.g., 'email@company.com')"
    )
    sign_parser.add_argument(
        "--scan-phi",
        action="store_true",
        help="Scan for PHI before signing and display warning",
    )
    sign_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")

    # Command: validate
    validate_parser = subparsers.add_parser("validate", help="Validate existing signatures")
    validate_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    validate_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Search in subfolders"
    )

    # Command: list-certs
    subparsers.add_parser("list-certs", help="List certificates from token")

    # Command: archive-ts
    archive_ts_parser = subparsers.add_parser(
        "archive-ts", help="Add archive timestamp to signed PDFs"
    )
    archive_ts_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    archive_ts_parser.add_argument(
        "-o", "--output", type=Path, help="Output path (only for single file)"
    )
    archive_ts_parser.add_argument(
        "-t",
        "--tsa-url",
        action="append",
        help="TSA URL (can be repeated for fallback). If not specified, uses config.toml setting",
    )
    archive_ts_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Search in subfolders"
    )

    # Command: encrypt
    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt PDF files with password protection (AES-256)"
    )
    encrypt_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    encrypt_parser.add_argument(
        "-p", "--password", required=True, help="Encryption password (required)"
    )
    encrypt_parser.add_argument(
        "--owner-password",
        help="Owner password for full permissions (default: same as user password)",
    )
    encrypt_parser.add_argument(
        "--allow-print", action="store_true", default=True, help="Allow printing (default: True)"
    )
    encrypt_parser.add_argument("--deny-print", action="store_false", dest="allow_print")
    encrypt_parser.add_argument(
        "--allow-copy", action="store_true", default=False, help="Allow content copying"
    )
    encrypt_parser.add_argument(
        "--aes128", action="store_false", dest="aes256", help="Use AES-128 instead of AES-256"
    )
    encrypt_parser.add_argument(
        "-s", "--suffix", default="_encrypted", help="Output file suffix (default: _encrypted)"
    )
    encrypt_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Search in subfolders"
    )

    # Command: decrypt
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt password-protected PDFs")
    decrypt_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    decrypt_parser.add_argument(
        "-p", "--password", help="Decryption password (tries keyring if not provided)"
    )
    decrypt_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Search in subfolders"
    )

    # Command: scan-pii
    scan_pii_parser = subparsers.add_parser(
        "scan-pii", help="Scan PDFs for Protected Health Information (PHI) and PII"
    )
    scan_pii_parser.add_argument("file", type=Path, help="PDF file to scan")
    scan_pii_parser.add_argument(
        "-c",
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold (0.0-1.0, default: 0.7)",
    )
    scan_pii_parser.add_argument(
        "--show-values", action="store_true", help="Show redacted PII values in output"
    )
    scan_pii_parser.add_argument("--verbose", action="store_true", help="Show detailed information")

    # Command: redact
    redact_parser = subparsers.add_parser("redact", help="Automatically redact PII/PHI from PDFs")
    redact_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    redact_parser.add_argument(
        "--types",
        "-t",
        nargs="+",
        choices=[
            "ssn",
            "credit_card",
            "email",
            "phone",
            "dob",
            "date_of_birth",
            "medical_record_number",
            "health_plan_id",
            "diagnosis_code",
            "prescription",
        ],
        help="PII types to redact (e.g., ssn credit_card email)",
    )
    redact_parser.add_argument("--all", "-a", action="store_true", help="Redact all PII types")
    redact_parser.add_argument(
        "-o", "--output", type=Path, help="Output file path (only for single file input)"
    )
    redact_parser.add_argument(
        "-c",
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold (0.0-1.0, default: 0.7)",
    )
    redact_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Search in subfolders"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    # Propagate global dry-run
    if args.dry_run:
        set_dry_run_mode(True)

    # If no command, show help
    if args.command is None:
        parser.print_help()
        print("\nExamples:")
        print("  pdfsigner sign document.pdf")
        print("  pdfsigner sign ./folder/ -r --visible")
        print("  pdfsigner --dry-run sign document.pdf    # Simulate without token")
        print("  pdfsigner validate signed_document.pdf")
        print("  pdfsigner list-certs")
        print("  pdfsigner archive-ts signed_document.pdf")
        print("  pdfsigner encrypt document.pdf -p mypassword")
        print("  pdfsigner decrypt encrypted.pdf -p mypassword")
        print("  pdfsigner scan-pii document.pdf")
        print("  pdfsigner redact document.pdf --types ssn credit_card -o document_redacted.pdf")
        print("  pdfsigner redact document.pdf --all")
        return 0

    # Execute command
    commands = {
        "sign": cmd_sign,
        "validate": cmd_validate,
        "list-certs": cmd_list_certs,
        "archive-ts": cmd_archive_ts,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "scan-pii": cmd_scan_pii,
        "redact": cmd_redact,
    }

    if args.command in commands:
        return commands[args.command](args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
