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

from pdfsigner.cli import cmd_list_certs, cmd_sign, cmd_validate
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
        "--location", type=str, help="Signature location (e.g., 'Buenos Aires, Argentina')"
    )
    sign_parser.add_argument(
        "--contact", type=str, help="Contact information (e.g., 'email@company.com')"
    )

    # Command: validate
    validate_parser = subparsers.add_parser("validate", help="Validate existing signatures")
    validate_parser.add_argument("files", nargs="+", type=Path, help="Files or folders")
    validate_parser.add_argument(
        "-r", "--recursive", action="store_true", help="Search in subfolders"
    )

    # Command: list-certs
    subparsers.add_parser("list-certs", help="List certificates from token")

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
        return 0

    # Execute command
    commands = {
        "sign": cmd_sign,
        "validate": cmd_validate,
        "list-certs": cmd_list_certs,
    }

    if args.command in commands:
        return commands[args.command](args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
