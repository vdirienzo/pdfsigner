"""
encrypt.py - CLI commands for PDF encryption

Provides encrypt and decrypt commands for the pdfsigner CLI.
"""

import argparse
from pathlib import Path

from loguru import logger

from pdfsigner.cli.utils import collect_pdf_files
from pdfsigner.config.settings import get_settings
from pdfsigner.core.encryption import (
    EncryptionConfig,
    EncryptionMethod,
    EncryptionStrength,
    PDFEncryptor,
    PDFPermissions,
)
from pdfsigner.exceptions import PasswordIncorrectError, PDFEncryptionError


def cmd_encrypt(args: argparse.Namespace) -> int:
    """
    Encrypt PDF files with password protection.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        # Collect PDF files
        pdf_files = collect_pdf_files(args.files, getattr(args, "recursive", False))

        if not pdf_files:
            logger.error("No PDF files found")
            return 1

        logger.info(f"Encrypting {len(pdf_files)} file(s)")

        # Get settings
        settings = get_settings()

        # Build permissions
        permissions = PDFPermissions(
            allow_print_low_quality=getattr(
                args, "allow_print", settings.encryption_default_allow_print
            ),
            allow_print_high_quality=getattr(
                args, "allow_print", settings.encryption_default_allow_print
            ),
            allow_copy_content=getattr(args, "allow_copy", settings.encryption_default_allow_copy),
            allow_accessibility=True,  # Always enabled for HIPAA
        )

        # Build config
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
            strength=EncryptionStrength.AES_256
            if getattr(args, "aes256", True)
            else EncryptionStrength.AES_128,
            user_password=args.password,
            owner_password=getattr(args, "owner_password", None) or args.password,
            permissions=permissions,
            output_suffix=getattr(args, "suffix", settings.encryption_output_suffix),
        )

        # Encrypt
        encryptor = PDFEncryptor()
        results = encryptor.encrypt_batch(pdf_files, config)

        # Report results
        success_count = sum(1 for r in results if r.success)

        for result in results:
            if result.success:
                output = result.output_path.name if result.output_path else "N/A"
                print(f"✓ {result.input_path.name} → {output}")
            else:
                print(f"✗ {result.input_path.name}: {result.error}")

        print(f"\nEncrypted: {success_count}/{len(results)}")

        return 0 if success_count == len(results) else 1

    except PDFEncryptionError as e:
        logger.error(f"Encryption error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nCancelled")
        return 130
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


def cmd_decrypt(args: argparse.Namespace) -> int:
    """
    Decrypt password-protected PDF files.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        # Collect PDF files
        pdf_files = collect_pdf_files(args.files, getattr(args, "recursive", False))

        if not pdf_files:
            logger.error("No PDF files found")
            return 1

        logger.info(f"Decrypting {len(pdf_files)} file(s)")

        encryptor = PDFEncryptor()
        success_count = 0

        for pdf_file in pdf_files:
            try:
                result = encryptor.decrypt(
                    pdf_file,
                    password=getattr(args, "password", None),
                )

                if result.success:
                    output = result.output_path.name if result.output_path else "decrypted"
                    print(f"✓ {pdf_file.name} → {output}")
                    success_count += 1
                else:
                    print(f"✗ {pdf_file.name}: {result.error}")

            except PasswordIncorrectError:
                print(f"✗ {pdf_file.name}: Incorrect password")
            except Exception as e:
                print(f"✗ {pdf_file.name}: {e}")

        print(f"\nDecrypted: {success_count}/{len(pdf_files)}")

        return 0 if success_count == len(pdf_files) else 1

    except KeyboardInterrupt:
        print("\nCancelled")
        return 130
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


def setup_encrypt_parser(subparsers: argparse._SubParsersAction) -> None:
    """
    Setup encrypt and decrypt subcommands.

    Args:
        subparsers: Subparsers from main argument parser
    """
    # Encrypt command
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt PDF files with password protection (AES-256)",
        description="Encrypt one or more PDF files using AES-256 encryption.",
    )
    encrypt_parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="PDF files or directories to encrypt",
    )
    encrypt_parser.add_argument(
        "-p",
        "--password",
        required=True,
        help="Encryption password (required)",
    )
    encrypt_parser.add_argument(
        "--owner-password",
        help="Owner password for full permissions (default: same as user password)",
    )
    encrypt_parser.add_argument(
        "--allow-print",
        action="store_true",
        default=True,
        help="Allow printing (default: True)",
    )
    encrypt_parser.add_argument(
        "--deny-print",
        action="store_false",
        dest="allow_print",
        help="Deny printing",
    )
    encrypt_parser.add_argument(
        "--allow-copy",
        action="store_true",
        default=False,
        help="Allow content copying (default: False)",
    )
    encrypt_parser.add_argument(
        "--aes128",
        action="store_false",
        dest="aes256",
        help="Use AES-128 instead of AES-256",
    )
    encrypt_parser.add_argument(
        "-s",
        "--suffix",
        default="_encrypted",
        help="Output file suffix (default: _encrypted)",
    )
    encrypt_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Process subdirectories recursively",
    )
    encrypt_parser.set_defaults(func=cmd_encrypt)

    # Decrypt command
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt password-protected PDF files",
        description="Decrypt one or more password-protected PDF files.",
    )
    decrypt_parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="PDF files or directories to decrypt",
    )
    decrypt_parser.add_argument(
        "-p",
        "--password",
        help="Decryption password (tries keyring if not provided)",
    )
    decrypt_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Process subdirectories recursively",
    )
    decrypt_parser.set_defaults(func=cmd_decrypt)
