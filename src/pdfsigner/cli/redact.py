"""
redact.py - CLI commands for PDF redaction

Provides redact command for automatic PII removal from PDFs.
"""

import argparse
from pathlib import Path

from loguru import logger

from pdfsigner.cli.utils import collect_pdf_files
from pdfsigner.core.detection import PIIType, get_pdf_redactor


def cmd_redact(args: argparse.Namespace) -> int:
    """
    Redact PII/PHI from PDF files.

    Args:
        args: Parsed command line arguments with:
            - files: List of PDF files or directories
            - types: List of PII types to redact (or --all for all types)
            - output: Optional output file path
            - min_confidence: Minimum confidence threshold (0.0-1.0)

    Returns:
        Exit code (0 = success, 1 = error)
    """
    try:
        # Collect PDF files
        pdf_files = collect_pdf_files(args.files, getattr(args, "recursive", False))

        if not pdf_files:
            logger.error("No PDF files found")
            return 1

        # Determine PII types to redact
        if getattr(args, "all", False):
            pii_types = [t.value for t in PIIType]
            logger.info("Redacting all PII types")
        else:
            pii_types = getattr(args, "types", [])
            if not pii_types:
                logger.error("No PII types specified. Use --types or --all")
                return 1

        logger.info(f"Redacting {len(pdf_files)} file(s) for PII types: {', '.join(pii_types)}")

        # Get redactor
        redactor = get_pdf_redactor()

        # Get min confidence threshold
        min_confidence = getattr(args, "min_confidence", 0.7)

        # Redact each file
        success_count = 0
        total_redactions = 0

        for pdf_file in pdf_files:
            # Determine output path
            if hasattr(args, "output") and args.output and len(pdf_files) == 1:
                output_path = Path(args.output)
            else:
                output_path = pdf_file.with_stem(f"{pdf_file.stem}_redacted")

            logger.info(f"Processing: {pdf_file}")

            try:
                # Perform redaction
                result = redactor.redact_by_pattern(
                    pdf_path=pdf_file,
                    pii_types=pii_types,
                    output_path=output_path,
                    min_confidence=min_confidence,
                )

                if result.success:
                    success_count += 1
                    total_redactions += result.redaction_count
                    logger.info(
                        f"  ✓ Redacted {result.redaction_count} regions on "
                        f"{len(result.pages_affected)} pages → {output_path}"
                    )
                else:
                    logger.error(f"  ✗ Failed: {', '.join(result.errors)}")

            except Exception as e:
                logger.error(f"  ✗ Error processing {pdf_file}: {e}")

        # Summary
        logger.info(
            f"\nRedaction complete: {success_count}/{len(pdf_files)} files processed, "
            f"{total_redactions} total redactions"
        )

        return 0 if success_count == len(pdf_files) else 1

    except Exception as e:
        logger.exception(f"Redaction failed: {e}")
        return 1


def add_redact_parser(subparsers) -> None:
    """
    Add redact command to CLI parser.

    Args:
        subparsers: Subparser object from argparse
    """
    parser = subparsers.add_parser(
        "redact",
        help="Redact PII/PHI from PDF files",
        description="Automatically detect and redact sensitive information from PDFs",
    )

    parser.add_argument(
        "files",
        nargs="+",
        help="PDF file(s) or directory to redact",
    )

    parser.add_argument(
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

    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Redact all PII types",
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (only for single file input)",
    )

    parser.add_argument(
        "--min-confidence",
        "-c",
        type=float,
        default=0.7,
        help="Minimum confidence threshold for detection (0.0-1.0, default: 0.7)",
    )

    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively process directories",
    )

    parser.set_defaults(func=cmd_redact)
