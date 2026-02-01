"""
archive_ts.py - CLI archive timestamp command

Author: Homero Thompson del Lago del Terror

Implements the 'archive-ts' command to add archive timestamps to signed PDFs.
"""

import argparse

from loguru import logger

from pdfsigner.cli.utils import collect_pdf_files
from pdfsigner.config.settings import get_settings
from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager
from pdfsigner.exceptions import TSAConnectionError


def cmd_archive_ts(args: argparse.Namespace) -> int:
    """Archive timestamp command."""
    pdf_files = collect_pdf_files(args.files, args.recursive)

    if not pdf_files:
        logger.error("No PDF files to timestamp")
        return 1

    # Get TSA URLs from CLI args or settings
    tsa_urls = args.tsa_url if args.tsa_url else []

    # If no CLI TSA URLs, try settings
    if not tsa_urls:
        settings = get_settings()
        if settings.tsa_url:
            tsa_urls = [settings.tsa_url]

    # Check if any TSA URLs are available
    if not tsa_urls:
        logger.error("No TSA URL configured. Use --tsa-url or configure in settings")
        return 1

    # Initialize manager with TSA URLs
    manager = ArchiveTimestampManager(tsa_urls=tsa_urls)

    successful = 0
    failed = 0

    for pdf_path in pdf_files:
        try:
            # Determine output path
            if args.output and len(pdf_files) == 1:
                output_path = args.output
            else:
                # For multiple files or no output specified, overwrite input
                output_path = None

            logger.info(f"Adding archive timestamp to {pdf_path.name}...")
            result_path = manager.add_archive_timestamp(pdf_path, output_path)

            print(f"✓ {pdf_path.name}: Archive timestamp added")
            if output_path and output_path != pdf_path:
                print(f"  → Saved to: {result_path}")

            successful += 1

        except TSAConnectionError as e:
            print(f"✗ {pdf_path.name}: TSA error - {e}")
            logger.error(f"TSA connection failed for {pdf_path}: {e}")
            failed += 1

        except FileNotFoundError as e:
            print(f"✗ {pdf_path.name}: File not found - {e}")
            logger.error(f"File not found: {e}")
            failed += 1

        except Exception as e:
            print(f"✗ {pdf_path.name}: Error - {e}")
            logger.error(f"Failed to add archive timestamp to {pdf_path}: {e}")
            failed += 1

    # Summary
    total = len(pdf_files)
    print(f"\nTotal: {total} file(s), {successful} successful, {failed} failed")

    return 0 if failed == 0 else 1
