"""Example usage of ArchiveTimestampManager for PAdES-LTA compliance."""

from pathlib import Path

from loguru import logger

from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager
from pdfsigner.exceptions import TSAConnectionError


def main():
    """Demonstrate archive timestamp management."""
    # Example TSA URLs (in priority order for fallback)
    tsa_urls = [
        "http://timestamp.digicert.com",
        "http://timestamp.globalsign.com/tsa/r6advanced1",
        "http://tsa.startssl.com/rfc3161",
    ]

    # Initialize manager with multiple TSAs
    manager = ArchiveTimestampManager(
        tsa_urls=tsa_urls,
        timeout=30,  # 30 seconds per TSA request
    )

    pdf_path = Path("signed_document.pdf")

    # Check if PDF needs a new archive timestamp
    try:
        if manager.needs_archive_timestamp(pdf_path, algorithm_threshold_years=10):
            logger.info("PDF needs a new archive timestamp")

            # Add archive timestamp (with automatic TSA fallback)
            output_path = manager.add_archive_timestamp(
                pdf_path=pdf_path,
                output_path=pdf_path.with_stem(f"{pdf_path.stem}_archival"),
            )

            logger.info(f"Archive timestamp added: {output_path}")
        else:
            logger.info("PDF archive timestamp is still valid")

    except TSAConnectionError as e:
        logger.error(f"Failed to add archive timestamp: {e}")
        return 1

    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        return 1

    # Get information about existing archive timestamps
    timestamps = manager.get_archive_timestamps(pdf_path)

    logger.info(f"Found {len(timestamps)} archive timestamp(s)")
    for idx, ts in enumerate(timestamps, 1):
        logger.info(f"Archive TS #{idx}:")
        logger.info(f"  Timestamp: {ts.timestamp}")
        logger.info(f"  TSA URL: {ts.tsa_url or 'Unknown'}")
        logger.info(f"  Hash Algorithm: {ts.hash_algorithm}")
        logger.info(f"  Covers DSS: {ts.covers_dss}")

    return 0


if __name__ == "__main__":
    exit(main())
