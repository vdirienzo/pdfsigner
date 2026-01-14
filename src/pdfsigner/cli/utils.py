"""
utils.py - Shared CLI utilities

Author: Homero Thompson del Lago del Terror

Shared functions between CLI commands.
"""

import getpass
from pathlib import Path

from loguru import logger


def get_pin_from_user() -> str:
    """Request PIN from console."""
    return getpass.getpass("Enter token PIN: ")


def collect_pdf_files(paths: list[Path], recursive: bool = False) -> list[Path]:
    """
    Collect PDF files from paths (files or directories).

    Args:
        paths: List of paths (files or directories)
        recursive: Search recursively in directories

    Returns:
        List of PDF files found
    """
    pdf_files = []

    for path in paths:
        if path.is_file():
            if path.suffix.lower() == ".pdf":
                pdf_files.append(path)
            else:
                logger.warning(f"Ignoring non-PDF file: {path}")
        elif path.is_dir():
            pattern = "**/*.pdf" if recursive else "*.pdf"
            found = list(path.glob(pattern))
            logger.info(f"Found {len(found)} PDFs in {path}")
            pdf_files.extend(found)
        else:
            logger.error(f"Path does not exist: {path}")

    return sorted(set(pdf_files))
