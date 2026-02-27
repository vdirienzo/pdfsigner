"""
upload_handler.py - File upload handling for PDF signing API

Handles file validation, sanitization, and streaming to temp storage.
"""

import asyncio
import os
import tempfile
from pathlib import Path

from fastapi import HTTPException, UploadFile, status
from loguru import logger

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.services.signing_service import SigningService
from pdfsigner.api.utils import sanitize_filename


async def validate_and_save_upload(
    file: UploadFile,
    username: str,
) -> tuple[str, Path]:
    """
    Validate uploaded file and save to temp storage.

    Performs filename sanitization, PDF extension check, size limit check,
    streaming to temp file, and PDF content validation.

    Args:
        file: Uploaded file from request
        username: Username for temp file prefix

    Returns:
        Tuple of (sanitized_filename, temp_file_path)

    Raises:
        HTTPException: 400 if file is invalid
        HTTPException: 413 if file exceeds size limit
        HTTPException: 500 if save fails
    """
    safe_filename = _validate_filename(file.filename)
    temp_path = await _stream_to_temp(file, username)

    try:
        await _validate_pdf_content(temp_path, safe_filename)
    except HTTPException:
        os.unlink(str(temp_path))
        raise

    return safe_filename, temp_path


def _validate_filename(filename: str | None) -> str:
    """
    Validate and sanitize the uploaded filename.

    Args:
        filename: Original filename from upload

    Returns:
        Sanitized filename string

    Raises:
        HTTPException: 400 if filename is missing or invalid
    """
    if not filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required",
        )

    try:
        safe_filename = sanitize_filename(filename)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid filename: {e}",
        ) from e

    if not safe_filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF files are accepted",
        )

    return safe_filename


async def _stream_to_temp(file: UploadFile, username: str) -> Path:
    """
    Stream uploaded file to temp directory in chunks.

    Avoids loading entire PDF in memory.

    Args:
        file: Uploaded file
        username: Username for temp file prefix

    Returns:
        Path to temp file

    Raises:
        HTTPException: 400 if file is empty
        HTTPException: 413 if file exceeds size limit
        HTTPException: 500 if save fails
    """
    settings = get_api_settings()
    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    temp_dir = settings.temp_dir
    temp_dir.mkdir(parents=True, exist_ok=True)

    temp_fd, temp_path_str = tempfile.mkstemp(
        suffix=".pdf",
        prefix=f"upload_{username}_",
        dir=str(temp_dir),
    )
    temp_path = Path(temp_path_str)

    try:
        total_size = 0
        with open(temp_fd, "wb") as f:
            while chunk := await file.read(8192):
                total_size += len(chunk)
                if total_size > max_size_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File size exceeds maximum ({settings.max_upload_size_mb}MB)",
                    )
                f.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        logger.debug(f"Saved uploaded file to {temp_path} ({total_size} bytes)")

    except HTTPException:
        os.unlink(temp_path_str)
        raise
    except Exception as e:
        os.unlink(temp_path_str)
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file",
        ) from e

    return temp_path


async def _validate_pdf_content(temp_path: Path, filename: str) -> None:
    """
    Validate PDF content using magic bytes and MIME type detection.

    Args:
        temp_path: Path to temp file
        filename: Original filename

    Raises:
        HTTPException: 400 if not a valid PDF
    """
    try:
        file_content = await asyncio.to_thread(temp_path.read_bytes)
        SigningService.validate_pdf_file(file_content, filename)
        del file_content  # Free memory after validation
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
