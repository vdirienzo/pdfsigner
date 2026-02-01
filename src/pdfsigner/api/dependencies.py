"""
Dependency injection functions for FastAPI.

These functions provide common dependencies used across API endpoints.
"""

import tempfile
from collections.abc import Generator
from pathlib import Path

from fastapi import Depends

from pdfsigner.api.config import APISettings, get_api_settings


def get_settings() -> APISettings:
    """
    Get API settings dependency.

    Returns:
        API settings instance

    Example:
        ```python
        @app.get("/example")
        def example_endpoint(settings: APISettings = Depends(get_settings)):
            return {"max_upload_mb": settings.max_upload_size_mb}
        ```
    """
    return get_api_settings()


def get_temp_dir(settings: APISettings = Depends(get_settings)) -> Path:
    """
    Get temporary directory for file uploads.

    Args:
        settings: API settings (injected)

    Returns:
        Path to temporary directory

    Example:
        ```python
        @app.post("/upload")
        def upload(temp_dir: Path = Depends(get_temp_dir)):
            file_path = temp_dir / "upload.pdf"
            # ... save file
        ```
    """
    temp_dir = settings.temp_dir
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def get_temp_file(
    suffix: str = ".pdf",
    temp_dir: Path = Depends(get_temp_dir),
) -> Generator[Path, None, None]:
    """
    Create a temporary file and clean it up after use.

    Args:
        suffix: File extension (default: .pdf)
        temp_dir: Temporary directory (injected)

    Yields:
        Path to temporary file

    Example:
        ```python
        @app.post("/process")
        def process(temp_file: Path = Depends(get_temp_file)):
            temp_file.write_bytes(uploaded_data)
            # ... process file
            # File is automatically deleted after request
        ```
    """
    with tempfile.NamedTemporaryFile(
        suffix=suffix,
        dir=temp_dir,
        delete=False,
    ) as tmp:
        temp_path = Path(tmp.name)

    try:
        yield temp_path
    finally:
        cleanup_temp_file(temp_path)


def cleanup_temp_file(file_path: Path) -> None:
    """
    Safely delete a temporary file.

    Args:
        file_path: Path to file to delete

    Note:
        Silently ignores if file doesn't exist or can't be deleted.
    """
    try:
        if file_path.exists():
            file_path.unlink()
    except Exception:
        # Silently ignore cleanup errors
        # File will be removed by periodic cleanup task
        pass


def cleanup_temp_directory(
    temp_dir: Path,
    max_age_hours: int = 24,
) -> tuple[int, int]:
    """
    Clean up old files in temporary directory.

    Args:
        temp_dir: Directory to clean
        max_age_hours: Maximum file age in hours

    Returns:
        Tuple of (files_removed, errors)

    Example:
        ```python
        # In background task or cron job
        removed, errors = cleanup_temp_directory(
            Path("/tmp/pdfsigner-api"),
            max_age_hours=24
        )
        ```
    """
    import time

    if not temp_dir.exists():
        return 0, 0

    cutoff_time = time.time() - (max_age_hours * 3600)
    removed = 0
    errors = 0

    for file_path in temp_dir.iterdir():
        if not file_path.is_file():
            continue

        try:
            if file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
                removed += 1
        except Exception:
            errors += 1

    return removed, errors
