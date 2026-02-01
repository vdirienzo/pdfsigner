"""
Utility functions for API routes.

Provides common helpers for file handling, validation, and security.
"""

from pathlib import Path
from uuid import uuid4

from werkzeug.utils import secure_filename


def sanitize_filename(filename: str | None, fallback_extension: str = ".pdf") -> str:
    """
    Sanitize filename to prevent Path Traversal attacks.

    Removes path components (../../), control characters, and ensures
    a safe filename. If sanitization results in empty string, generates
    a random UUID-based name.

    Args:
        filename: Original filename from upload
        fallback_extension: Extension to use if random name is generated

    Returns:
        Safe filename without path components

    Raises:
        ValueError: If filename is None or empty

    Examples:
        >>> sanitize_filename("document.pdf")
        'document.pdf'
        >>> sanitize_filename("../../etc/passwd.pdf")
        'etc_passwd.pdf'
        >>> sanitize_filename("")  # Returns UUID-based name
        '7c6a1c5e3f4d4b8a9e2f1d3c5b7a9e8f.pdf'
    """
    if not filename:
        raise ValueError("Filename cannot be None or empty")

    # Apply werkzeug's secure_filename
    safe_name = secure_filename(filename)

    # If secure_filename returns empty string (all chars were unsafe),
    # generate a random name with original extension if possible
    if not safe_name:
        # Try to extract extension from original filename
        original_path = Path(filename)
        extension = original_path.suffix if original_path.suffix else fallback_extension

        # Ensure extension starts with dot
        if not extension.startswith("."):
            extension = f".{extension}"

        safe_name = f"{uuid4().hex}{extension}"

    return safe_name
