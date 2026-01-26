"""
path_sanitizer.py - Path traversal prevention utilities

Author: Homero Thompson del Lago del Terror

Provides functions to sanitize file paths and prevent path traversal attacks.
These attacks exploit user input containing sequences like "../" to access
files outside the intended directory.
"""

from __future__ import annotations

import re
from pathlib import Path

from loguru import logger


class PathTraversalError(Exception):
    """Raised when a path traversal attack is detected."""

    pass


def validate_path_within_base(path: Path, base_dir: Path, path_description: str = "path") -> Path:
    """
    Validate that a path resolves within a base directory.

    This is the primary defense against path traversal attacks.
    Uses Path.resolve() to canonicalize the path (resolve symlinks, ../, etc.)
    then verifies it's still within the allowed base directory.

    Args:
        path: The path to validate (can be relative or absolute)
        base_dir: The base directory that path must be within
        path_description: Description for error messages (e.g., "template image")

    Returns:
        The resolved absolute path

    Raises:
        PathTraversalError: If the resolved path is outside base_dir
    """
    resolved_base = base_dir.resolve()
    resolved_path = (base_dir / path).resolve() if not path.is_absolute() else path.resolve()

    try:
        # Python 3.9+ has is_relative_to()
        if not resolved_path.is_relative_to(resolved_base):
            logger.warning(
                f"Path traversal attempt blocked: {path_description}='{path}' "
                f"resolved to '{resolved_path}' which is outside '{resolved_base}'"
            )
            raise PathTraversalError(f"Invalid {path_description}: path escapes base directory")
    except ValueError:
        # is_relative_to() raises ValueError for paths on different drives (Windows)
        raise PathTraversalError(f"Invalid {path_description}: path escapes base directory")

    return resolved_path


def sanitize_filename(filename: str, allow_subdirs: bool = False) -> str:
    """
    Sanitize a filename to prevent path traversal.

    Removes or replaces dangerous characters and sequences:
    - Parent directory references (..)
    - Absolute path prefixes (/ or C:)
    - Null bytes and other control characters
    - Optionally, all path separators

    Args:
        filename: The filename to sanitize
        allow_subdirs: If True, allows forward slashes (for relative paths like "images/logo.png")

    Returns:
        Sanitized filename

    Raises:
        PathTraversalError: If the filename contains path traversal sequences
    """
    if not filename:
        raise PathTraversalError("Empty filename not allowed")

    # Check for null bytes (common attack vector)
    if "\x00" in filename:
        raise PathTraversalError("Null bytes not allowed in filename")

    # Check for path traversal sequences
    if ".." in filename:
        raise PathTraversalError("Parent directory references (..) not allowed in filename")

    # Check for absolute paths
    if filename.startswith("/") or (len(filename) > 1 and filename[1] == ":"):
        raise PathTraversalError("Absolute paths not allowed in filename")

    # Check for backslash (Windows path separator, also dangerous on Linux)
    if "\\" in filename:
        raise PathTraversalError("Backslashes not allowed in filename")

    if not allow_subdirs and "/" in filename:
        raise PathTraversalError("Path separators not allowed in filename")

    # Remove control characters except for common whitespace
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", filename)

    if not sanitized or sanitized != filename:
        logger.warning(f"Filename sanitized: '{filename}' -> '{sanitized}'")

    return sanitized


def sanitize_path(
    path: str | Path,
    base_dir: Path,
    must_exist: bool = False,
    path_description: str = "path",
) -> Path:
    """
    Sanitize and validate a path relative to a base directory.

    Combines filename sanitization with path validation.

    Args:
        path: The path to sanitize (as string or Path)
        base_dir: The base directory that the final path must be within
        must_exist: If True, raises error if the resolved path doesn't exist
        path_description: Description for error messages

    Returns:
        Resolved absolute path within base_dir

    Raises:
        PathTraversalError: If the path contains traversal sequences or escapes base_dir
        FileNotFoundError: If must_exist=True and the path doesn't exist
    """
    # Convert to string for initial checks
    path_str = str(path)

    # Basic sanitization checks
    if not path_str:
        raise PathTraversalError(f"Empty {path_description} not allowed")

    if "\x00" in path_str:
        raise PathTraversalError(f"Null bytes not allowed in {path_description}")

    # Check for backslash
    if "\\" in path_str:
        raise PathTraversalError(f"Backslashes not allowed in {path_description}")

    # Create Path object and validate
    path_obj = Path(path_str)

    # Prevent absolute paths (must be relative to base_dir)
    if path_obj.is_absolute():
        raise PathTraversalError(f"Absolute paths not allowed for {path_description}")

    # Validate within base directory
    resolved = validate_path_within_base(path_obj, base_dir, path_description)

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"{path_description} not found: {resolved}")

    return resolved


def sanitize_output_suffix(suffix: str) -> str:
    """
    Sanitize an output filename suffix.

    Ensures the suffix doesn't contain path separators or traversal sequences.

    Args:
        suffix: The suffix to sanitize (e.g., "_signed")

    Returns:
        The validated suffix

    Raises:
        PathTraversalError: If the suffix is invalid
    """
    if not suffix:
        return ""

    # Check for dangerous characters
    if "/" in suffix or "\\" in suffix:
        raise PathTraversalError("Path separators not allowed in output suffix")

    if ".." in suffix:
        raise PathTraversalError("Parent directory references not allowed in output suffix")

    if "\x00" in suffix:
        raise PathTraversalError("Null bytes not allowed in output suffix")

    # Ensure it starts with allowed characters
    if not re.match(r"^[_\-a-zA-Z0-9]", suffix):
        raise PathTraversalError(
            "Output suffix must start with alphanumeric, underscore, or hyphen"
        )

    return suffix
