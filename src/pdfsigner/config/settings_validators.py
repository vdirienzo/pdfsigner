"""
settings_validators.py - Field validators for Settings configuration

Extracted from settings.py to reduce file size.
Each function is called by a @field_validator on the Settings class.

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path


def validate_nss_path(v: Path) -> Path:
    """Validate NSS path format (existence checked at runtime by NSSChecker)."""
    # Don't validate existence here - NSS may not exist on first run
    # The NSSSetupWizard handles creating it
    return v


def validate_image_path(v: Path | None) -> Path | None:
    """Validate that signature image exists if specified."""
    if v is not None and not v.exists():
        raise ValueError(f"Signature image does not exist: {v}")
    return v


def validate_output_suffix(v: str) -> str:
    """Validate output suffix to prevent path traversal."""
    from pdfsigner.core.security.path_sanitizer import (
        PathTraversalError,
        sanitize_output_suffix,
    )

    try:
        return sanitize_output_suffix(v)
    except PathTraversalError as e:
        raise ValueError(str(e)) from e


def validate_signature_template(v: str) -> str:
    """Validate signature template name to prevent path traversal."""
    if not v:
        return v  # Empty string is valid (means default template)

    from pdfsigner.core.security.path_sanitizer import (
        PathTraversalError,
        sanitize_filename,
    )

    try:
        return sanitize_filename(v, allow_subdirs=False)
    except PathTraversalError as e:
        raise ValueError(str(e)) from e
