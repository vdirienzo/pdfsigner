"""
security - Security utilities for PDFSigner

Author: Homero Thompson del Lago del Terror

Provides path sanitization, credential management, and schema validation.
"""

from pdfsigner.core.security.credential_manager import (
    CredentialManager,
    TSACredentials,
    get_credential_manager,
)
from pdfsigner.core.security.path_sanitizer import (
    PathTraversalError,
    sanitize_filename,
    sanitize_output_suffix,
    sanitize_path,
    validate_path_within_base,
)
from pdfsigner.core.security.template_validator import (
    TEMPLATE_SCHEMA,
    TemplateValidationError,
    validate_template_data,
    validate_template_file,
    validate_template_strict,
)

__all__ = [
    # Path sanitization
    "PathTraversalError",
    "sanitize_filename",
    "sanitize_output_suffix",
    "sanitize_path",
    "validate_path_within_base",
    # Template validation
    "TEMPLATE_SCHEMA",
    "TemplateValidationError",
    "validate_template_data",
    "validate_template_file",
    "validate_template_strict",
    # Credential management
    "CredentialManager",
    "TSACredentials",
    "get_credential_manager",
]
