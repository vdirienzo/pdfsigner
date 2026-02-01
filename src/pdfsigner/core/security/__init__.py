"""
security - Security utilities for PDFSigner

Author: Homero Thompson del Lago del Terror

Provides path sanitization, credential management, schema validation,
and secure temporary file handling with HIPAA-compliant deletion.
"""

from pdfsigner.core.security.cleanup_scheduler import (
    CleanupScheduler,
    CleanupTask,
    get_cleanup_scheduler,
)
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
from pdfsigner.core.security.secure_temp import (
    SecureTempDirectory,
    SecureTempFile,
    TempFileInfo,
    secure_temp_directory,
    secure_temp_file,
)
from pdfsigner.core.security.template_validator import (
    TEMPLATE_SCHEMA,
    TemplateValidationError,
    validate_template_data,
    validate_template_file,
    validate_template_strict,
)
from pdfsigner.core.security.vuln_report import VulnReporter, get_vuln_reporter
from pdfsigner.core.security.vuln_repository import VulnRepository, get_vuln_repository
from pdfsigner.core.security.vuln_scanner import (
    PipAuditScanner,
    ScannerNotAvailableError,
    SemgrepScanner,
    run_all_scans,
)
from pdfsigner.core.security.vuln_tracker import VulnTracker, get_vuln_tracker
from pdfsigner.core.security.vuln_types import (
    Vulnerability,
    VulnSeverity,
    VulnSource,
    VulnStatus,
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
    # Secure temp file handling
    "SecureTempFile",
    "SecureTempDirectory",
    "TempFileInfo",
    "secure_temp_file",
    "secure_temp_directory",
    # Cleanup scheduling
    "CleanupScheduler",
    "CleanupTask",
    "get_cleanup_scheduler",
    # Vulnerability management
    "Vulnerability",
    "VulnSeverity",
    "VulnSource",
    "VulnStatus",
    "VulnRepository",
    "get_vuln_repository",
    "VulnTracker",
    "get_vuln_tracker",
    "VulnReporter",
    "get_vuln_reporter",
    "SemgrepScanner",
    "PipAuditScanner",
    "ScannerNotAvailableError",
    "run_all_scans",
]
