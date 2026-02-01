"""
encryption_config.py - Configuration dataclasses for PDF encryption

Defines encryption settings and results following HIPAA compliance requirements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class EncryptionMethod(str, Enum):
    """Supported encryption methods."""

    PASSWORD = "password"
    CERTIFICATE = "certificate"


class EncryptionStrength(str, Enum):
    """Encryption strength levels (HIPAA requires minimum AES-128)."""

    AES_128 = "aes128"
    AES_256 = "aes256"


@dataclass
class PDFPermissions:
    """
    PDF permission flags (granular access control).

    HIPAA compliance: Restrict unauthorized access to ePHI.
    """

    allow_print_low_quality: bool = False
    allow_print_high_quality: bool = False
    allow_copy_content: bool = False
    allow_accessibility: bool = True  # Required for HIPAA (screen readers)
    allow_modify_content: bool = False
    allow_modify_annotations: bool = False
    allow_fill_forms: bool = False
    allow_assemble: bool = False

    def to_pymupdf_flags(self) -> int:
        """Convert to PyMuPDF permission integer."""
        import fitz

        flags = 0
        if self.allow_print_low_quality:
            flags |= fitz.PDF_PERM_PRINT
        if self.allow_print_high_quality:
            flags |= fitz.PDF_PERM_PRINT | 2048
        if self.allow_copy_content:
            flags |= fitz.PDF_PERM_COPY
        if self.allow_accessibility:
            flags |= fitz.PDF_PERM_ACCESSIBILITY
        if self.allow_modify_content:
            flags |= fitz.PDF_PERM_MODIFY
        if self.allow_modify_annotations:
            flags |= fitz.PDF_PERM_ANNOTATE
        if self.allow_fill_forms:
            flags |= fitz.PDF_PERM_FORM
        if self.allow_assemble:
            flags |= fitz.PDF_PERM_ASSEMBLE
        return flags

    @classmethod
    def hipaa_compliant_default(cls) -> "PDFPermissions":
        """HIPAA-compliant default: read-only with accessibility."""
        return cls(allow_accessibility=True)

    @classmethod
    def allow_printing_only(cls) -> "PDFPermissions":
        """Allow printing but no copying or modification."""
        return cls(
            allow_print_low_quality=True,
            allow_print_high_quality=True,
            allow_accessibility=True,
        )

    @classmethod
    def no_restrictions(cls) -> "PDFPermissions":
        """All permissions enabled."""
        return cls(
            allow_print_low_quality=True,
            allow_print_high_quality=True,
            allow_copy_content=True,
            allow_accessibility=True,
            allow_modify_content=True,
            allow_modify_annotations=True,
            allow_fill_forms=True,
            allow_assemble=True,
        )


@dataclass
class EncryptionConfig:
    """
    PDF encryption configuration.

    Supports both password-based and certificate-based encryption
    with granular permission control.
    """

    method: EncryptionMethod
    strength: EncryptionStrength = EncryptionStrength.AES_256
    permissions: PDFPermissions = field(default_factory=PDFPermissions.hipaa_compliant_default)

    # Password-based encryption
    user_password: str | None = None
    owner_password: str | None = None

    # Certificate-based encryption (X.509)
    recipient_certificates: list[bytes] = field(default_factory=list)

    # Output settings
    output_suffix: str = "_encrypted"
    overwrite_input: bool = False

    # Metadata
    encrypt_metadata: bool = True

    def validate(self) -> None:
        """Validate configuration."""
        if self.method == EncryptionMethod.PASSWORD:
            if not self.user_password and not self.owner_password:
                raise ValueError(
                    "At least one password (user or owner) required for password-based encryption"
                )
        elif self.method == EncryptionMethod.CERTIFICATE:
            if not self.recipient_certificates:
                raise ValueError(
                    "At least one recipient certificate required for certificate-based encryption"
                )


@dataclass
class EncryptionResult:
    """Result of an encryption operation."""

    success: bool
    input_path: Path
    output_path: Path | None = None
    error: str | None = None
    encrypted_at: datetime | None = None
    method_used: EncryptionMethod | None = None
    strength_used: EncryptionStrength | None = None
    permissions_applied: PDFPermissions | None = None

    def __str__(self) -> str:
        if self.success:
            return f"✓ Encrypted: {self.input_path.name} → {self.output_path.name if self.output_path else 'N/A'}"
        return f"✗ Failed: {self.input_path.name} - {self.error}"
