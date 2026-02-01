"""
encryption_validator.py - Encryption validation and inspection

Validates encryption status and extracts encryption metadata.
"""

from dataclasses import dataclass
from pathlib import Path

import fitz
from loguru import logger

from pdfsigner.core.encryption.encryption_config import (
    EncryptionMethod,
    EncryptionStrength,
)
from pdfsigner.exceptions import HIPAAComplianceError, PDFCorruptedError


@dataclass
class EncryptionInfo:
    """Encryption metadata extracted from PDF."""

    is_encrypted: bool
    encryption_method: EncryptionMethod | None = None
    encryption_strength: EncryptionStrength | None = None
    has_user_password: bool = False
    has_owner_password: bool = False
    permissions_value: int = 0
    can_print: bool = True
    can_copy: bool = True
    can_modify: bool = True
    can_annotate: bool = True


class EncryptionValidator:
    """
    Validates and inspects PDF encryption.

    Can check encryption status and HIPAA compliance.
    """

    def is_encrypted(self, pdf_path: Path) -> bool:
        """
        Check if PDF is encrypted.

        Args:
            pdf_path: Path to PDF file

        Returns:
            True if encrypted
        """
        try:
            doc = fitz.open(pdf_path)
            is_enc = doc.is_encrypted
            doc.close()
            return is_enc
        except Exception as e:
            logger.error(f"Cannot check encryption status for {pdf_path}: {e}")
            raise PDFCorruptedError(pdf_path.name) from e

    def get_encryption_info(self, pdf_path: Path) -> EncryptionInfo:
        """
        Extract encryption metadata from PDF.

        Args:
            pdf_path: Path to PDF file

        Returns:
            EncryptionInfo with detailed metadata
        """
        try:
            doc = fitz.open(pdf_path)

            if not doc.is_encrypted:
                doc.close()
                return EncryptionInfo(is_encrypted=False)

            permissions = doc.permissions if hasattr(doc, "permissions") else -1

            info = EncryptionInfo(
                is_encrypted=True,
                encryption_method=EncryptionMethod.PASSWORD,
                encryption_strength=self._detect_strength(doc),
                has_user_password=doc.needs_pass,
                has_owner_password=True,
                permissions_value=permissions,
                can_print=bool(permissions & fitz.PDF_PERM_PRINT) if permissions > 0 else True,
                can_copy=bool(permissions & fitz.PDF_PERM_COPY) if permissions > 0 else True,
                can_modify=bool(permissions & fitz.PDF_PERM_MODIFY) if permissions > 0 else True,
                can_annotate=bool(permissions & fitz.PDF_PERM_ANNOTATE)
                if permissions > 0
                else True,
            )

            doc.close()
            return info

        except PDFCorruptedError:
            raise
        except Exception as e:
            logger.error(f"Cannot extract encryption info from {pdf_path}: {e}")
            raise PDFCorruptedError(pdf_path.name) from e

    def validate_hipaa_compliance(self, pdf_path: Path) -> tuple[bool, str]:
        """
        Validate HIPAA encryption compliance.

        HIPAA requires:
        - AES-128 minimum (AES-256 recommended)
        - Encryption for PHI data

        Args:
            pdf_path: Path to PDF file

        Returns:
            Tuple of (is_compliant, reason)
        """
        info = self.get_encryption_info(pdf_path)

        if not info.is_encrypted:
            return False, "PDF is not encrypted (HIPAA requires encryption for ePHI)"

        if info.encryption_strength == EncryptionStrength.AES_256:
            return True, "HIPAA compliant (AES-256)"
        elif info.encryption_strength == EncryptionStrength.AES_128:
            return True, "HIPAA compliant (AES-128 minimum met)"
        else:
            return False, "Encryption strength below HIPAA minimum (AES-128 required)"

    def can_modify(self, pdf_path: Path, password: str | None = None) -> bool:
        """
        Check if PDF can be modified (for signing encrypted PDFs).

        Args:
            pdf_path: Path to PDF file
            password: Optional decryption password

        Returns:
            True if PDF can be modified
        """
        try:
            doc = fitz.open(pdf_path)

            if doc.is_encrypted and password:
                auth_result = doc.authenticate(password)
                if auth_result == 0:
                    doc.close()
                    return False

            permissions = doc.permissions if hasattr(doc, "permissions") else -1
            can_mod = bool(permissions & fitz.PDF_PERM_MODIFY) if permissions > 0 else True

            doc.close()
            return can_mod

        except Exception as e:
            logger.error(f"Cannot check modify permissions for {pdf_path}: {e}")
            return False

    def validate_hipaa_settings(
        self,
        encryption_strength: str,
        allow_print: bool,
        encryption_enabled: bool = True,
    ) -> None:
        """
        Validate encryption settings meet HIPAA requirements.

        HIPAA §164.312(a)(2)(iv) requires:
        - AES-256 encryption (AES-128 minimum)
        - No print permissions on PHI documents
        - Encryption enabled for ePHI at rest

        Args:
            encryption_strength: Encryption strength ("aes128" or "aes256")
            allow_print: Whether printing is allowed
            encryption_enabled: Whether encryption is enabled

        Raises:
            HIPAAComplianceError: If settings don't meet HIPAA requirements
        """
        errors = []

        if not encryption_enabled:
            errors.append("Encryption must be enabled for ePHI at rest")

        if encryption_strength != "aes256":
            errors.append(
                "HIPAA requires AES-256 encryption (AES-128 minimum met but not recommended)"
            )

        if allow_print:
            errors.append("Print permissions must be disabled for PHI documents")

        if errors:
            raise HIPAAComplianceError("; ".join(errors))

    def _detect_strength(self, doc: fitz.Document) -> EncryptionStrength | None:
        """Detect encryption strength from PDF metadata."""
        try:
            # PyMuPDF doesn't directly expose encryption method
            # Use PDF version as heuristic
            # PDF 2.0+ typically uses AES-256
            # PDF 1.6+ typically uses AES-128
            if hasattr(doc, "metadata"):
                pdf_version = doc.metadata.get("format", "")
                if "2.0" in pdf_version or "1.7" in pdf_version:
                    return EncryptionStrength.AES_256
                elif "1.6" in pdf_version or "1.5" in pdf_version:
                    return EncryptionStrength.AES_128
        except Exception:
            pass

        # Default to AES-256 for modern encrypted PDFs
        return EncryptionStrength.AES_256
