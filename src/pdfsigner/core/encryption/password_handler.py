"""
password_handler.py - Password-based PDF encryption

Implements password-based encryption using PyMuPDF (AES-256).
"""

from datetime import UTC, datetime
from pathlib import Path

import fitz
from loguru import logger

from pdfsigner.core.audit import log_encryption_event
from pdfsigner.core.encryption.encryption_config import (
    EncryptionConfig,
    EncryptionMethod,
    EncryptionResult,
    EncryptionStrength,
)
from pdfsigner.exceptions import (
    PasswordIncorrectError,
    PDFCorruptedError,
    PDFEncryptionError,
)


class PasswordEncryptionHandler:
    """
    Password-based encryption using PyMuPDF.

    Supports AES-128 and AES-256 with granular permissions.
    """

    def encrypt(
        self,
        input_path: Path,
        output_path: Path,
        config: EncryptionConfig,
    ) -> EncryptionResult:
        """
        Encrypt PDF with password.

        Args:
            input_path: Input PDF path
            output_path: Output PDF path
            config: Encryption configuration

        Returns:
            EncryptionResult

        Raises:
            PDFCorruptedError: If PDF is invalid
            PDFEncryptionError: If encryption fails
        """
        try:
            if config.method != EncryptionMethod.PASSWORD:
                raise ValueError(f"Expected PASSWORD method, got {config.method}")

            logger.info(f"Encrypting PDF: {input_path.name} → {output_path.name}")

            # Open PDF
            doc = fitz.open(input_path)
            try:
                # Validate PDF
                if doc.is_closed or doc.page_count == 0:
                    raise PDFCorruptedError(input_path.name)

                # Check if already encrypted
                if doc.is_encrypted:
                    raise PDFEncryptionError(f"PDF '{input_path.name}' is already encrypted")

                # Map encryption strength
                encrypt_method = self._map_encryption_strength(config.strength)

                # Calculate permission flags
                permissions = config.permissions.to_pymupdf_flags()

                # Ensure we have at least owner password
                owner_pw = config.owner_password or config.user_password or ""
                user_pw = config.user_password or ""

                # Apply encryption and save
                doc.save(
                    output_path,
                    encryption=encrypt_method,
                    owner_pw=owner_pw,
                    user_pw=user_pw,
                    permissions=permissions,
                )
            finally:
                doc.close()

            logger.success(
                f"PDF encrypted successfully: {input_path.name} "
                f"(strength={config.strength.value}, permissions={permissions})"
            )

            # Audit failure is critical but encryption must complete
            try:
                log_encryption_event(
                    document_path=str(input_path),
                    success=True,
                    method="password",
                    strength=config.strength.value,
                    details={
                        "output_path": str(output_path),
                        "permissions": permissions,
                    },
                )
            except Exception as e:
                logger.critical(f"Audit logging failed for encryption operation: {e}")

            return EncryptionResult(
                success=True,
                input_path=input_path,
                output_path=output_path,
                encrypted_at=datetime.now(UTC),
                method_used=EncryptionMethod.PASSWORD,
                strength_used=config.strength,
                permissions_applied=config.permissions,
            )

        except (PDFCorruptedError, PDFEncryptionError):
            raise
        except Exception as e:
            # Log audit event for failure
            try:
                log_encryption_event(
                    document_path=str(input_path),
                    success=False,
                    method="password",
                    strength=config.strength.value if hasattr(config, "strength") else "unknown",
                    error=str(e),
                )
            except Exception as audit_err:
                # Audit failure is critical but encryption must complete
                logger.critical(f"Audit logging failed for encryption operation: {audit_err}")

            logger.exception(f"Password encryption failed for {input_path}: {e}")
            raise PDFEncryptionError(str(e)) from e

    def decrypt(
        self,
        input_path: Path,
        output_path: Path,
        password: str,
    ) -> EncryptionResult:
        """
        Decrypt password-protected PDF.

        Args:
            input_path: Encrypted PDF path
            output_path: Decrypted PDF path
            password: Decryption password

        Returns:
            EncryptionResult

        Raises:
            PasswordIncorrectError: If password is wrong
            PDFEncryptionError: If decryption fails
        """
        try:
            logger.info(f"Decrypting PDF: {input_path.name}")

            # Open PDF
            doc = fitz.open(input_path)
            try:
                # Check if actually encrypted
                if not doc.is_encrypted:
                    logger.warning(f"PDF '{input_path.name}' is not encrypted")
                    return EncryptionResult(
                        success=True,
                        input_path=input_path,
                        output_path=input_path,
                        error="PDF is not encrypted",
                    )

                # Authenticate
                auth_result = doc.authenticate(password)
                if auth_result == 0:
                    raise PasswordIncorrectError(input_path.name)

                # Save without encryption
                doc.save(output_path, encryption=fitz.PDF_ENCRYPT_NONE)
            finally:
                doc.close()

            logger.success(f"PDF decrypted successfully: {input_path.name} → {output_path.name}")

            # Audit failure is critical but decryption must complete
            try:
                log_encryption_event(
                    document_path=str(input_path),
                    success=True,
                    method="password_decrypt",
                    strength="N/A",
                    details={
                        "output_path": str(output_path),
                    },
                )
            except Exception as e:
                logger.critical(f"Audit logging failed for decryption operation: {e}")

            return EncryptionResult(
                success=True,
                input_path=input_path,
                output_path=output_path,
                encrypted_at=datetime.now(UTC),
                method_used=EncryptionMethod.PASSWORD,
            )

        except PasswordIncorrectError:
            raise
        except Exception as e:
            # Log audit event for failure
            try:
                log_encryption_event(
                    document_path=str(input_path),
                    success=False,
                    method="password_decrypt",
                    strength="N/A",
                    error=str(e),
                )
            except Exception as audit_err:
                # Audit failure is critical but decryption must complete
                logger.critical(f"Audit logging failed for decryption operation: {audit_err}")

            logger.exception(f"Decryption failed for {input_path}: {e}")
            raise PDFEncryptionError(str(e)) from e

    def change_password(
        self,
        pdf_path: Path,
        old_password: str,
        new_user_password: str | None,
        new_owner_password: str | None,
        output_path: Path | None = None,
    ) -> EncryptionResult:
        """
        Change encryption passwords on an existing PDF.

        Args:
            pdf_path: Path to encrypted PDF
            old_password: Current password
            new_user_password: New user password (or None to keep)
            new_owner_password: New owner password (or None to keep)
            output_path: Optional new path (default: overwrite)

        Returns:
            EncryptionResult
        """
        try:
            logger.info(f"Changing password for: {pdf_path.name}")

            doc = fitz.open(pdf_path)
            try:
                if not doc.is_encrypted:
                    raise PDFEncryptionError("PDF is not encrypted")

                # Authenticate with old password
                auth_result = doc.authenticate(old_password)
                if auth_result == 0:
                    raise PasswordIncorrectError(pdf_path.name)

                # Determine output path
                final_output = output_path or pdf_path

                # Re-encrypt with new passwords
                doc.save(
                    final_output,
                    encryption=fitz.PDF_ENCRYPT_AES_256,
                    owner_pw=new_owner_password or old_password,
                    user_pw=new_user_password or "",
                )
            finally:
                doc.close()

            logger.success(f"Password changed for: {pdf_path.name}")

            return EncryptionResult(
                success=True,
                input_path=pdf_path,
                output_path=final_output,
                encrypted_at=datetime.now(UTC),
                method_used=EncryptionMethod.PASSWORD,
                strength_used=EncryptionStrength.AES_256,
            )

        except (PasswordIncorrectError, PDFEncryptionError):
            raise
        except Exception as e:
            logger.exception(f"Password change failed: {e}")
            raise PDFEncryptionError(str(e)) from e

    def _map_encryption_strength(self, strength: EncryptionStrength) -> int:
        """Map EncryptionStrength to PyMuPDF constant."""
        mapping = {
            EncryptionStrength.AES_128: fitz.PDF_ENCRYPT_AES_128,
            EncryptionStrength.AES_256: fitz.PDF_ENCRYPT_AES_256,
        }
        return mapping.get(strength, fitz.PDF_ENCRYPT_AES_256)
