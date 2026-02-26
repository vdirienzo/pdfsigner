"""
pdf_encryptor.py - Main PDF encryption orchestrator

Coordinates password-based and certificate-based encryption
with HIPAA compliance validation.
"""

from pathlib import Path

from loguru import logger

from pdfsigner.core.encryption.credential_store import get_encryption_credential_store
from pdfsigner.core.encryption.encryption_config import (
    EncryptionConfig,
    EncryptionMethod,
    EncryptionResult,
)
from pdfsigner.core.encryption.encryption_validator import EncryptionValidator
from pdfsigner.core.encryption.password_handler import PasswordEncryptionHandler
from pdfsigner.exceptions import (
    PDFCorruptedError,
    PDFEncryptionError,
    PDFProtectedError,
)


class PDFEncryptor:
    """
    Main PDF encryption coordinator.

    Orchestrates password-based and certificate-based encryption
    following HIPAA compliance requirements (AES-256 minimum).

    Usage:
        # Password-based
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
            user_password="<user-password>",
            owner_password="<owner-password>",
        )
        encryptor = PDFEncryptor()
        result = encryptor.encrypt(Path("document.pdf"), config)

        # Decrypt
        result = encryptor.decrypt(Path("encrypted.pdf"), password="<user-password>")
    """

    def __init__(self):
        """Initialize encryptor with handlers."""
        self.credential_store = get_encryption_credential_store()
        self.validator = EncryptionValidator()
        self._password_handler: PasswordEncryptionHandler | None = None

    @property
    def password_handler(self) -> PasswordEncryptionHandler:
        """Lazy-load password handler."""
        if self._password_handler is None:
            self._password_handler = PasswordEncryptionHandler()
        return self._password_handler

    def encrypt(
        self,
        input_path: Path,
        config: EncryptionConfig,
        output_path: Path | None = None,
    ) -> EncryptionResult:
        """
        Encrypt a PDF file.

        Args:
            input_path: Path to input PDF
            config: Encryption configuration
            output_path: Optional output path (default: input + suffix)

        Returns:
            EncryptionResult with success/error details

        Raises:
            PDFCorruptedError: If PDF is invalid
            PDFProtectedError: If PDF is already encrypted
            PDFEncryptionError: If encryption fails
        """
        try:
            # Validate config
            config.validate()

            # Check if file exists
            if not input_path.exists():
                raise FileNotFoundError(f"PDF not found: {input_path}")

            # Check if PDF already encrypted
            if self.validator.is_encrypted(input_path):
                raise PDFProtectedError(input_path.name)

            # Determine output path
            if output_path is None:
                if config.overwrite_input:
                    output_path = input_path
                else:
                    output_path = self._get_output_path(input_path, config.output_suffix)

            # Route to appropriate handler
            if config.method == EncryptionMethod.PASSWORD:
                result = self.password_handler.encrypt(input_path, output_path, config)
            elif config.method == EncryptionMethod.CERTIFICATE:
                # Certificate encryption not yet implemented
                raise NotImplementedError(
                    "Certificate-based encryption is planned for a future release. "
                    "Use password-based encryption for now."
                )
            else:
                raise ValueError(f"Unsupported encryption method: {config.method}")

            # Store credentials if successful
            if result.success and config.user_password:
                self._store_credentials(output_path, config)

            return result

        except (PDFCorruptedError, PDFProtectedError, PDFEncryptionError, FileNotFoundError):
            raise
        except NotImplementedError:
            raise
        except Exception as e:
            logger.exception(f"Encryption failed for {input_path}: {e}")
            return EncryptionResult(
                success=False,
                input_path=input_path,
                error=str(e),
            )

    def encrypt_batch(
        self,
        pdf_paths: list[Path],
        config: EncryptionConfig,
        stop_on_error: bool = False,
    ) -> list[EncryptionResult]:
        """
        Encrypt multiple PDFs with the same configuration.

        Args:
            pdf_paths: List of PDF paths
            config: Shared encryption configuration
            stop_on_error: Stop batch if any file fails

        Returns:
            List of EncryptionResults (one per file)
        """
        results = []

        for pdf_path in pdf_paths:
            try:
                result = self.encrypt(pdf_path, config)
                results.append(result)

                if not result.success and stop_on_error:
                    logger.warning(f"Batch stopped due to error: {result.error}")
                    break

            except Exception as e:
                result = EncryptionResult(
                    success=False,
                    input_path=pdf_path,
                    error=str(e),
                )
                results.append(result)

                if stop_on_error:
                    break

        # Summary
        success_count = sum(1 for r in results if r.success)
        logger.info(f"Batch encryption complete: {success_count}/{len(results)} successful")

        return results

    def decrypt(
        self,
        input_path: Path,
        password: str | None = None,
        output_path: Path | None = None,
    ) -> EncryptionResult:
        """
        Decrypt a password-protected PDF.

        Args:
            input_path: Path to encrypted PDF
            password: Password (if None, tries keyring)
            output_path: Optional output path

        Returns:
            EncryptionResult
        """
        try:
            # Check if file exists
            if not input_path.exists():
                raise FileNotFoundError(f"PDF not found: {input_path}")

            # Check if actually encrypted
            if not self.validator.is_encrypted(input_path):
                return EncryptionResult(
                    success=True,
                    input_path=input_path,
                    output_path=input_path,
                    error="PDF is not encrypted",
                )

            # Try keyring if no password provided
            if password is None:
                password = self.credential_store.get_any_password_for_file(input_path)

            if password is None:
                raise PDFEncryptionError("No password provided and none found in credential store")

            # Determine output path
            if output_path is None:
                output_path = input_path.with_stem(f"{input_path.stem}_decrypted")

            # Decrypt
            result = self.password_handler.decrypt(input_path, output_path, password)

            return result

        except (PDFEncryptionError, FileNotFoundError):
            raise
        except Exception as e:
            logger.exception(f"Decryption failed for {input_path}: {e}")
            return EncryptionResult(
                success=False,
                input_path=input_path,
                error=str(e),
            )

    def validate_hipaa(self, pdf_path: Path) -> tuple[bool, str]:
        """
        Check if PDF encryption meets HIPAA requirements.

        Args:
            pdf_path: Path to PDF file

        Returns:
            Tuple of (is_compliant, reason)
        """
        return self.validator.validate_hipaa_compliance(pdf_path)

    def _get_output_path(self, input_path: Path, suffix: str) -> Path:
        """Generate output path with suffix."""
        return input_path.with_stem(f"{input_path.stem}{suffix}")

    def _store_credentials(self, pdf_path: Path, config: EncryptionConfig) -> None:
        """Store encryption credentials in keyring."""
        try:
            if config.owner_password:
                self.credential_store.store_password_for_file(
                    pdf_path,
                    config.owner_password,
                    is_owner=True,
                )
            if config.user_password:
                self.credential_store.store_password_for_file(
                    pdf_path,
                    config.user_password,
                    is_owner=False,
                )
        except Exception as e:
            # Non-fatal - log but don't fail encryption
            logger.warning(f"Could not store credentials in keyring: {e}")


# Convenience function
def get_pdf_encryptor() -> PDFEncryptor:
    """Get a new PDFEncryptor instance."""
    return PDFEncryptor()
