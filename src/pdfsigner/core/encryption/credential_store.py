"""
credential_store.py - Secure storage for encryption passwords

Extends credential_manager for PDF-specific encryption passwords.
Uses keyring with file-based key generation.
"""

import hashlib
from pathlib import Path

from loguru import logger

from pdfsigner.core.security.credential_manager import get_credential_manager


class EncryptionCredentialStore:
    """
    Secure storage for PDF encryption passwords.

    Integrates with existing credential_manager infrastructure.
    Uses file hash as key identifier for per-file passwords.
    """

    def __init__(self):
        """Initialize with shared credential manager."""
        self._credential_manager = None

    @property
    def credential_manager(self):
        """Lazy-load credential manager."""
        if self._credential_manager is None:
            self._credential_manager = get_credential_manager()
        return self._credential_manager

    def store_password_for_file(
        self,
        pdf_path: Path,
        password: str,
        is_owner: bool = False,
    ) -> bool:
        """
        Store encryption password for specific PDF.

        Args:
            pdf_path: Path to PDF file
            password: Encryption password
            is_owner: True if owner password, False if user password

        Returns:
            True if stored successfully
        """
        key = self._generate_key_for_file(pdf_path, is_owner)
        success = self.credential_manager.store_password(key, password)

        if success:
            logger.debug(f"Stored encryption password for {pdf_path.name} (owner={is_owner})")

        return success

    def get_password_for_file(
        self,
        pdf_path: Path,
        is_owner: bool = False,
    ) -> str | None:
        """
        Retrieve encryption password for specific PDF.

        Args:
            pdf_path: Path to PDF file
            is_owner: True for owner password, False for user password

        Returns:
            Password if found, None otherwise
        """
        try:
            key = self._generate_key_for_file(pdf_path, is_owner)
            password = self.credential_manager.get_password(key)

            if password:
                logger.debug(f"Retrieved encryption password for {pdf_path.name}")

            return password
        except Exception as e:
            logger.warning(f"Failed to get password for {pdf_path.name}: {e}")
            return None

    def delete_password_for_file(
        self,
        pdf_path: Path,
        is_owner: bool = False,
    ) -> bool:
        """
        Delete stored password for specific PDF.

        Args:
            pdf_path: Path to PDF file
            is_owner: True for owner password

        Returns:
            True if deleted
        """
        try:
            key = self._generate_key_for_file(pdf_path, is_owner)
            success = self.credential_manager.delete_password(key)

            if success:
                logger.debug(f"Deleted encryption password for {pdf_path.name}")

            return success
        except Exception as e:
            logger.warning(f"Failed to delete password for {pdf_path.name}: {e}")
            return False

    def get_any_password_for_file(self, pdf_path: Path) -> str | None:
        """
        Get any stored password for file (tries owner first, then user).

        Args:
            pdf_path: Path to PDF file

        Returns:
            Password if found, None otherwise
        """
        # Try owner password first (more privileged)
        password = self.get_password_for_file(pdf_path, is_owner=True)
        if password:
            return password

        # Fall back to user password
        return self.get_password_for_file(pdf_path, is_owner=False)

    def _generate_key_for_file(self, pdf_path: Path, is_owner: bool) -> str:
        """
        Generate unique keyring key for PDF file.

        Args:
            pdf_path: Path to PDF file
            is_owner: True for owner password key

        Returns:
            Keyring key string
        """
        # Create hash of absolute path for uniqueness
        path_str = str(pdf_path.absolute())
        path_hash = hashlib.sha256(path_str.encode()).hexdigest()[:16]

        # Format: pdfsigner_encrypt_{filename}_{hash}_{type}
        password_type = "owner" if is_owner else "user"
        key = f"pdfsigner_encrypt_{pdf_path.stem}_{path_hash}_{password_type}"

        return key


# Singleton instance
_credential_store: EncryptionCredentialStore | None = None


def get_encryption_credential_store() -> EncryptionCredentialStore:
    """Get singleton credential store instance."""
    global _credential_store
    if _credential_store is None:
        _credential_store = EncryptionCredentialStore()
    return _credential_store
