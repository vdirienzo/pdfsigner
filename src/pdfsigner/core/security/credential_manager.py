"""
credential_manager.py - Secure credential storage using system keyring

Author: Homero Thompson del Lago del Terror

Provides secure storage for sensitive credentials (like TSA passwords)
using the system keyring (libsecret on Linux, Keychain on macOS).
Falls back to in-memory storage if keyring is not available.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from loguru import logger

# Service name for keyring entries
SERVICE_NAME = "pdfsigner"


@dataclass
class TSACredentials:
    """TSA server credentials."""

    url: str
    username: str | None = None
    password: str | None = None

    def has_auth(self) -> bool:
        """Check if credentials include authentication."""
        return bool(self.username and self.password)


class CredentialManager:
    """
    Secure credential management with tiered storage.

    Storage tiers:
    1. System keyring (libsecret/Keychain) - most secure
    2. In-memory only - for session-only storage
    3. TOML config - least secure (username only, NOT password)

    Passwords are NEVER stored in plaintext config files.
    """

    def __init__(self):
        self._keyring_available: bool | None = None
        self._memory_store: dict[str, str] = {}

    def _check_keyring(self) -> bool:
        """Check if system keyring is available."""
        if self._keyring_available is not None:
            return self._keyring_available

        try:
            import keyring
            from keyring.errors import NoKeyringError

            # Test keyring availability with a dummy operation
            try:
                keyring.get_keyring()
                self._keyring_available = True
                logger.debug("System keyring is available")
            except NoKeyringError:
                self._keyring_available = False
                logger.warning("No system keyring available, using memory-only storage")
        except ImportError:
            self._keyring_available = False
            logger.warning("keyring module not installed, using memory-only storage")

        return self._keyring_available

    def store_password(
        self,
        key: str,
        password: str,
        storage: Literal["keyring", "memory"] = "keyring",
    ) -> bool:
        """
        Store a password securely.

        Args:
            key: Unique identifier for the credential (e.g., "tsa_password")
            password: The password to store
            storage: Where to store ("keyring" preferred, "memory" fallback)

        Returns:
            True if stored successfully
        """
        if storage == "keyring" and self._check_keyring():
            try:
                import keyring

                keyring.set_password(SERVICE_NAME, key, password)
                logger.debug(f"Password stored in keyring: {key}")
                return True
            except Exception as e:
                logger.error(f"Failed to store in keyring: {e}")
                # Fall through to memory storage

        # Memory-only storage (session lifetime)
        self._memory_store[key] = password
        logger.debug(f"Password stored in memory: {key}")
        return True

    def get_password(self, key: str) -> str | None:
        """
        Retrieve a stored password.

        Checks keyring first, then memory.

        Args:
            key: Unique identifier for the credential

        Returns:
            Password if found, None otherwise
        """
        # Try keyring first
        if self._check_keyring():
            try:
                import keyring

                password = keyring.get_password(SERVICE_NAME, key)
                if password:
                    logger.debug(f"Password retrieved from keyring: {key}")
                    return password
            except Exception as e:
                logger.error(f"Failed to retrieve from keyring: {e}")

        # Fallback to memory
        password = self._memory_store.get(key)
        if password:
            logger.debug(f"Password retrieved from memory: {key}")
        return password

    def delete_password(self, key: str) -> bool:
        """
        Delete a stored password.

        Args:
            key: Unique identifier for the credential

        Returns:
            True if deleted from at least one storage
        """
        deleted = False

        # Try keyring
        if self._check_keyring():
            try:
                import keyring

                keyring.delete_password(SERVICE_NAME, key)
                logger.debug(f"Password deleted from keyring: {key}")
                deleted = True
            except Exception as e:
                # May not exist, which is fine
                logger.debug(f"No keyring entry to delete: {key} ({e})")

        # Clear from memory
        if key in self._memory_store:
            del self._memory_store[key]
            logger.debug(f"Password deleted from memory: {key}")
            deleted = True

        return deleted

    def has_password(self, key: str) -> bool:
        """Check if a password is stored (in any tier)."""
        return self.get_password(key) is not None

    # --- TSA-specific methods ---

    def store_tsa_credentials(self, url: str, username: str | None, password: str | None) -> bool:
        """
        Store TSA credentials.

        URL and username can be stored in config, but password goes to keyring.

        Args:
            url: TSA server URL
            username: Optional TSA username
            password: Optional TSA password (stored securely)

        Returns:
            True if all credentials stored successfully
        """
        success = True

        if password:
            success = self.store_password("tsa_password", password)

        # URL and username are stored in settings (not here)
        # This method only handles the secure password storage

        return success

    def get_tsa_credentials(self, url: str, username: str | None) -> TSACredentials:
        """
        Get complete TSA credentials.

        Combines URL/username from settings with password from secure storage.

        Args:
            url: TSA server URL (from settings)
            username: TSA username (from settings)

        Returns:
            TSACredentials with password from keyring if available
        """
        password = self.get_password("tsa_password") if username else None

        return TSACredentials(
            url=url,
            username=username,
            password=password,
        )

    def clear_tsa_password(self) -> bool:
        """Clear stored TSA password."""
        return self.delete_password("tsa_password")

    def clear_all(self) -> None:
        """Clear all stored credentials (for logout/security)."""
        self._memory_store.clear()

        if self._check_keyring():
            try:
                import keyring

                # Clear known keys
                for key in ["tsa_password"]:
                    try:
                        keyring.delete_password(SERVICE_NAME, key)
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"Error clearing keyring: {e}")

        logger.info("All stored credentials cleared")


# Singleton instance
_credential_manager: CredentialManager | None = None


def get_credential_manager() -> CredentialManager:
    """Get the credential manager singleton."""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager
