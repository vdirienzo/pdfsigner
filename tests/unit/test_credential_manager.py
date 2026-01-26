"""
Tests for credential_manager.py - Secure credential storage

Author: Homero Thompson del Lago del Terror
"""

import pytest

from pdfsigner.core.security.credential_manager import (
    CredentialManager,
    TSACredentials,
    get_credential_manager,
)


class TestTSACredentials:
    """Tests for TSACredentials dataclass."""

    def test_credentials_without_auth(self):
        """Credentials without username/password should return has_auth=False."""
        creds = TSACredentials(url="https://tsa.example.com")
        assert creds.url == "https://tsa.example.com"
        assert creds.username is None
        assert creds.password is None
        assert creds.has_auth() is False

    def test_credentials_with_auth(self):
        """Credentials with username and password should return has_auth=True."""
        creds = TSACredentials(
            url="https://tsa.example.com",
            username="user",
            password="pass",
        )
        assert creds.has_auth() is True

    def test_credentials_partial_auth(self):
        """Credentials with only username should return has_auth=False."""
        creds = TSACredentials(url="https://tsa.example.com", username="user")
        assert creds.has_auth() is False


class TestCredentialManager:
    """Tests for CredentialManager class."""

    @pytest.fixture
    def manager(self):
        """Create a fresh credential manager for each test."""
        return CredentialManager()

    def test_store_and_get_password_memory(self, manager: CredentialManager):
        """Password can be stored and retrieved from memory."""
        manager.store_password("test_key", "test_password", storage="memory")
        assert manager.get_password("test_key") == "test_password"

    def test_get_nonexistent_password_returns_none(self, manager: CredentialManager):
        """Getting non-existent password returns None."""
        assert manager.get_password("nonexistent") is None

    def test_delete_password_memory(self, manager: CredentialManager):
        """Password can be deleted from memory."""
        manager.store_password("to_delete", "password", storage="memory")
        assert manager.get_password("to_delete") == "password"

        result = manager.delete_password("to_delete")
        assert result is True
        assert manager.get_password("to_delete") is None

    def test_delete_nonexistent_password(self, manager: CredentialManager):
        """Deleting non-existent password returns False."""
        result = manager.delete_password("never_existed")
        assert result is False

    def test_has_password(self, manager: CredentialManager):
        """has_password correctly checks existence."""
        assert manager.has_password("check_key") is False

        manager.store_password("check_key", "value", storage="memory")
        assert manager.has_password("check_key") is True

    def test_clear_all(self, manager: CredentialManager):
        """clear_all removes all stored credentials."""
        manager.store_password("key1", "val1", storage="memory")
        manager.store_password("key2", "val2", storage="memory")

        manager.clear_all()

        assert manager.get_password("key1") is None
        assert manager.get_password("key2") is None


class TestCredentialManagerTSA:
    """Tests for TSA-specific credential methods."""

    @pytest.fixture
    def manager(self):
        """Create a fresh credential manager."""
        return CredentialManager()

    def test_store_tsa_credentials(self, manager: CredentialManager):
        """TSA credentials can be stored."""
        result = manager.store_tsa_credentials(
            url="https://tsa.example.com",
            username="user",
            password="secret",
        )
        assert result is True
        assert manager.get_password("tsa_password") == "secret"

    def test_get_tsa_credentials(self, manager: CredentialManager):
        """TSA credentials can be retrieved."""
        manager.store_password("tsa_password", "secret", storage="memory")

        creds = manager.get_tsa_credentials(
            url="https://tsa.example.com",
            username="user",
        )

        assert isinstance(creds, TSACredentials)
        assert creds.url == "https://tsa.example.com"
        assert creds.username == "user"
        assert creds.password == "secret"

    def test_get_tsa_credentials_no_password(self, manager: CredentialManager):
        """TSA credentials without stored password return None password."""
        # Ensure no password is stored
        manager.clear_tsa_password()

        creds = manager.get_tsa_credentials(
            url="https://tsa.example.com",
            username="user",
        )

        assert creds.password is None
        assert creds.has_auth() is False

    def test_clear_tsa_password(self, manager: CredentialManager):
        """TSA password can be cleared."""
        manager.store_password("tsa_password", "secret", storage="memory")
        assert manager.get_password("tsa_password") == "secret"

        result = manager.clear_tsa_password()
        assert result is True
        assert manager.get_password("tsa_password") is None


class TestCredentialManagerSingleton:
    """Tests for singleton behavior."""

    def test_get_credential_manager_returns_same_instance(self):
        """get_credential_manager should return same instance."""
        # Note: This test may interact with other tests due to global state
        # In real use, the singleton ensures consistency across the app
        manager1 = get_credential_manager()
        manager2 = get_credential_manager()
        assert manager1 is manager2


class TestCredentialManagerKeyringFallback:
    """Tests for keyring fallback behavior."""

    def test_keyring_not_available_uses_memory(self):
        """When keyring unavailable, should fall back to memory."""
        manager = CredentialManager()
        # Force keyring unavailable
        manager._keyring_available = False

        # Should still work via memory
        result = manager.store_password("key", "value", storage="keyring")
        assert result is True
        assert manager.get_password("key") == "value"
