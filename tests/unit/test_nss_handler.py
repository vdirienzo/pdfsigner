"""
test_nss_handler.py - Tests for NSSHandler

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.token.nss_handler import CertificateInfo, NSSHandler
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    NSSConfigError,
    TokenAuthenticationError,
    TokenNotFoundError,
)


class TestCertificateInfo:
    """Tests for CertificateInfo dataclass."""

    def test_creation(self):
        """Test creating CertificateInfo."""
        cert_info = CertificateInfo(
            label="Test Certificate",
            subject="CN=Test User,O=Test Org",
            issuer="CN=Test CA,O=Test Org",
            serial_number="abc123",
            not_before="2024-01-01T00:00:00",
            not_after="2025-01-01T00:00:00",
            can_sign=True,
            pkcs11_id=b"\x01\x02\x03",
        )

        assert cert_info.label == "Test Certificate"
        assert cert_info.can_sign is True
        assert cert_info.pkcs11_id == b"\x01\x02\x03"

    def test_can_sign_false(self):
        """Test certificate that cannot sign."""
        cert_info = CertificateInfo(
            label="Encryption Cert",
            subject="CN=Test",
            issuer="CN=CA",
            serial_number="123",
            not_before="2024-01-01",
            not_after="2025-01-01",
            can_sign=False,
            pkcs11_id=b"\x01",
        )

        assert cert_info.can_sign is False


class TestNSSHandler:
    """Tests for NSSHandler class."""

    @pytest.fixture
    def handler_with_mock_settings(self, temp_dir: Path, mock_settings):
        """Create handler with mock settings."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir(exist_ok=True)
        return NSSHandler(nss_db_path=nss_dir)

    def test_initialization_default_path(self, mock_settings):
        """Test initialization with default path."""
        handler = NSSHandler()

        # Should use path from settings
        assert handler.nss_db_path is not None

    def test_initialization_custom_path(self, temp_dir: Path):
        """Test initialization with custom path."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        handler = NSSHandler(nss_db_path=nss_dir)

        assert handler.nss_db_path == nss_dir

    def test_initialize_missing_nss_db(self, temp_dir: Path):
        """Test initialize with missing NSS database."""
        handler = NSSHandler(nss_db_path=temp_dir / "nonexistent")

        with pytest.raises(NSSConfigError):
            handler.initialize()

    def test_find_pkcs11_lib_not_found(self, handler_with_mock_settings):
        """Test finding PKCS#11 library when none available."""
        handler = handler_with_mock_settings

        # Mock Path.exists to return False for all libraries
        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(TokenNotFoundError) as exc_info:
                handler._find_pkcs11_lib()

            assert "No PKCS#11 library found" in str(exc_info.value)

    def test_find_pkcs11_lib_safenet_found(self, handler_with_mock_settings):
        """Test finding SafeNet library."""
        handler = handler_with_mock_settings

        def mock_exists(path):
            return str(path) == "/usr/lib/libeToken.so"

        with patch.object(Path, "exists", side_effect=lambda: True):
            with patch("builtins.open", MagicMock()):
                with patch.object(Path, "exists", mock_exists):
                    lib_path = handler._find_pkcs11_lib()

                    assert lib_path == "/usr/lib/libeToken.so"

    def test_get_available_tokens_not_initialized(self, handler_with_mock_settings):
        """Test get_available_tokens initializes if needed."""
        handler = handler_with_mock_settings

        with patch.object(handler, "initialize") as mock_init:
            with patch.object(handler, "_lib", None):
                mock_init.side_effect = TokenNotFoundError("No lib")

                with pytest.raises(TokenNotFoundError):
                    handler.get_available_tokens()

    def test_connect_token_not_initialized(self, handler_with_mock_settings):
        """Test connect_token initializes if needed."""
        handler = handler_with_mock_settings

        with patch.object(handler, "initialize") as mock_init:
            handler._lib = None
            mock_init.side_effect = TokenNotFoundError("No lib")

            with pytest.raises(TokenNotFoundError):
                handler.connect_token()

    def test_authenticate_no_token(self, handler_with_mock_settings):
        """Test authenticate without connected token."""
        handler = handler_with_mock_settings
        handler._token = None

        with pytest.raises(TokenNotFoundError) as exc_info:
            handler.authenticate("1234")

        assert "connect a token first" in str(exc_info.value).lower()

    def test_authenticate_success(self, handler_with_mock_settings):
        """Test successful authentication."""
        handler = handler_with_mock_settings
        mock_token = MagicMock()
        mock_session = MagicMock()
        mock_token.open.return_value = mock_session
        handler._token = mock_token

        handler.authenticate("1234")

        assert handler._session == mock_session
        mock_token.open.assert_called_once_with(user_pin="1234")

    def test_authenticate_incorrect_pin(self, handler_with_mock_settings):
        """Test authentication with incorrect PIN."""
        handler = handler_with_mock_settings
        mock_token = MagicMock()

        # Import pkcs11 exceptions for mocking
        import pkcs11.exceptions

        mock_token.open.side_effect = pkcs11.exceptions.PinIncorrect()
        handler._token = mock_token

        with pytest.raises(TokenAuthenticationError) as exc_info:
            handler.authenticate("wrong")

        assert "incorrect pin" in str(exc_info.value).lower()

    def test_authenticate_pin_locked(self, handler_with_mock_settings):
        """Test authentication with locked PIN."""
        handler = handler_with_mock_settings
        mock_token = MagicMock()

        import pkcs11.exceptions

        mock_token.open.side_effect = pkcs11.exceptions.PinLocked()
        handler._token = mock_token

        with pytest.raises(TokenAuthenticationError) as exc_info:
            handler.authenticate("1234")

        assert "locked" in str(exc_info.value).lower()

    def test_list_certificates_not_authenticated(self, handler_with_mock_settings):
        """Test list_certificates without authentication."""
        handler = handler_with_mock_settings
        handler._session = None

        with pytest.raises(TokenAuthenticationError) as exc_info:
            handler.list_certificates()

        assert "authenticate first" in str(exc_info.value).lower()

    def test_get_signing_key_and_cert_not_authenticated(self, handler_with_mock_settings):
        """Test get_signing_key_and_cert without authentication."""
        handler = handler_with_mock_settings
        handler._session = None

        with pytest.raises(TokenAuthenticationError):
            handler.get_signing_key_and_cert()

    def test_get_signing_key_and_cert_no_certs(self, handler_with_mock_settings):
        """Test get_signing_key_and_cert with no signing certificates."""
        handler = handler_with_mock_settings
        handler._session = MagicMock()

        with patch.object(handler, "list_certificates", return_value=[]):
            with pytest.raises(CertificateNotFoundError):
                handler.get_signing_key_and_cert()

    def test_close_session(self, handler_with_mock_settings):
        """Test closing session."""
        handler = handler_with_mock_settings
        mock_session = MagicMock()
        handler._session = mock_session
        handler._token = MagicMock()

        handler.close()

        assert handler._session is None
        assert handler._token is None
        mock_session.close.assert_called_once()

    def test_close_no_session(self, handler_with_mock_settings):
        """Test close when no session exists."""
        handler = handler_with_mock_settings
        handler._session = None
        handler._token = None

        # Should not raise
        handler.close()

    def test_context_manager_enter(self, handler_with_mock_settings):
        """Test context manager __enter__."""
        handler = handler_with_mock_settings

        result = handler.__enter__()

        assert result is handler

    def test_context_manager_exit(self, handler_with_mock_settings):
        """Test context manager __exit__."""
        handler = handler_with_mock_settings
        handler._session = MagicMock()
        handler._token = MagicMock()

        result = handler.__exit__(None, None, None)

        assert result is False
        assert handler._session is None


class TestNSSHandlerLibraryPaths:
    """Tests for library path detection."""

    def test_nss_lib_paths_defined(self):
        """Test NSS library paths are defined."""
        from pdfsigner.core.token.pkcs11_libs import NSS_LIB_PATHS

        assert len(NSS_LIB_PATHS) > 0

    def test_safenet_lib_paths_defined(self):
        """Test SafeNet library paths are defined."""
        from pdfsigner.core.token.pkcs11_libs import SAFENET_LIB_PATHS

        assert len(SAFENET_LIB_PATHS) > 0

    def test_all_paths_are_absolute(self):
        """Test all library paths are absolute."""
        from pdfsigner.core.token.pkcs11_libs import NSS_LIB_PATHS, SAFENET_LIB_PATHS

        for path in NSS_LIB_PATHS + SAFENET_LIB_PATHS:
            assert path.startswith("/")
