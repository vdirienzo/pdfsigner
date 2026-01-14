"""
test_lta_handler.py - Tests for LTAHandler

Author: Homero Thompson del Lago del Terror
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from pdfsigner.core.signer.lta_handler import (
    LTAHandler,
    TSAConfig,
    create_lta_handler_from_settings,
)
from pdfsigner.exceptions import TSAConnectionError


class TestTSAConfig:
    """Tests for TSAConfig dataclass."""

    def test_default_values(self):
        """Test default values."""
        config = TSAConfig(url="https://tsa.example.com")

        assert config.url == "https://tsa.example.com"
        assert config.username is None
        assert config.password is None
        assert config.timeout == 30

    def test_with_auth(self):
        """Test with authentication."""
        config = TSAConfig(
            url="https://tsa.example.com",
            username="user",
            password="pass",
            timeout=60,
        )

        assert config.username == "user"
        assert config.password == "pass"
        assert config.timeout == 60


class TestLTAHandlerInit:
    """Tests for LTAHandler initialization."""

    def test_init_with_config(self):
        """Test initialization with TSAConfig."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        assert handler.tsa_config == config
        assert handler._timestamper is None

    def test_init_from_settings(self):
        """Test initialization from settings when tsa_config is None."""
        # Need to patch get_settings at the module where it's imported
        mock_settings = MagicMock()
        mock_settings.tsa_url = "https://test.tsa.example.com"
        mock_settings.tsa_username = None
        mock_settings.tsa_password = None

        with patch(
            "pdfsigner.core.signer.lta_handler.get_settings",
            return_value=mock_settings,
        ):
            handler = LTAHandler(tsa_config=None)

        assert handler.tsa_config is not None
        assert handler.tsa_config.url == "https://test.tsa.example.com"


class TestLTAHandlerValidateConnection:
    """Tests for validate_tsa_connection method."""

    def test_validate_empty_url(self):
        """Test validation with empty URL raises error."""
        config = TSAConfig(url="")
        handler = LTAHandler(config)

        with pytest.raises(TSAConnectionError) as exc_info:
            handler.validate_tsa_connection()

        assert "not configured" in str(exc_info.value)

    def test_validate_invalid_url(self):
        """Test validation with invalid URL format."""
        config = TSAConfig(url="not-a-valid-url")
        handler = LTAHandler(config)

        with pytest.raises(TSAConnectionError) as exc_info:
            handler.validate_tsa_connection()

        assert "Invalid URL" in str(exc_info.value)

    def test_validate_connection_success(self):
        """Test successful connection validation."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        with patch("pdfsigner.core.signer.lta_handler.requests.head") as mock_head:
            mock_head.return_value = MagicMock(status_code=200)
            result = handler.validate_tsa_connection()

        assert result is True
        mock_head.assert_called_once()

    def test_validate_connection_with_auth(self):
        """Test connection validation with authentication."""
        config = TSAConfig(
            url="https://tsa.example.com",
            username="user",
            password="pass",
        )
        handler = LTAHandler(config)

        with patch("pdfsigner.core.signer.lta_handler.requests.head") as mock_head:
            mock_head.return_value = MagicMock(status_code=200)
            handler.validate_tsa_connection()

        # Verify auth was passed
        call_kwargs = mock_head.call_args[1]
        assert call_kwargs["auth"] == ("user", "pass")

    def test_validate_connection_method_not_allowed(self):
        """Test connection validation when TSA returns 405."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        with patch("pdfsigner.core.signer.lta_handler.requests.head") as mock_head:
            mock_head.return_value = MagicMock(status_code=405)
            result = handler.validate_tsa_connection()

        assert result is True  # 405 is acceptable

    def test_validate_connection_error(self):
        """Test connection error raises TSAConnectionError."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        with patch("pdfsigner.core.signer.lta_handler.requests.head") as mock_head:
            mock_head.side_effect = requests.exceptions.ConnectionError()
            with pytest.raises(TSAConnectionError):
                handler.validate_tsa_connection()

    def test_validate_connection_timeout(self):
        """Test timeout raises TSAConnectionError."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        with patch("pdfsigner.core.signer.lta_handler.requests.head") as mock_head:
            mock_head.side_effect = requests.exceptions.Timeout()
            with pytest.raises(TSAConnectionError) as exc_info:
                handler.validate_tsa_connection()

        assert "Timeout" in str(exc_info.value)


class TestLTAHandlerGetTimestamper:
    """Tests for get_timestamper method."""

    def test_get_timestamper_no_url(self):
        """Test get_timestamper raises error when URL not configured."""
        config = TSAConfig(url="")
        handler = LTAHandler(config)

        with pytest.raises(TSAConnectionError) as exc_info:
            handler.get_timestamper()

        assert "not configured" in str(exc_info.value)

    def test_get_timestamper_creates_once(self):
        """Test get_timestamper creates timestamper only once."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        ts1 = handler.get_timestamper()
        ts2 = handler.get_timestamper()

        assert ts1 is ts2  # Same instance

    def test_get_timestamper_with_auth(self):
        """Test get_timestamper with authentication."""
        config = TSAConfig(
            url="https://tsa.example.com",
            username="user",
            password="pass",
        )
        handler = LTAHandler(config)

        with patch("pdfsigner.core.signer.lta_handler.HTTPTimeStamper") as MockTimestamper:
            handler.get_timestamper()

        # Verify HTTPBasicAuth was created
        call_kwargs = MockTimestamper.call_args[1]
        assert call_kwargs["auth"] is not None
        assert call_kwargs["url"] == "https://tsa.example.com"


class TestLTAHandlerHelpers:
    """Tests for helper methods."""

    def test_get_validation_context_kwargs(self):
        """Test get_validation_context_kwargs returns correct dict."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        kwargs = handler.get_validation_context_kwargs()

        assert kwargs["revocation_mode"] == "require"
        assert kwargs["allow_fetching"] is True

    def test_get_signature_kwargs_with_url(self):
        """Test get_signature_kwargs with URL configured."""
        config = TSAConfig(url="https://tsa.example.com")
        handler = LTAHandler(config)

        kwargs = handler.get_signature_kwargs()

        assert "timestamper" in kwargs
        assert kwargs["embed_validation_info"] is True

    def test_get_signature_kwargs_without_url(self):
        """Test get_signature_kwargs without URL."""
        config = TSAConfig(url="")
        handler = LTAHandler(config)

        kwargs = handler.get_signature_kwargs()

        assert "timestamper" not in kwargs
        assert kwargs["embed_validation_info"] is True

    def test_get_ltv_profile(self):
        """Test get_ltv_profile returns correct profile."""
        profile = LTAHandler.get_ltv_profile()
        assert profile == "PAdES-LTV"

    def test_get_subfilter(self):
        """Test get_subfilter returns correct subfilter."""
        subfilter = LTAHandler.get_subfilter()
        assert subfilter == "ETSI.CAdES.detached"


class TestCreateLTAHandlerFromSettings:
    """Tests for create_lta_handler_from_settings function."""

    def test_create_without_tsa_url(self):
        """Test creating handler when TSA URL is not configured."""
        mock_settings = MagicMock()
        mock_settings.tsa_url = ""

        with patch(
            "pdfsigner.core.signer.lta_handler.get_settings",
            return_value=mock_settings,
        ):
            handler = create_lta_handler_from_settings()

        assert handler.tsa_config.url == ""

    def test_create_with_valid_tsa(self):
        """Test creating handler with valid TSA configuration."""
        mock_settings = MagicMock()
        mock_settings.tsa_url = "https://test.tsa.example.com"
        mock_settings.tsa_username = None
        mock_settings.tsa_password = None

        with patch(
            "pdfsigner.core.signer.lta_handler.get_settings",
            return_value=mock_settings,
        ):
            with patch.object(LTAHandler, "validate_tsa_connection", return_value=True):
                handler = create_lta_handler_from_settings()

        assert handler.tsa_config.url == "https://test.tsa.example.com"

    def test_create_with_connection_error(self):
        """Test creating handler when TSA connection fails."""
        mock_settings = MagicMock()
        mock_settings.tsa_url = "https://test.tsa.example.com"
        mock_settings.tsa_username = None
        mock_settings.tsa_password = None

        with patch(
            "pdfsigner.core.signer.lta_handler.get_settings",
            return_value=mock_settings,
        ):
            with patch.object(
                LTAHandler,
                "validate_tsa_connection",
                side_effect=TSAConnectionError("Connection failed"),
            ):
                with pytest.raises(TSAConnectionError):
                    create_lta_handler_from_settings()

    def test_create_with_auth_settings(self):
        """Test creating handler with auth from settings."""
        mock_settings = MagicMock()
        mock_settings.tsa_url = "https://test.tsa.example.com"
        mock_settings.tsa_username = "testuser"
        mock_settings.tsa_password = "testpass"

        with patch(
            "pdfsigner.core.signer.lta_handler.get_settings",
            return_value=mock_settings,
        ):
            with patch.object(LTAHandler, "validate_tsa_connection", return_value=True):
                handler = create_lta_handler_from_settings()

        assert handler.tsa_config.username == "testuser"
        assert handler.tsa_config.password == "testpass"
