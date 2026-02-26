"""
test_nss_setup.py - Tests for NSS database setup

Author: Homero Thompson del Lago del Terror
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.setup.nss_setup import NSSSetup, SetupResult


class TestSetupResult:
    """Tests for SetupResult dataclass."""

    def test_success_result(self):
        """Test successful result creation."""
        result = SetupResult(success=True, message="Done")
        assert result.success is True
        assert result.message == "Done"
        assert result.error_type is None

    def test_error_result(self):
        """Test error result creation."""
        result = SetupResult(
            success=False,
            message="Failed",
            error_type="not_found",
        )
        assert result.success is False
        assert result.message == "Failed"
        assert result.error_type == "not_found"


class TestNSSSetup:
    """Tests for NSSSetup class."""

    @pytest.fixture
    def setup(self, tmp_path: Path) -> NSSSetup:
        """Create setup with temporary path."""
        return NSSSetup(nss_path=tmp_path)

    def test_initialization_default_path(self):
        """Test initialization with default path."""
        setup = NSSSetup()
        assert setup.nss_path == Path.home() / ".nss"

    def test_initialization_custom_path(self, tmp_path: Path):
        """Test initialization with custom path."""
        setup = NSSSetup(nss_path=tmp_path)
        assert setup.nss_path == tmp_path

    def test_create_database_certutil_not_found(self, setup: NSSSetup):
        """Test create_database when certutil is not available."""
        with patch.object(setup.checker, "is_certutil_available", return_value=False):
            result = setup.create_database()

        assert result.success is False
        assert result.error_type == "not_found"
        assert "certutil not found" in result.message

    def test_create_database_success(self, setup: NSSSetup):
        """Test successful database creation."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch.object(setup.checker, "is_certutil_available", return_value=True):
            with patch.object(setup, "_run_certutil", return_value=mock_result):
                result = setup.create_database()

        assert result.success is True
        assert "successfully" in result.message

    def test_create_database_already_exists(self, setup: NSSSetup):
        """Test when database already exists (treat as success)."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "database already exists"

        with patch.object(setup.checker, "is_certutil_available", return_value=True):
            with patch.object(setup, "_run_certutil", return_value=mock_result):
                result = setup.create_database()

        assert result.success is True
        assert "already" in result.message.lower()

    def test_create_database_permission_denied(self, setup: NSSSetup):
        """Test when permission is denied."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Permission denied"

        with patch.object(setup.checker, "is_certutil_available", return_value=True):
            with patch.object(setup, "_run_certutil", return_value=mock_result):
                result = setup.create_database()

        assert result.success is False
        assert result.error_type == "permission"

    def test_create_database_timeout(self, setup: NSSSetup):
        """Test when certutil times out."""
        with patch.object(setup.checker, "is_certutil_available", return_value=True):
            with patch.object(
                setup,
                "_run_certutil",
                side_effect=subprocess.TimeoutExpired("certutil", 30),
            ):
                result = setup.create_database()

        assert result.success is False
        assert result.error_type == "timeout"
        assert "timed out" in result.message.lower()

    def test_create_database_unknown_error(self, setup: NSSSetup):
        """Test unknown error during creation."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Some weird error"

        with patch.object(setup.checker, "is_certutil_available", return_value=True):
            with patch.object(setup, "_run_certutil", return_value=mock_result):
                result = setup.create_database()

        assert result.success is False
        assert result.error_type == "unknown"

    def test_create_database_creates_directory(self, tmp_path: Path):
        """Test that directory is created if it doesn't exist."""
        nss_path = tmp_path / "new_nss_dir"
        setup = NSSSetup(nss_path=nss_path)

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch.object(setup.checker, "is_certutil_available", return_value=True):
            with patch.object(setup, "_run_certutil", return_value=mock_result):
                result = setup.create_database()

        assert nss_path.exists()
        assert result.success is True


class TestNSSSetupRunCertutil:
    """Tests for _run_certutil method."""

    def test_run_certutil_command(self, tmp_path: Path):
        """Test that correct command is executed."""
        setup = NSSSetup(nss_path=tmp_path)

        with patch("shutil.which", return_value="/usr/bin/certutil"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                setup._run_certutil()

                # Check command arguments
                call_args = mock_run.call_args
                cmd = call_args[0][0]  # First positional arg

                assert cmd[0] == "/usr/bin/certutil"
                assert "-N" in cmd
                assert "--empty-password" in cmd
                assert f"sql:{tmp_path}" in cmd

    def test_run_certutil_timeout(self, tmp_path: Path):
        """Test that timeout is set."""
        setup = NSSSetup(nss_path=tmp_path)

        with patch("shutil.which", return_value="/usr/bin/certutil"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                setup._run_certutil()

                call_kwargs = mock_run.call_args[1]
                assert call_kwargs.get("timeout") == setup.TIMEOUT_SECONDS


class TestNSSSetupVerify:
    """Tests for verify_setup method."""

    def test_verify_setup_success(self, tmp_path: Path):
        """Test verify_setup when configured."""
        (tmp_path / "cert9.db").touch()
        (tmp_path / "key4.db").touch()

        setup = NSSSetup(nss_path=tmp_path)
        assert setup.verify_setup() is True

    def test_verify_setup_failure(self, tmp_path: Path):
        """Test verify_setup when not configured."""
        setup = NSSSetup(nss_path=tmp_path)
        assert setup.verify_setup() is False
