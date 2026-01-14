"""
test_nss_checker.py - Tests for NSS database checker

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from pdfsigner.core.setup.nss_checker import NSSChecker


class TestNSSChecker:
    """Tests for NSSChecker class."""

    @pytest.fixture
    def checker(self, tmp_path: Path) -> NSSChecker:
        """Create checker with temporary path."""
        return NSSChecker(nss_path=tmp_path)

    def test_initialization_default_path(self):
        """Test initialization with default path."""
        checker = NSSChecker()
        assert checker.nss_path == Path.home() / ".nss"

    def test_initialization_custom_path(self, tmp_path: Path):
        """Test initialization with custom path."""
        checker = NSSChecker(nss_path=tmp_path)
        assert checker.nss_path == tmp_path

    def test_is_configured_no_directory(self, tmp_path: Path):
        """Test is_configured when directory doesn't exist."""
        checker = NSSChecker(nss_path=tmp_path / "nonexistent")
        assert checker.is_configured() is False

    def test_is_configured_empty_directory(self, tmp_path: Path):
        """Test is_configured when directory exists but is empty."""
        checker = NSSChecker(nss_path=tmp_path)
        assert checker.is_configured() is False

    def test_is_configured_with_modern_files(self, tmp_path: Path):
        """Test is_configured with SQLite format files."""
        (tmp_path / "cert9.db").touch()
        (tmp_path / "key4.db").touch()

        checker = NSSChecker(nss_path=tmp_path)
        assert checker.is_configured() is True

    def test_is_configured_with_legacy_files(self, tmp_path: Path):
        """Test is_configured with BerkeleyDB format files."""
        (tmp_path / "cert8.db").touch()
        (tmp_path / "key3.db").touch()
        (tmp_path / "secmod.db").touch()

        checker = NSSChecker(nss_path=tmp_path)
        assert checker.is_configured() is True

    def test_is_configured_partial_modern_files(self, tmp_path: Path):
        """Test is_configured with only some modern files."""
        (tmp_path / "cert9.db").touch()
        # Missing key4.db

        checker = NSSChecker(nss_path=tmp_path)
        assert checker.is_configured() is False

    def test_get_status_no_directory(self, tmp_path: Path):
        """Test get_status when directory doesn't exist."""
        checker = NSSChecker(nss_path=tmp_path / "nonexistent")
        configured, reason = checker.get_status()

        assert configured is False
        assert "does not exist" in reason

    def test_get_status_configured(self, tmp_path: Path):
        """Test get_status when properly configured."""
        (tmp_path / "cert9.db").touch()
        (tmp_path / "key4.db").touch()

        checker = NSSChecker(nss_path=tmp_path)
        configured, reason = checker.get_status()

        assert configured is True
        assert reason == ""

    def test_get_status_not_initialized(self, tmp_path: Path):
        """Test get_status when directory exists but empty."""
        checker = NSSChecker(nss_path=tmp_path)
        configured, reason = checker.get_status()

        assert configured is False
        assert "not initialized" in reason

    def test_get_status_path_is_file(self, tmp_path: Path):
        """Test get_status when path is a file, not directory."""
        file_path = tmp_path / "notadir"
        file_path.touch()

        checker = NSSChecker(nss_path=file_path)
        configured, reason = checker.get_status()

        assert configured is False
        assert "not a directory" in reason


class TestNSSCheckerCertutil:
    """Tests for certutil availability checking."""

    def test_is_certutil_available_found(self):
        """Test when certutil is available."""
        with patch("shutil.which", return_value="/usr/bin/certutil"):
            checker = NSSChecker()
            assert checker.is_certutil_available() is True

    def test_is_certutil_available_not_found(self):
        """Test when certutil is not available."""
        with patch("shutil.which", return_value=None):
            checker = NSSChecker()
            assert checker.is_certutil_available() is False

    def test_get_install_instructions_contains_distros(self):
        """Test install instructions contain major distros."""
        checker = NSSChecker()
        instructions = checker.get_install_instructions()

        assert "Ubuntu" in instructions or "Debian" in instructions
        assert "Fedora" in instructions
        assert "Arch" in instructions
        assert "libnss3-tools" in instructions or "nss-tools" in instructions


class TestNSSCheckerGetPath:
    """Tests for get_nss_path method."""

    def test_get_nss_path_default(self):
        """Test getting default path."""
        checker = NSSChecker()
        assert checker.get_nss_path() == Path.home() / ".nss"

    def test_get_nss_path_custom(self, tmp_path: Path):
        """Test getting custom path."""
        checker = NSSChecker(nss_path=tmp_path)
        assert checker.get_nss_path() == tmp_path
