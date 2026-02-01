"""
Tests for the cross-platform module.

Tests platform detection and path generation for Linux, macOS, and Windows.
"""

import sys
from pathlib import Path
from unittest.mock import patch


class TestPlatformDetector:
    """Tests for platform detection."""

    def test_get_platform_returns_enum(self):
        """get_platform should return a Platform enum value."""
        from pdfsigner.core.platform import Platform, get_platform

        result = get_platform()
        assert isinstance(result, Platform)

    def test_get_platform_linux(self):
        """get_platform should detect Linux correctly."""
        from pdfsigner.core.platform.detector import Platform, get_platform

        # Clear the cache to test with mocked value
        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            result = get_platform()
            assert result == Platform.LINUX

        get_platform.cache_clear()

    def test_get_platform_macos(self):
        """get_platform should detect macOS correctly."""
        from pdfsigner.core.platform.detector import Platform, get_platform

        get_platform.cache_clear()

        with patch.object(sys, "platform", "darwin"):
            result = get_platform()
            assert result == Platform.MACOS

        get_platform.cache_clear()

    def test_get_platform_windows(self):
        """get_platform should detect Windows correctly."""
        from pdfsigner.core.platform.detector import Platform, get_platform

        get_platform.cache_clear()

        with patch.object(sys, "platform", "win32"):
            result = get_platform()
            assert result == Platform.WINDOWS

        get_platform.cache_clear()

    def test_get_platform_cygwin_as_windows(self):
        """Cygwin should be detected as Windows."""
        from pdfsigner.core.platform.detector import Platform, get_platform

        get_platform.cache_clear()

        with patch.object(sys, "platform", "cygwin"):
            result = get_platform()
            assert result == Platform.WINDOWS

        get_platform.cache_clear()

    def test_get_platform_unknown(self):
        """Unknown platforms should return UNKNOWN."""
        from pdfsigner.core.platform.detector import Platform, get_platform

        get_platform.cache_clear()

        with patch.object(sys, "platform", "freebsd"):
            result = get_platform()
            assert result == Platform.UNKNOWN

        get_platform.cache_clear()

    def test_is_linux(self):
        """is_linux should return True only on Linux."""
        from pdfsigner.core.platform.detector import get_platform, is_linux

        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            assert is_linux() is True

        get_platform.cache_clear()

        with patch.object(sys, "platform", "darwin"):
            assert is_linux() is False

        get_platform.cache_clear()

    def test_is_macos(self):
        """is_macos should return True only on macOS."""
        from pdfsigner.core.platform.detector import get_platform, is_macos

        get_platform.cache_clear()

        with patch.object(sys, "platform", "darwin"):
            assert is_macos() is True

        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            assert is_macos() is False

        get_platform.cache_clear()

    def test_is_windows(self):
        """is_windows should return True only on Windows."""
        from pdfsigner.core.platform.detector import get_platform, is_windows

        get_platform.cache_clear()

        with patch.object(sys, "platform", "win32"):
            assert is_windows() is True

        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            assert is_windows() is False

        get_platform.cache_clear()


class TestPlatformPaths:
    """Tests for platform-specific paths."""

    def test_get_pkcs11_extension_linux(self):
        """Linux should use .so extension."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.paths import get_pkcs11_extension

        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            assert get_pkcs11_extension() == ".so"

        get_platform.cache_clear()

    def test_get_pkcs11_extension_macos(self):
        """macOS should use .dylib extension."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.paths import get_pkcs11_extension

        get_platform.cache_clear()

        with patch.object(sys, "platform", "darwin"):
            assert get_pkcs11_extension() == ".dylib"

        get_platform.cache_clear()

    def test_get_pkcs11_extension_windows(self):
        """Windows should use .dll extension."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.paths import get_pkcs11_extension

        get_platform.cache_clear()

        with patch.object(sys, "platform", "win32"):
            assert get_pkcs11_extension() == ".dll"

        get_platform.cache_clear()

    def test_get_config_dir_linux(self):
        """Linux config dir should follow XDG standard."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.paths import get_config_dir

        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            with patch.dict("os.environ", {"XDG_CONFIG_HOME": ""}, clear=False):
                result = get_config_dir()
                assert "pdfsigner" in str(result)
                assert ".config" in str(result)

        get_platform.cache_clear()

    def test_get_config_dir_macos(self):
        """macOS config dir should use Application Support."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.paths import get_config_dir

        get_platform.cache_clear()

        with patch.object(sys, "platform", "darwin"):
            result = get_config_dir()
            assert "pdfsigner" in str(result)
            assert "Application Support" in str(result)

        get_platform.cache_clear()

    def test_get_config_dir_windows(self):
        """Windows config dir should use APPDATA."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.paths import get_config_dir

        get_platform.cache_clear()

        with patch.object(sys, "platform", "win32"):
            with patch.dict("os.environ", {"APPDATA": "C:\\Users\\Test\\AppData\\Roaming"}):
                result = get_config_dir()
                assert "pdfsigner" in str(result)

        get_platform.cache_clear()

    def test_get_nss_db_path_returns_path(self):
        """get_nss_db_path should return a Path object."""
        from pdfsigner.core.platform.paths import get_nss_db_path

        result = get_nss_db_path()
        assert isinstance(result, Path)

    def test_get_trust_store_paths_returns_list(self):
        """get_trust_store_paths should return a list of Paths."""
        from pdfsigner.core.platform.paths import get_trust_store_paths

        result = get_trust_store_paths()
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(p, Path) for p in result)


class TestPKCS11Paths:
    """Tests for PKCS#11 library paths."""

    def test_get_all_pkcs11_paths_returns_dict(self):
        """get_all_pkcs11_paths should return a dictionary."""
        from pdfsigner.core.platform.pkcs11_paths import get_all_pkcs11_paths

        result = get_all_pkcs11_paths()
        assert isinstance(result, dict)
        assert "yubikey" in result
        assert "opensc" in result

    def test_get_pkcs11_paths_for_vendor_yubikey(self):
        """Should return YubiKey paths for the current platform."""
        from pdfsigner.core.platform.pkcs11_paths import get_pkcs11_paths_for_vendor

        result = get_pkcs11_paths_for_vendor("yubikey")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(p, Path) for p in result)

    def test_get_pkcs11_paths_for_vendor_unknown(self):
        """Unknown vendor should return empty list."""
        from pdfsigner.core.platform.pkcs11_paths import get_pkcs11_paths_for_vendor

        result = get_pkcs11_paths_for_vendor("unknown_vendor")
        assert result == []

    def test_get_pkcs11_lib_groups_returns_tuples(self):
        """get_pkcs11_lib_groups should return list of tuples."""
        from pdfsigner.core.platform.pkcs11_paths import get_pkcs11_lib_groups

        result = get_pkcs11_lib_groups()
        assert isinstance(result, list)
        assert len(result) > 0

        # Each entry should be (name, paths)
        for name, paths in result:
            assert isinstance(name, str)
            assert isinstance(paths, list)

    def test_find_pkcs11_library_returns_none_when_not_found(self):
        """find_pkcs11_library should return None if no library exists."""
        from pdfsigner.core.platform.pkcs11_paths import find_pkcs11_library

        # Search for a vendor that won't have libraries on test system
        result = find_pkcs11_library("ncipher")
        # Result depends on system, just verify it returns Path or None
        assert result is None or isinstance(result, Path)

    def test_linux_paths_use_so_extension(self):
        """Linux paths should use .so extension."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.pkcs11_paths import get_all_pkcs11_paths

        get_platform.cache_clear()

        with patch.object(sys, "platform", "linux"):
            paths = get_all_pkcs11_paths()
            for vendor_paths in paths.values():
                for path in vendor_paths:
                    assert str(path).endswith(".so"), f"Linux path should end with .so: {path}"

        get_platform.cache_clear()

    def test_macos_paths_use_dylib_extension(self):
        """macOS paths should use .dylib extension."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.pkcs11_paths import get_all_pkcs11_paths

        get_platform.cache_clear()

        with patch.object(sys, "platform", "darwin"):
            paths = get_all_pkcs11_paths()
            for vendor_paths in paths.values():
                for path in vendor_paths:
                    assert str(path).endswith(".dylib"), (
                        f"macOS path should end with .dylib: {path}"
                    )

        get_platform.cache_clear()

    def test_windows_paths_use_dll_extension(self):
        """Windows paths should use .dll extension."""
        from pdfsigner.core.platform.detector import get_platform
        from pdfsigner.core.platform.pkcs11_paths import get_all_pkcs11_paths

        get_platform.cache_clear()

        with patch.object(sys, "platform", "win32"):
            with patch.dict(
                "os.environ",
                {
                    "PROGRAMFILES": "C:\\Program Files",
                    "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
                    "SYSTEMROOT": "C:\\Windows",
                },
            ):
                paths = get_all_pkcs11_paths()
                for vendor_paths in paths.values():
                    for path in vendor_paths:
                        assert str(path).endswith(".dll"), (
                            f"Windows path should end with .dll: {path}"
                        )

        get_platform.cache_clear()


class TestBackwardCompatibility:
    """Tests for backward compatibility with legacy pkcs11_libs.py API."""

    def test_pkcs11_lib_groups_exists(self):
        """Legacy PKCS11_LIB_GROUPS should still be available."""
        from pdfsigner.core.token.pkcs11_libs import PKCS11_LIB_GROUPS

        assert PKCS11_LIB_GROUPS is not None
        assert isinstance(PKCS11_LIB_GROUPS, list)

    def test_vendor_path_lists_exist(self):
        """Legacy vendor path lists should still be available as strings."""
        from pdfsigner.core.token.pkcs11_libs import (
            FEITIAN_LIB_PATHS,
            NCIPHER_LIB_PATHS,
            NITROKEY_LIB_PATHS,
            NSS_LIB_PATHS,
            OPENSC_LIB_PATHS,
            SAFENET_LIB_PATHS,
            SOFTHSM_LIB_PATHS,
            YUBIKEY_LIB_PATHS,
        )

        # All should be lists of strings
        for paths in [
            SAFENET_LIB_PATHS,
            YUBIKEY_LIB_PATHS,
            NITROKEY_LIB_PATHS,
            OPENSC_LIB_PATHS,
            FEITIAN_LIB_PATHS,
            SOFTHSM_LIB_PATHS,
            NCIPHER_LIB_PATHS,
            NSS_LIB_PATHS,
        ]:
            assert isinstance(paths, list)
            assert all(isinstance(p, str) for p in paths)

    def test_find_library_function_exists(self):
        """Legacy find_library function should still work."""
        from pdfsigner.core.token.pkcs11_libs import find_library

        # Should return string or None
        result = find_library()
        assert result is None or isinstance(result, str)

    def test_get_platform_info_function(self):
        """get_platform_info should return platform flags."""
        from pdfsigner.core.token.pkcs11_libs import get_platform_info

        result = get_platform_info()
        assert isinstance(result, dict)
        assert "is_linux" in result
        assert "is_macos" in result
        assert "is_windows" in result
        assert all(isinstance(v, bool) for v in result.values())
