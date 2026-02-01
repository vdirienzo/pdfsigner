"""
Platform detection utilities.

Provides reliable OS detection for cross-platform compatibility.
"""

import sys
from enum import Enum
from functools import lru_cache


class Platform(Enum):
    """Supported operating systems."""

    LINUX = "linux"
    MACOS = "darwin"
    WINDOWS = "win32"
    UNKNOWN = "unknown"


@lru_cache(maxsize=1)
def get_platform() -> Platform:
    """
    Detect the current operating system.

    Returns:
        Platform enum value for the current OS.

    Note:
        Result is cached for performance.
    """
    platform_map = {
        "linux": Platform.LINUX,
        "darwin": Platform.MACOS,
        "win32": Platform.WINDOWS,
        "cygwin": Platform.WINDOWS,
        "msys": Platform.WINDOWS,
    }

    return platform_map.get(sys.platform, Platform.UNKNOWN)


def is_linux() -> bool:
    """Check if running on Linux."""
    return get_platform() == Platform.LINUX


def is_macos() -> bool:
    """Check if running on macOS."""
    return get_platform() == Platform.MACOS


def is_windows() -> bool:
    """Check if running on Windows."""
    return get_platform() == Platform.WINDOWS
