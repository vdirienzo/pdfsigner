"""Recent files management for PDFSigner."""

from pdfsigner.core.recent.recent_manager import (
    RecentFileInfo,
    RecentFilesManager,
    get_recent_files_manager,
)

__all__ = ["RecentFilesManager", "RecentFileInfo", "get_recent_files_manager"]
