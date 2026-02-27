"""
recent_manager.py - Recent PDF files manager

Wraps Gtk.RecentManager with PDF-specific filtering.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


@dataclass
class RecentFileInfo:
    """Information about a recent file."""

    path: Path
    display_name: str
    added_time: datetime
    exists: bool


class RecentFilesManager:
    """Manages recent PDF files using GTK RecentManager."""

    MIME_TYPE = "application/pdf"
    APP_NAME = "pdfsigner"

    def __init__(self, limit: int = 10):
        try:
            self._manager = Gtk.RecentManager.get_default()
        except Exception:
            # May fail without a display (tests, CLI)
            self._manager = None
        self._limit = limit

    def add_file(self, path: Path, operation: str = "signed") -> bool:
        """Add a file to recent history.

        Args:
            path: Path to the PDF file
            operation: Type of operation (signed, validated, opened)

        Returns:
            True if added successfully
        """
        if not path.exists():
            return False

        if self._manager is None:
            return False

        try:
            uri = path.as_uri()
            # Use simple add_item (add_full with RecentData causes SIGABRT in tests)
            return self._manager.add_item(uri)
        except Exception:
            # GTK operations may fail without a display
            return False

    def get_recent_pdfs(self) -> list[RecentFileInfo]:
        """Get list of recent PDF files.

        Returns:
            List of RecentFileInfo sorted by time (newest first)
        """
        from pdfsigner.config.settings import get_settings

        settings = get_settings()
        if not settings.recent_files_enabled:
            return []

        if self._manager is None:
            return []

        items = self._manager.get_items()
        pdf_files: list[RecentFileInfo] = []

        for item in items:
            # Filter by MIME type and app
            if item.get_mime_type() != self.MIME_TYPE:
                continue

            if not item.has_application(self.APP_NAME):
                continue

            try:
                uri = item.get_uri()
                if not uri.startswith("file://"):
                    continue

                path = Path(uri[7:])  # Remove file://

                pdf_files.append(
                    RecentFileInfo(
                        path=path,
                        display_name=item.get_display_name(),
                        added_time=datetime.fromtimestamp(item.get_modified()),
                        exists=path.exists(),
                    )
                )
            except Exception as e:
                from loguru import logger

                logger.debug(f"Failed to parse recent file entry: {e}")
                continue

        # Sort by time (newest first) and limit
        pdf_files.sort(key=lambda x: x.added_time, reverse=True)
        return pdf_files[: settings.recent_files_limit]

    def clear_pdf_history(self) -> int:
        """Clear PDFSigner entries from recent history.

        Returns:
            Number of items removed
        """
        if self._manager is None:
            return 0

        items = self._manager.get_items()
        removed = 0

        for item in items:
            if item.has_application(self.APP_NAME):
                try:
                    self._manager.remove_item(item.get_uri())
                    removed += 1
                except Exception as e:
                    from loguru import logger

                    logger.debug(f"Failed to remove recent item {item.get_uri()}: {e}")

        return removed


# Singleton
_manager: RecentFilesManager | None = None


def get_recent_files_manager() -> RecentFilesManager:
    """Get the singleton RecentFilesManager instance."""
    global _manager
    if _manager is None:
        from pdfsigner.config.settings import get_settings

        settings = get_settings()
        _manager = RecentFilesManager(limit=settings.recent_files_limit)
    return _manager
