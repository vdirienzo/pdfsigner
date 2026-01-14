"""
sign_extension.py - Nautilus extension for PDF signing

Author: Homero Thompson del Lago del Terror

Adds "Sign digitally" option to Nautilus context menu for PDF files.
Supports two modes (configured in ~/.config/pdfsigner/config.toml):
  - gui: Opens the full PDFSigner application
  - quick: Signs directly with preconfigured options (only asks for PIN)
"""

import subprocess
from pathlib import Path
from urllib.parse import unquote, urlparse

import gi

gi.require_version("Nautilus", "4.1")
gi.require_version("GObject", "2.0")

from gi.repository import GObject, Nautilus

# Project path for launching commands
# __file__ = .../pdfsigner/src/pdfsigner/nautilus_extension/sign_extension.py
# We need:  .../pdfsigner (4 parents up)
PROJECT_PATH = Path(__file__).parent.parent.parent.parent


def _get_nautilus_mode() -> str:
    """Get configured Nautilus mode from settings."""
    try:
        import sys
        # Ensure project is in path
        site_packages = PROJECT_PATH / ".venv/lib/python3.13/site-packages"
        src_path = PROJECT_PATH / "src"
        if str(site_packages) not in sys.path:
            sys.path.insert(0, str(site_packages))
        if str(src_path) not in sys.path:
            sys.path.insert(0, str(src_path))

        from pdfsigner.config.settings import get_settings
        settings = get_settings()
        return settings.nautilus_mode
    except Exception:
        return "gui"  # Default to GUI mode on error


class PDFSignerExtension(GObject.GObject, Nautilus.MenuProvider):
    """
    Nautilus extension for digital PDF signing.

    Adds context menu option when PDF files are selected.
    """

    def __init__(self):
        """Initialize the extension."""
        super().__init__()
        self._mode = _get_nautilus_mode()

    def get_file_items(
        self,
        files: list[Nautilus.FileInfo],
    ) -> list[Nautilus.MenuItem] | None:
        """
        Nautilus callback to get menu items.

        Args:
            files: List of selected files

        Returns:
            List of menu items or None
        """
        # Filter only PDFs
        pdf_files = [f for f in files if self._is_pdf(f)]

        if not pdf_files:
            return None

        # Create menu item with mode indicator
        count = len(pdf_files)
        if self._mode == "quick":
            label = "Sign digitally (quick)" if count == 1 else f"Sign {count} PDFs (quick)"
            tip = "Sign directly with preconfigured options"
        else:
            label = "Sign digitally" if count == 1 else f"Sign {count} PDFs"
            tip = "Open PDFSigner to configure and sign"

        item = Nautilus.MenuItem(
            name="PDFSigner::Sign",
            label=label,
            tip=tip,
        )

        item.connect("activate", self._on_sign_activate, pdf_files)

        return [item]

    def _is_pdf(self, file_info: Nautilus.FileInfo) -> bool:
        """Check if a file is a PDF."""
        mime = file_info.get_mime_type()
        return mime == "application/pdf"

    def _get_path_from_uri(self, uri: str) -> str:
        """Convert Nautilus URI to file path."""
        parsed = urlparse(uri)
        return unquote(parsed.path)

    def _on_sign_activate(
        self,
        menu: Nautilus.MenuItem,
        files: list[Nautilus.FileInfo],
    ) -> None:
        """
        Handle menu activation.

        Args:
            menu: Activated menu item
            files: List of selected PDF files
        """
        # Convert URIs to paths
        pdf_paths = [self._get_path_from_uri(f.get_uri()) for f in files]

        # Launch based on mode
        if self._mode == "quick":
            self._launch_quick_sign(pdf_paths)
        else:
            self._launch_gui(pdf_paths)

    def _launch_gui(self, pdf_paths: list[str]) -> None:
        """
        Launch the PDFSigner GUI with the given files.

        Args:
            pdf_paths: List of PDF file paths
        """
        try:
            cmd = [
                "uv",
                "run",
                "--directory",
                str(PROJECT_PATH),
                "pdfsigner-gui",
            ] + pdf_paths

            subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[PDFSigner] Error launching GUI: {e}")

    def _launch_quick_sign(self, pdf_paths: list[str]) -> None:
        """
        Launch quick sign mode with the given files.

        Args:
            pdf_paths: List of PDF file paths
        """
        try:
            cmd = [
                "uv",
                "run",
                "--directory",
                str(PROJECT_PATH),
                "pdfsigner-quick-sign",
            ] + pdf_paths

            subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[PDFSigner] Error launching quick sign: {e}")
