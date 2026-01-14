"""
sign_extension.py - Nautilus extension for PDF signing

Author: Homero Thompson del Lago del Terror

Adds "Sign digitally" option to Nautilus context menu for PDF files.
Launches the standalone GUI application with the selected files.
"""

import subprocess
from pathlib import Path
from urllib.parse import unquote, urlparse

import gi

gi.require_version("Nautilus", "4.1")
gi.require_version("GObject", "2.0")

from gi.repository import GObject, Nautilus

# Project path for launching GUI
PROJECT_PATH = Path(__file__).parent.parent.parent.parent.parent


class PDFSignerExtension(GObject.GObject, Nautilus.MenuProvider):
    """
    Nautilus extension for digital PDF signing.

    Adds context menu option when PDF files are selected.
    """

    def __init__(self):
        """Initialize the extension."""
        super().__init__()

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

        # Create menu item
        count = len(pdf_files)
        label = "Sign digitally" if count == 1 else f"Sign {count} PDFs"

        item = Nautilus.MenuItem(
            name="PDFSigner::Sign",
            label=label,
            tip="Sign with digital certificate (USB token)",
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

        # Launch GUI with the files
        self._launch_gui(pdf_paths)

    def _launch_gui(self, pdf_paths: list[str]) -> None:
        """
        Launch the PDFSigner GUI with the given files.

        Args:
            pdf_paths: List of PDF file paths
        """
        try:
            # Build command to run GUI via uv
            cmd = [
                "uv",
                "run",
                "--directory",
                str(PROJECT_PATH),
                "pdfsigner-gui",
            ] + pdf_paths

            # Launch without blocking Nautilus
            subprocess.Popen(
                cmd,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[PDFSigner] Error launching GUI: {e}")
