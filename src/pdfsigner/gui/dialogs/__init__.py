"""
dialogs - GTK4/Adwaita dialogs for PDFSigner

This module contains custom dialogs used throughout the application.
"""

from .certificate_details_dialog import CertificateDetailsDialog
from .emergency_access_dialog import EmergencyAccessDialog
from .export_report_dialog import ExportReportDialog
from .shortcuts_window import ShortcutsWindow

__all__ = [
    "CertificateDetailsDialog",
    "EmergencyAccessDialog",
    "ExportReportDialog",
    "ShortcutsWindow",
]
