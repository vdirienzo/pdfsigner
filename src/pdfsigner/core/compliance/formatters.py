"""
formatters.py - Compliance report formatters (facade)

Author: Homero Thompson del Lago del Terror

Facade module that re-exports all formatter classes.
Actual implementations live in:
- formatter_pdf.py: PDFReportFormatter (PyMuPDF)
- formatter_text.py: JSONReportFormatter, CSVReportFormatter, CEFReportFormatter

All imports via `from pdfsigner.core.compliance.formatters import X` continue to work.
"""

from abc import ABC, abstractmethod
from typing import Any

from pdfsigner.core.compliance.formatter_pdf import PDFReportFormatter
from pdfsigner.core.compliance.formatter_text import (
    CEFReportFormatter,
    CSVReportFormatter,
    JSONReportFormatter,
)
from pdfsigner.core.compliance.report_types import ReportConfig
from pdfsigner.core.compliance.status_types import ComplianceStatus

# Status symbols shared across formatters
STATUS_SYMBOLS: dict[ComplianceStatus, str] = {
    ComplianceStatus.COMPLIANT: "\u2713",
    ComplianceStatus.WARNING: "\u26a0",
    ComplianceStatus.NON_COMPLIANT: "\u2717",
    ComplianceStatus.UNKNOWN: "?",
}


class ReportFormatter(ABC):
    """Base class for report formatters."""

    @abstractmethod
    def format(self, reports: dict[str, Any], config: ReportConfig) -> bytes | str:
        """
        Format compliance report data.

        Args:
            reports: Dictionary of compliance reports by standard
            config: Report configuration

        Returns:
            Formatted report as bytes (PDF) or string (JSON/CSV/CEF)
        """


__all__ = [
    "ReportFormatter",
    "PDFReportFormatter",
    "JSONReportFormatter",
    "CSVReportFormatter",
    "CEFReportFormatter",
    "STATUS_SYMBOLS",
]
