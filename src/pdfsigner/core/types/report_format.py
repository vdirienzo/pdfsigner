"""Shared report format enum used across compliance and reporting modules."""

from enum import Enum


class ReportFormat(str, Enum):
    """Output format for generated reports."""

    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    CEF = "cef"  # Common Event Format for SIEM
