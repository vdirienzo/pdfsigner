"""
report_types.py - Shared report types for compliance module

Extracted from report_generator.py to break circular import between
formatters.py and report_generator.py.
"""

from dataclasses import dataclass

from pdfsigner.core.types.report_format import ReportFormat


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    format: ReportFormat
    standards: list[str] | None = None  # Which standards to include, or ["all"]
    include_evidence: bool = True
    include_recommendations: bool = True
    executive_summary: bool = True

    def __post_init__(self):
        """Initialize default values."""
        if self.standards is None:
            self.standards = ["all"]


__all__ = [
    "ReportConfig",
]
