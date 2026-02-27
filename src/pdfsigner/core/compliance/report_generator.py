"""
report_generator.py - Compliance report generation

Author: Homero Thompson del Lago del Terror

Generates compliance reports in multiple formats (PDF, JSON, CSV, CEF)
for government and healthcare compliance documentation.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.compliance.status_checker import (
    ComplianceStatusChecker,
)
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


@dataclass
class GeneratedReport:
    """Metadata for a generated report."""

    path: Path
    format: ReportFormat
    size_bytes: int
    generated_at: datetime
    checksum: str  # SHA-256 for integrity


class ComplianceReportGenerator:
    """
    Generate compliance reports in multiple formats.

    Supports:
    - PDF: Executive summary with charts and detailed findings
    - JSON: Full structured data for programmatic access
    - CSV: Controls matrix for spreadsheet analysis
    - CEF: Common Event Format for SIEM integration
    """

    def __init__(self, checker: ComplianceStatusChecker):
        """
        Initialize report generator.

        Args:
            checker: ComplianceStatusChecker instance to use for checks
        """
        self.checker = checker

    def generate(self, config: ReportConfig, output_path: Path) -> GeneratedReport:
        """
        Generate compliance report in specified format.

        Args:
            config: Report configuration
            output_path: Where to write the report

        Returns:
            GeneratedReport with metadata

        Raises:
            ValueError: If format is not supported
        """
        logger.info(f"Generating {config.format.value} compliance report to {output_path}")

        # Get compliance report data
        report = self.checker.check_all()

        # Filter by standards if specified
        reports_data = {"all": report}  # For now, we only have HIPAA

        # Generate based on format
        if config.format == ReportFormat.PDF:
            return self.generate_pdf(reports_data, output_path, config)
        elif config.format == ReportFormat.JSON:
            return self.generate_json(reports_data, output_path, config)
        elif config.format == ReportFormat.CSV:
            return self.generate_csv(reports_data, output_path, config)
        elif config.format == ReportFormat.CEF:
            return self.generate_cef(reports_data, output_path, config)
        else:
            raise ValueError(f"Unsupported format: {config.format}")

    def generate_pdf(
        self, reports: dict[str, Any], output_path: Path, config: ReportConfig
    ) -> GeneratedReport:
        """
        Generate PDF report with executive summary and charts.

        Args:
            reports: Dictionary of compliance reports by standard
            output_path: Output file path
            config: Report configuration

        Returns:
            GeneratedReport metadata
        """
        from pdfsigner.core.compliance.formatters import PDFReportFormatter

        formatter = PDFReportFormatter()
        content = formatter.format(reports, config)

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(content)

        # Calculate metadata
        size = output_path.stat().st_size
        checksum = hashlib.sha256(content).hexdigest()

        logger.info(
            f"Generated PDF report: {output_path} ({size} bytes, SHA-256: {checksum[:16]}...)"
        )

        return GeneratedReport(
            path=output_path,
            format=ReportFormat.PDF,
            size_bytes=size,
            generated_at=datetime.now(UTC),
            checksum=checksum,
        )

    def generate_json(
        self, reports: dict[str, Any], output_path: Path, config: ReportConfig
    ) -> GeneratedReport:
        """
        Generate JSON report with full details.

        Args:
            reports: Dictionary of compliance reports by standard
            output_path: Output file path
            config: Report configuration

        Returns:
            GeneratedReport metadata
        """
        from pdfsigner.core.compliance.formatters import JSONReportFormatter

        formatter = JSONReportFormatter()
        content = formatter.format(reports, config)

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

        # Calculate metadata
        size = output_path.stat().st_size
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        logger.info(
            f"Generated JSON report: {output_path} ({size} bytes, SHA-256: {checksum[:16]}...)"
        )

        return GeneratedReport(
            path=output_path,
            format=ReportFormat.JSON,
            size_bytes=size,
            generated_at=datetime.now(UTC),
            checksum=checksum,
        )

    def generate_csv(
        self, reports: dict[str, Any], output_path: Path, config: ReportConfig
    ) -> GeneratedReport:
        """
        Generate CSV controls matrix.

        Args:
            reports: Dictionary of compliance reports by standard
            output_path: Output file path
            config: Report configuration

        Returns:
            GeneratedReport metadata
        """
        from pdfsigner.core.compliance.formatters import CSVReportFormatter

        formatter = CSVReportFormatter()
        content = formatter.format(reports, config)

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

        # Calculate metadata
        size = output_path.stat().st_size
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        logger.info(
            f"Generated CSV report: {output_path} ({size} bytes, SHA-256: {checksum[:16]}...)"
        )

        return GeneratedReport(
            path=output_path,
            format=ReportFormat.CSV,
            size_bytes=size,
            generated_at=datetime.now(UTC),
            checksum=checksum,
        )

    def generate_cef(
        self, reports: dict[str, Any], output_path: Path, config: ReportConfig
    ) -> GeneratedReport:
        """
        Generate CEF format for SIEM integration.

        Args:
            reports: Dictionary of compliance reports by standard
            output_path: Output file path
            config: Report configuration

        Returns:
            GeneratedReport metadata
        """
        from pdfsigner.core.compliance.formatters import CEFReportFormatter

        formatter = CEFReportFormatter()
        content = formatter.format(reports, config)

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

        # Calculate metadata
        size = output_path.stat().st_size
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        logger.info(
            f"Generated CEF report: {output_path} ({size} bytes, SHA-256: {checksum[:16]}...)"
        )

        return GeneratedReport(
            path=output_path,
            format=ReportFormat.CEF,
            size_bytes=size,
            generated_at=datetime.now(UTC),
            checksum=checksum,
        )


# Singleton
_report_generator: ComplianceReportGenerator | None = None


def get_report_generator() -> ComplianceReportGenerator:
    """
    Get ComplianceReportGenerator singleton instance.

    Returns:
        ComplianceReportGenerator instance
    """
    global _report_generator
    if _report_generator is None:
        from pdfsigner.core.compliance import get_compliance_checker

        _report_generator = ComplianceReportGenerator(get_compliance_checker())
    return _report_generator


__all__ = [
    "ReportFormat",
    "ReportConfig",
    "GeneratedReport",
    "ComplianceReportGenerator",
    "get_report_generator",
]
