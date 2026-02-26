"""
formatters.py - Compliance report formatters

Author: Homero Thompson del Lago del Terror

Implements formatters for different report formats:
- PDF: Executive summary with visual layout
- JSON: Structured data for programmatic access
- CSV: Controls matrix for spreadsheet analysis
- CEF: Common Event Format for SIEM integration
"""

import csv
import io
import json
from abc import ABC, abstractmethod
from typing import Any

import fitz  # PyMuPDF

from pdfsigner.core.compliance.report_generator import ReportConfig
from pdfsigner.core.compliance.status_checker import ComplianceReport, ComplianceStatus

# PDF Layout Constants
MARGIN_LEFT = 50
MARGIN_RIGHT_OFFSET = 50  # Subtracted from page width
PAGE_BREAK_Y = 700
TITLE_FONT_SIZE = 24
HEADING_FONT_SIZE = 18
SUBHEADING_FONT_SIZE = 14
BODY_FONT_SIZE = 11
DETAIL_FONT_SIZE = 9
EVIDENCE_FONT_SIZE = 8
SMALL_FONT_SIZE = 10
CHECK_HEADER_FONT_SIZE = 12
INDENT_LEFT = 70

# Status symbols shared across formatters
STATUS_SYMBOLS: dict[ComplianceStatus, str] = {
    ComplianceStatus.COMPLIANT: "✓",
    ComplianceStatus.WARNING: "⚠",
    ComplianceStatus.NON_COMPLIANT: "✗",
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


class PDFReportFormatter(ReportFormatter):
    """
    Generate PDF compliance reports using PyMuPDF.

    Creates a professional report with:
    - Title page with metadata
    - Executive summary with overall score
    - Detailed findings by category
    - Recommendations section
    """

    def format(self, reports: dict[str, Any], config: ReportConfig) -> bytes:
        """
        Generate PDF report.

        Args:
            reports: Dictionary of compliance reports by standard
            config: Report configuration

        Returns:
            PDF content as bytes
        """
        doc = fitz.open()  # Create new PDF

        # Get the main report
        report_obj = reports.get("all")
        if not report_obj or not isinstance(report_obj, ComplianceReport):
            raise ValueError("No compliance report found")
        report: ComplianceReport = report_obj

        # Add title page
        self._add_title_page(doc, report)

        # Add executive summary if requested
        if config.executive_summary:
            self._add_executive_summary(doc, report)

        # Add detailed findings
        self._add_detailed_findings(doc, report, config)

        # Add recommendations if requested
        if config.include_recommendations:
            self._add_recommendations(doc, report)

        # Convert to bytes
        pdf_bytes = doc.tobytes()
        doc.close()

        return pdf_bytes

    def _add_title_page(self, doc: fitz.Document, report: ComplianceReport) -> None:
        """Add title page to PDF."""
        page = doc.new_page()
        width = page.rect.width
        right = width - MARGIN_RIGHT_OFFSET

        # Title
        title_rect = fitz.Rect(MARGIN_LEFT, 100, right, 150)
        page.insert_textbox(
            title_rect,
            "COMPLIANCE REPORT",
            fontsize=TITLE_FONT_SIZE,
            fontname="Helvetica-Bold",
            align=fitz.TEXT_ALIGN_CENTER,
        )

        # Subtitle
        subtitle_rect = fitz.Rect(MARGIN_LEFT, 160, right, 190)
        page.insert_textbox(
            subtitle_rect,
            "PDFSigner Healthcare Compliance",
            fontsize=SUBHEADING_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_CENTER,
        )

        # Generated date
        date_rect = fitz.Rect(MARGIN_LEFT, 200, right, 230)
        page.insert_textbox(
            date_rect,
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            fontsize=BODY_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_CENTER,
        )

        # Overall status indicator
        status_text = (
            f"{STATUS_SYMBOLS.get(report.overall_status, '?')} "
            f"{report.overall_status.value.upper()}"
        )

        status_rect = fitz.Rect(MARGIN_LEFT, 250, right, 290)
        page.insert_textbox(
            status_rect,
            status_text,
            fontsize=HEADING_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_CENTER,
        )

    def _add_executive_summary(self, doc: fitz.Document, report: ComplianceReport) -> None:
        """Add executive summary page."""
        page = doc.new_page()
        width = page.rect.width
        right = width - MARGIN_RIGHT_OFFSET
        y_pos = MARGIN_LEFT

        # Section title
        title_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 30)
        page.insert_textbox(
            title_rect,
            "EXECUTIVE SUMMARY",
            fontsize=HEADING_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_LEFT,
        )
        y_pos += 50

        # Overall compliance score
        total_checks = len(report.checks)
        score = (report.compliant_count / total_checks * 100) if total_checks > 0 else 0
        score_text = f"Overall Compliance Score: {score:.0f}/100"

        score_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 20)
        page.insert_textbox(
            score_rect,
            score_text,
            fontsize=SUBHEADING_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_LEFT,
        )
        y_pos += 40

        # Standards assessed
        standards_text = "Standards Assessed:\n\n• HIPAA §164.312 (Security Rule)"

        standards_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 60)
        page.insert_textbox(
            standards_rect,
            standards_text,
            fontsize=BODY_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_LEFT,
        )
        y_pos += 80

        # Summary statistics
        stats_text = f"""Compliance Statistics:

• Compliant: {report.compliant_count} checks
• Warnings: {report.warning_count} checks
• Non-Compliant: {report.non_compliant_count} checks

Total Checks: {total_checks}"""

        stats_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 150)
        page.insert_textbox(
            stats_rect,
            stats_text,
            fontsize=BODY_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_LEFT,
        )

    def _add_detailed_findings(
        self, doc: fitz.Document, report: ComplianceReport, config: ReportConfig
    ) -> None:
        """Add detailed findings pages."""
        page = doc.new_page()
        width = page.rect.width
        right = width - MARGIN_RIGHT_OFFSET
        y_pos = MARGIN_LEFT

        # Section title
        title_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 30)
        page.insert_textbox(
            title_rect,
            "DETAILED FINDINGS",
            fontsize=HEADING_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_LEFT,
        )
        y_pos += 50

        # List each check
        for check in report.checks:
            # Check if we need a new page
            if y_pos > PAGE_BREAK_Y:
                page = doc.new_page()
                y_pos = MARGIN_LEFT

            symbol = STATUS_SYMBOLS.get(check.status, "?")

            # Check header
            header_text = f"{symbol} {check.name}"
            header_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 20)
            page.insert_textbox(
                header_rect,
                header_text,
                fontsize=CHECK_HEADER_FONT_SIZE,
                fontname="Helvetica-Bold",
                align=fitz.TEXT_ALIGN_LEFT,
            )
            y_pos += 25

            # Reference
            ref_text = f"Reference: {check.hipaa_reference}"
            ref_rect = fitz.Rect(INDENT_LEFT, y_pos, right, y_pos + 15)
            page.insert_textbox(
                ref_rect,
                ref_text,
                fontsize=DETAIL_FONT_SIZE,
                fontname="Helvetica",
                align=fitz.TEXT_ALIGN_LEFT,
            )
            y_pos += 20

            # Details
            details_text = f"{check.description}\n{check.details}"
            details_rect = fitz.Rect(INDENT_LEFT, y_pos, right, y_pos + 40)
            page.insert_textbox(
                details_rect,
                details_text,
                fontsize=DETAIL_FONT_SIZE,
                fontname="Helvetica",
                align=fitz.TEXT_ALIGN_LEFT,
            )
            y_pos += 45

            # Evidence if requested
            if config.include_evidence and check.status == ComplianceStatus.COMPLIANT:
                evidence_text = f"Evidence: {check.details}"
                evidence_rect = fitz.Rect(INDENT_LEFT, y_pos, right, y_pos + 25)
                page.insert_textbox(
                    evidence_rect,
                    evidence_text,
                    fontsize=EVIDENCE_FONT_SIZE,
                    fontname="Helvetica",
                    align=fitz.TEXT_ALIGN_LEFT,
                    color=(0.3, 0.3, 0.3),
                )
                y_pos += 30

            y_pos += 10  # Spacing between checks

    def _add_recommendations(self, doc: fitz.Document, report: ComplianceReport) -> None:
        """Add recommendations page."""
        # Get all checks that have remediation suggestions
        checks_with_remediation = [c for c in report.checks if c.remediation]

        if not checks_with_remediation:
            return  # No recommendations to add

        page = doc.new_page()
        width = page.rect.width
        right = width - MARGIN_RIGHT_OFFSET
        y_pos = MARGIN_LEFT

        # Section title
        title_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 30)
        page.insert_textbox(
            title_rect,
            "RECOMMENDATIONS",
            fontsize=HEADING_FONT_SIZE,
            fontname="Helvetica",
            align=fitz.TEXT_ALIGN_LEFT,
        )
        y_pos += 50

        # List recommendations
        for i, check in enumerate(checks_with_remediation, 1):
            if y_pos > PAGE_BREAK_Y:
                page = doc.new_page()
                y_pos = MARGIN_LEFT

            rec_text = f"{i}. {check.name}\n   {check.remediation}"
            rec_rect = fitz.Rect(MARGIN_LEFT, y_pos, right, y_pos + 40)
            page.insert_textbox(
                rec_rect,
                rec_text,
                fontsize=SMALL_FONT_SIZE,
                fontname="Helvetica",
                align=fitz.TEXT_ALIGN_LEFT,
            )
            y_pos += 50


class JSONReportFormatter(ReportFormatter):
    """Generate JSON compliance reports with full structured data."""

    def format(self, reports: dict[str, Any], config: ReportConfig) -> str:
        """
        Generate JSON report.

        Args:
            reports: Dictionary of compliance reports by standard
            config: Report configuration

        Returns:
            JSON string
        """
        report_obj = reports.get("all")
        if not report_obj or not isinstance(report_obj, ComplianceReport):
            raise ValueError("No compliance report found")
        report: ComplianceReport = report_obj

        # Build report structure
        output = {
            "report_metadata": {
                "generated_at": report.generated_at.isoformat(),
                "format": "json",
                "version": "1.0",
                "generator": "PDFSigner ComplianceReportGenerator",
            },
            "summary": {
                "overall_status": report.overall_status.value,
                "is_compliant": report.is_hipaa_compliant,
                "total_checks": len(report.checks),
                "compliant_count": report.compliant_count,
                "warning_count": report.warning_count,
                "non_compliant_count": report.non_compliant_count,
                "compliance_score": (
                    report.compliant_count / len(report.checks) * 100
                    if len(report.checks) > 0
                    else 0
                ),
            },
            "checks": [check.to_dict() for check in report.checks],
        }

        # Add recommendations if requested
        if config.include_recommendations:
            output["recommendations"] = [
                {"check": c.name, "remediation": c.remediation}
                for c in report.checks
                if c.remediation
            ]

        return json.dumps(output, indent=2)


class CSVReportFormatter(ReportFormatter):
    """Generate CSV compliance reports as controls matrix."""

    def format(self, reports: dict[str, Any], config: ReportConfig) -> str:
        """
        Generate CSV report.

        Args:
            reports: Dictionary of compliance reports by standard
            config: Report configuration

        Returns:
            CSV string
        """
        report_obj = reports.get("all")
        if not report_obj or not isinstance(report_obj, ComplianceReport):
            raise ValueError("No compliance report found")
        report: ComplianceReport = report_obj

        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        headers = ["Standard", "Control ID", "Name", "Category", "Status", "Description", "Details"]
        if config.include_recommendations:
            headers.append("Remediation")

        writer.writerow(headers)

        # Data rows
        for check in report.checks:
            row = [
                "HIPAA",
                check.hipaa_reference,
                check.name,
                check.category.value,
                check.status.value,
                check.description,
                check.details,
            ]

            if config.include_recommendations:
                row.append(check.remediation or "")

            writer.writerow(row)

        return output.getvalue()


class CEFReportFormatter(ReportFormatter):
    """
    Generate CEF (Common Event Format) compliance reports for SIEM.

    CEF Format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """

    def format(self, reports: dict[str, Any], config: ReportConfig) -> str:
        """
        Generate CEF report.

        Args:
            reports: Dictionary of compliance reports by standard
            config: Report configuration

        Returns:
            CEF formatted string (one event per line)
        """
        report_obj = reports.get("all")
        if not report_obj or not isinstance(report_obj, ComplianceReport):
            raise ValueError("No compliance report found")
        report: ComplianceReport = report_obj

        lines = []

        # Add overall compliance assessment event
        overall_severity = self._status_to_severity(report.overall_status)
        overall_event = (
            f"CEF:0|PDFSigner|ComplianceChecker|1.0|compliance_assessment|"
            f"Overall Compliance Assessment|{overall_severity}|"
            f"src=localhost dst=compliance_report "
            f"cs1Label=Standard cs1=HIPAA "
            f"cn1Label=CompliantCount cn1={report.compliant_count} "
            f"cn2Label=WarningCount cn2={report.warning_count} "
            f"cn3Label=NonCompliantCount cn3={report.non_compliant_count} "
            f"msg={report.overall_status.value} overall status"
        )
        lines.append(overall_event)

        # Add individual check events
        for check in report.checks:
            severity = self._status_to_severity(check.status)
            msg = self._escape_cef(check.details)

            event = (
                f"CEF:0|PDFSigner|ComplianceChecker|1.0|compliance_check|"
                f"Compliance Check|{severity}|"
                f"src=localhost dst=compliance_report "
                f"cs1Label=Standard cs1=HIPAA "
                f"cs2Label=ControlID cs2={self._escape_cef(check.hipaa_reference)} "
                f"cs3Label=Category cs3={check.category.value} "
                f"cs4Label=Status cs4={check.status.value} "
                f"cs5Label=CheckName cs5={self._escape_cef(check.name)} "
                f"msg={msg}"
            )
            lines.append(event)

        return "\n".join(lines) + "\n"

    def _status_to_severity(self, status: ComplianceStatus) -> int:
        """
        Convert ComplianceStatus to CEF severity (0-10).

        Args:
            status: ComplianceStatus enum value

        Returns:
            CEF severity level (0=low, 5=medium, 10=high)
        """
        severity_map = {
            ComplianceStatus.COMPLIANT: 1,  # Informational
            ComplianceStatus.WARNING: 5,  # Medium
            ComplianceStatus.NON_COMPLIANT: 8,  # High
            ComplianceStatus.UNKNOWN: 3,  # Low
        }
        return severity_map.get(status, 0)

    def _escape_cef(self, text: str) -> str:
        """
        Escape special characters for CEF format.

        CEF requires escaping: = | \\ (backslash must be doubled)

        Args:
            text: Text to escape

        Returns:
            Escaped text
        """
        # Escape backslash first, then others
        text = text.replace("\\", "\\\\")
        text = text.replace("=", "\\=")
        text = text.replace("|", "\\|")
        return text


__all__ = [
    "ReportFormatter",
    "PDFReportFormatter",
    "JSONReportFormatter",
    "CSVReportFormatter",
    "CEFReportFormatter",
]
