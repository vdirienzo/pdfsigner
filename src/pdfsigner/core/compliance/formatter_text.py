"""
formatter_text.py - Text-based compliance report formatters

Author: Homero Thompson del Lago del Terror

Implements text-based formatters for compliance reports:
- JSON: Structured data for programmatic access
- CSV: Controls matrix for spreadsheet analysis
- CEF: Common Event Format for SIEM integration
"""

import csv
import io
import json
from typing import Any

from pdfsigner.core.compliance.report_types import ReportConfig
from pdfsigner.core.compliance.status_types import ComplianceReport, ComplianceStatus


class JSONReportFormatter:
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


class CSVReportFormatter:
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


class CEFReportFormatter:
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

        CEF requires escaping: = | \\\\ (backslash must be doubled)

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
