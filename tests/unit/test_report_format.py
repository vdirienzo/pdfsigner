"""
test_report_format.py - Tests for shared ReportFormat enum

Verifies that the consolidated ReportFormat enum is consistent
across all modules that previously defined their own version.
"""

from pdfsigner.core.types.report_format import ReportFormat


class TestReportFormatValues:
    """Tests for ReportFormat enum values."""

    def test_has_exactly_four_members(self):
        """ReportFormat should have exactly 4 values: pdf, json, csv, cef."""
        members = list(ReportFormat)
        assert len(members) == 4

    def test_pdf_value(self):
        """PDF value should be 'pdf'."""
        assert ReportFormat.PDF.value == "pdf"

    def test_json_value(self):
        """JSON value should be 'json'."""
        assert ReportFormat.JSON.value == "json"

    def test_csv_value(self):
        """CSV value should be 'csv'."""
        assert ReportFormat.CSV.value == "csv"

    def test_cef_value(self):
        """CEF value should be 'cef'."""
        assert ReportFormat.CEF.value == "cef"

    def test_is_str_enum(self):
        """ReportFormat should inherit from str for string comparison."""
        assert isinstance(ReportFormat.PDF, str)
        assert ReportFormat.PDF == "pdf"

    def test_create_from_string(self):
        """ReportFormat should be constructible from string values."""
        assert ReportFormat("pdf") is ReportFormat.PDF
        assert ReportFormat("json") is ReportFormat.JSON
        assert ReportFormat("csv") is ReportFormat.CSV
        assert ReportFormat("cef") is ReportFormat.CEF


class TestReportFormatIdentityAcrossModules:
    """Verify all modules expose the SAME ReportFormat class (identity check)."""

    def test_reports_hipaa_uses_same_class(self):
        """hipaa_report.ReportFormat should be the shared ReportFormat."""
        from pdfsigner.core.reports.hipaa_report import (
            ReportFormat as HipaaReportFormat,
        )

        assert HipaaReportFormat is ReportFormat

    def test_reports_report_generator_uses_same_class(self):
        """reports/report_generator.ReportFormat should be the shared ReportFormat."""
        from pdfsigner.core.reports.report_generator import (
            ReportFormat as ValidationReportFormat,
        )

        assert ValidationReportFormat is ReportFormat

    def test_compliance_report_generator_uses_same_class(self):
        """compliance/report_generator.ReportFormat should be the shared ReportFormat."""
        from pdfsigner.core.compliance.report_generator import (
            ReportFormat as ComplianceReportFormat,
        )

        assert ComplianceReportFormat is ReportFormat

    def test_reports_init_reexport_uses_same_class(self):
        """reports/__init__.py re-export should be the shared ReportFormat."""
        from pdfsigner.core.reports import ReportFormat as ReportsReportFormat

        assert ReportsReportFormat is ReportFormat

    def test_compliance_init_reexport_uses_same_class(self):
        """compliance/__init__.py re-export should be the shared ReportFormat."""
        from pdfsigner.core.compliance import (
            ReportFormat as ComplianceReportFormat,
        )

        assert ComplianceReportFormat is ReportFormat

    def test_types_init_reexport_uses_same_class(self):
        """types/__init__.py re-export should be the shared ReportFormat."""
        from pdfsigner.core.types import ReportFormat as TypesReportFormat

        assert TypesReportFormat is ReportFormat
