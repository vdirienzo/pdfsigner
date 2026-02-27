"""HIPAA compliance reporting module for PDFSigner."""

from pdfsigner.core.reports.hipaa_pdf_exporter import export_hipaa_pdf
from pdfsigner.core.reports.hipaa_report import (
    HIPAAReportGenerator,
    generate_hipaa_report,
)
from pdfsigner.core.reports.hipaa_types import (
    EmergencyAccessSummary,
    EncryptionSummary,
    HIPAAReport,
    PHIAccessSummary,
    ReportConfig,
    ReportSection,
    UserAccessSummary,
)
from pdfsigner.core.types.report_format import ReportFormat

__all__ = [
    "ReportFormat",
    "ReportSection",
    "ReportConfig",
    "UserAccessSummary",
    "EncryptionSummary",
    "EmergencyAccessSummary",
    "PHIAccessSummary",
    "HIPAAReport",
    "HIPAAReportGenerator",
    "generate_hipaa_report",
    "export_hipaa_pdf",
]
