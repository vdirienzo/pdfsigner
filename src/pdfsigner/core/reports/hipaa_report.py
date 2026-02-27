"""
hipaa_report.py - HIPAA compliance audit report generator

Generates comprehensive audit reports for HIPAA compliance verification.
Supports PDF, JSON, and CSV export formats.
"""

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from loguru import logger

# PDF Layout Constants
PDF_PAGE_WIDTH = 612
PDF_PAGE_HEIGHT = 792
PDF_MARGIN_LEFT = 72
PDF_INDENT_LEFT = 90
PDF_INDENT_NESTED = 110
PDF_TITLE_FONT_SIZE = 24
PDF_HEADING_FONT_SIZE = 14
PDF_BODY_FONT_SIZE = 12
PDF_ITEM_FONT_SIZE = 11
PDF_DETAIL_FONT_SIZE = 10
PDF_FOOTER_FONT_SIZE = 9
PDF_LINE_HEIGHT = 16
PDF_SECTION_SPACING = 10
PDF_PAGE_BREAK_Y = 650
PDF_FOOTER_Y = 750


class ReportFormat(str, Enum):
    """Output format for HIPAA reports."""

    PDF = "pdf"
    JSON = "json"
    CSV = "csv"


class ReportSection(str, Enum):
    """Sections available in HIPAA report."""

    SUMMARY = "summary"
    USER_ACCESS = "user_access"
    ENCRYPTION_USAGE = "encryption_usage"
    EMERGENCY_ACCESS = "emergency_access"
    PHI_ACCESS = "phi_access"
    AUDIT_INTEGRITY = "audit_integrity"


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    start_date: datetime
    end_date: datetime
    sections: list[ReportSection] = field(default_factory=list)
    format: ReportFormat = ReportFormat.PDF
    include_details: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "sections": [s.value for s in self.sections],
            "format": self.format.value,
            "include_details": self.include_details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportConfig":
        """Create from dictionary."""
        return cls(
            start_date=datetime.fromisoformat(data["start_date"]),
            end_date=datetime.fromisoformat(data["end_date"]),
            sections=[ReportSection(s) for s in data.get("sections", [])],
            format=ReportFormat(data.get("format", "pdf")),
            include_details=data.get("include_details", True),
        )


@dataclass
class UserAccessSummary:
    """Summary of user access for the report period."""

    total_users: int
    active_users: int
    logins: int
    failed_logins: int
    sessions_created: int
    sessions_terminated: int
    unique_documents_accessed: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UserAccessSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class EncryptionSummary:
    """Summary of encryption operations."""

    documents_encrypted: int
    documents_decrypted: int
    encryption_method: str  # aes256
    phi_documents_encrypted: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EncryptionSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class EmergencyAccessSummary:
    """Summary of emergency access (break-glass)."""

    requests_made: int
    requests_approved: int
    requests_denied: int
    documents_accessed: int
    unique_users: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmergencyAccessSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class PHIAccessSummary:
    """Summary of PHI detection and access."""

    documents_scanned: int
    documents_with_phi: int
    phi_types_detected: dict[str, int]  # {ssn: 5, email: 10, ...}
    blocked_operations: int  # Operations blocked due to PHI

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PHIAccessSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class HIPAAReport:
    """Complete HIPAA audit report."""

    report_id: str
    title: str
    organization: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime

    # Sections
    user_access: UserAccessSummary | None = None
    encryption: EncryptionSummary | None = None
    emergency_access: EmergencyAccessSummary | None = None
    phi_access: PHIAccessSummary | None = None

    # Compliance status
    compliance_status: str = "unknown"  # compliant, warning, non_compliant
    compliance_checks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Convert datetime objects
        data["generated_at"] = self.generated_at.isoformat()
        data["period_start"] = self.period_start.isoformat()
        data["period_end"] = self.period_end.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HIPAAReport":
        """Create from dictionary."""
        # Convert datetime strings
        data["generated_at"] = datetime.fromisoformat(data["generated_at"])
        data["period_start"] = datetime.fromisoformat(data["period_start"])
        data["period_end"] = datetime.fromisoformat(data["period_end"])

        # Convert nested dataclasses
        if data.get("user_access"):
            data["user_access"] = UserAccessSummary.from_dict(data["user_access"])
        if data.get("encryption"):
            data["encryption"] = EncryptionSummary.from_dict(data["encryption"])
        if data.get("emergency_access"):
            data["emergency_access"] = EmergencyAccessSummary.from_dict(data["emergency_access"])
        if data.get("phi_access"):
            data["phi_access"] = PHIAccessSummary.from_dict(data["phi_access"])

        return cls(**data)


class HIPAAReportGenerator:
    """Generates HIPAA compliance audit reports."""

    def __init__(self):
        """Initialize report generator."""
        self._settings = None

    @property
    def settings(self):
        """Lazy-load settings."""
        if self._settings is None:
            from pdfsigner.config.settings import get_settings

            self._settings = get_settings()
        return self._settings

    def generate(
        self,
        config: ReportConfig,
        output_path: Path | None = None,
    ) -> HIPAAReport:
        """
        Generate a HIPAA audit report.

        Args:
            config: Report configuration with date range and sections
            output_path: Optional path to export report file

        Returns:
            Generated HIPAAReport object
        """
        from uuid import uuid4

        report = HIPAAReport(
            report_id=str(uuid4()),
            title="HIPAA Compliance Audit Report",
            organization="PDFSigner",
            generated_at=datetime.now(UTC),
            period_start=config.start_date,
            period_end=config.end_date,
        )

        # Load audit events once to avoid redundant queries
        audit_events = None
        audit_sections = {
            ReportSection.USER_ACCESS,
            ReportSection.ENCRYPTION_USAGE,
            ReportSection.PHI_ACCESS,
        }
        if audit_sections & set(config.sections):
            try:
                from pdfsigner.core.audit import get_audit_logger

                audit = get_audit_logger()
                audit_events = audit.get_events(
                    start_date=config.start_date,
                    end_date=config.end_date,
                )
            except Exception as e:
                logger.warning(f"Could not pre-load audit events: {e}")

        # Generate each requested section
        if ReportSection.USER_ACCESS in config.sections:
            report.user_access = self._generate_user_access(config, audit_events)

        if ReportSection.ENCRYPTION_USAGE in config.sections:
            report.encryption = self._generate_encryption_summary(config, audit_events)

        if ReportSection.EMERGENCY_ACCESS in config.sections:
            report.emergency_access = self._generate_emergency_summary(config)

        if ReportSection.PHI_ACCESS in config.sections:
            report.phi_access = self._generate_phi_summary(config, audit_events)

        # Get compliance status if available
        try:
            from pdfsigner.core.compliance import get_compliance_checker

            checker = get_compliance_checker()
            compliance = checker.check_all()
            report.compliance_status = compliance.overall_status.value
            report.compliance_checks = [c.to_dict() for c in compliance.checks]
        except (ImportError, AttributeError) as e:
            logger.debug(f"Compliance checker not available: {e}")
            report.compliance_status = "unknown"

        # Export to file if requested
        if output_path:
            self._export_report(report, output_path, config.format)

        logger.info(f"Generated HIPAA report: {report.report_id}")
        return report

    def _generate_user_access(
        self, config: ReportConfig, events: list | None = None
    ) -> UserAccessSummary:
        """
        Generate user access summary from audit logs.

        Args:
            config: Report configuration with date range
            events: Pre-loaded audit events (avoids redundant queries)

        Returns:
            UserAccessSummary with aggregated statistics
        """
        try:
            if events is None:
                from pdfsigner.core.audit import get_audit_logger

                audit = get_audit_logger()
                events = audit.get_events(
                    start_date=config.start_date,
                    end_date=config.end_date,
                )

            # Count session events
            logins = sum(1 for e in events if e.event_type.value == "session_start")
            failed = sum(1 for e in events if e.event_type.value == "access_denied")
            sessions_ended = sum(1 for e in events if e.event_type.value == "session_end")

            # Count unique users
            users = set(
                e.user_id for e in events if e.user_id and e.event_type.value == "session_start"
            )

            # Count unique documents
            docs = set(e.document_path for e in events if e.document_path)

            return UserAccessSummary(
                total_users=len(users),
                active_users=len(users),
                logins=logins,
                failed_logins=failed,
                sessions_created=logins,
                sessions_terminated=sessions_ended,
                unique_documents_accessed=len(docs),
            )
        except Exception as e:
            logger.warning(f"Could not generate user access summary: {e}")
            return UserAccessSummary(
                total_users=0,
                active_users=0,
                logins=0,
                failed_logins=0,
                sessions_created=0,
                sessions_terminated=0,
                unique_documents_accessed=0,
            )

    def _generate_encryption_summary(
        self, config: ReportConfig, events: list | None = None
    ) -> EncryptionSummary:
        """
        Generate encryption usage summary.

        Args:
            config: Report configuration with date range
            events: Pre-loaded audit events (avoids redundant queries)

        Returns:
            EncryptionSummary with encryption statistics
        """
        try:
            if events is None:
                from pdfsigner.core.audit import get_audit_logger

                audit = get_audit_logger()
                events = audit.get_events(
                    start_date=config.start_date,
                    end_date=config.end_date,
                )

            encrypted = sum(1 for e in events if e.event_type.value == "encrypt_success")
            decrypted = sum(1 for e in events if e.event_type.value == "decrypt_success")
            phi_encrypted = sum(
                1
                for e in events
                if e.event_type.value == "encrypt_success" and e.details.get("has_phi", False)
            )

            return EncryptionSummary(
                documents_encrypted=encrypted,
                documents_decrypted=decrypted,
                encryption_method=self.settings.encryption_strength,
                phi_documents_encrypted=phi_encrypted,
            )
        except Exception as e:
            logger.warning(f"Could not generate encryption summary: {e}")
            return EncryptionSummary(
                documents_encrypted=0,
                documents_decrypted=0,
                encryption_method="aes256",
                phi_documents_encrypted=0,
            )

    def _generate_emergency_summary(self, config: ReportConfig) -> EmergencyAccessSummary:
        """
        Generate emergency access summary.

        Args:
            config: Report configuration with date range

        Returns:
            EmergencyAccessSummary with emergency access statistics
        """
        try:
            from pdfsigner.core.emergency import get_emergency_repository

            repo = get_emergency_repository()

            # Get all requests and filter by date manually
            # (EmergencyAccessRepository doesn't have date-range query)
            all_requests = []
            with repo._get_connection() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM emergency_requests
                    WHERE requested_at >= ? AND requested_at <= ?
                    ORDER BY requested_at DESC
                    """,
                    (config.start_date.isoformat(), config.end_date.isoformat()),
                ).fetchall()
                all_requests = [repo._row_to_request(row) for row in rows]

            approved = sum(1 for r in all_requests if r.status.value == "approved")
            denied = sum(1 for r in all_requests if r.status.value == "denied")
            users = set(r.requester_id for r in all_requests)
            docs = sum(len(r.documents_accessed or []) for r in all_requests)

            return EmergencyAccessSummary(
                requests_made=len(all_requests),
                requests_approved=approved,
                requests_denied=denied,
                documents_accessed=docs,
                unique_users=len(users),
            )
        except Exception as e:
            logger.warning(f"Could not generate emergency summary: {e}")
            return EmergencyAccessSummary(
                requests_made=0,
                requests_approved=0,
                requests_denied=0,
                documents_accessed=0,
                unique_users=0,
            )

    def _generate_phi_summary(
        self, config: ReportConfig, events: list | None = None
    ) -> PHIAccessSummary:
        """
        Generate PHI detection summary.

        Args:
            config: Report configuration with date range
            events: Pre-loaded audit events (avoids redundant queries)

        Returns:
            PHIAccessSummary with PHI detection statistics
        """
        try:
            if events is None:
                from pdfsigner.core.audit import get_audit_logger

                audit = get_audit_logger()
                events = audit.get_events(
                    start_date=config.start_date,
                    end_date=config.end_date,
                )

            # PHI-related events (if implemented in future)
            phi_detected_events = [
                e
                for e in events
                if e.details.get("phi_detected")
                or e.details.get("has_phi")
                or e.event_type.value in ["phi_detected", "phi_scan"]
            ]

            scanned = len(
                set(
                    e.document_path
                    for e in events
                    if e.document_path
                    and e.event_type.value
                    in ["sign_success", "validate_success", "encrypt_success"]
                )
            )
            with_phi = len(phi_detected_events)
            blocked = sum(1 for e in events if e.event_type.value == "access_denied")

            # Aggregate PHI types
            phi_types: dict[str, int] = {}
            for event in phi_detected_events:
                for phi_type, count in event.details.get("by_type", {}).items():
                    phi_types[phi_type] = phi_types.get(phi_type, 0) + count

            return PHIAccessSummary(
                documents_scanned=scanned,
                documents_with_phi=with_phi,
                phi_types_detected=phi_types,
                blocked_operations=blocked,
            )
        except Exception as e:
            logger.warning(f"Could not generate PHI summary: {e}")
            return PHIAccessSummary(
                documents_scanned=0,
                documents_with_phi=0,
                phi_types_detected={},
                blocked_operations=0,
            )

    def _export_report(self, report: HIPAAReport, path: Path, format: ReportFormat) -> None:
        """
        Export report to file.

        Args:
            report: HIPAAReport to export
            path: Output file path
            format: Export format (JSON, CSV, or PDF)
        """
        if format == ReportFormat.JSON:
            self._export_json(report, path)
        elif format == ReportFormat.CSV:
            self._export_csv(report, path)
        elif format == ReportFormat.PDF:
            self._export_pdf(report, path)

    def _export_json(self, report: HIPAAReport, path: Path) -> None:
        """
        Export as JSON.

        Args:
            report: HIPAAReport to export
            path: Output file path
        """
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        logger.info(f"Exported JSON report to {path}")

    def _export_csv(self, report: HIPAAReport, path: Path) -> None:
        """
        Export as CSV (summary only).

        Args:
            report: HIPAAReport to export
            path: Output file path
        """
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Section", "Metric", "Value"])

            if report.user_access:
                for key, value in report.user_access.to_dict().items():
                    writer.writerow(["User Access", key, value])

            if report.encryption:
                for key, value in report.encryption.to_dict().items():
                    writer.writerow(["Encryption", key, value])

            if report.emergency_access:
                for key, value in report.emergency_access.to_dict().items():
                    writer.writerow(["Emergency Access", key, value])

            if report.phi_access:
                for key, value in report.phi_access.to_dict().items():
                    if isinstance(value, dict):
                        writer.writerow(["PHI Access", key, json.dumps(value)])
                    else:
                        writer.writerow(["PHI Access", key, value])

        logger.info(f"Exported CSV report to {path}")

    def _export_pdf(self, report: HIPAAReport, path: Path) -> None:
        """
        Export as PDF using PyMuPDF.

        Args:
            report: HIPAAReport to export
            path: Output file path
        """
        try:
            import fitz  # PyMuPDF
        except ImportError:
            logger.error("PyMuPDF (fitz) not available. Cannot export PDF.")
            return

        doc = fitz.open()
        try:
            # Title page
            page = doc.new_page(width=PDF_PAGE_WIDTH, height=PDF_PAGE_HEIGHT)

            # Title
            page.insert_text(
                (PDF_MARGIN_LEFT, 100),
                report.title,
                fontsize=PDF_TITLE_FONT_SIZE,
                fontname="helv",
            )

            # Metadata
            page.insert_text(
                (PDF_MARGIN_LEFT, 140),
                f"Organization: {report.organization}",
                fontsize=PDF_BODY_FONT_SIZE,
            )
            page.insert_text(
                (PDF_MARGIN_LEFT, 160),
                f"Report ID: {report.report_id}",
                fontsize=PDF_BODY_FONT_SIZE,
            )
            page.insert_text(
                (PDF_MARGIN_LEFT, 180),
                f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
                fontsize=PDF_BODY_FONT_SIZE,
            )
            period_text = (
                f"Period: {report.period_start.strftime('%Y-%m-%d')} "
                f"to {report.period_end.strftime('%Y-%m-%d')}"
            )
            page.insert_text((PDF_MARGIN_LEFT, 200), period_text, fontsize=PDF_BODY_FONT_SIZE)

            # Compliance Status
            status_color = {
                "compliant": (0, 0.5, 0),
                "warning": (0.8, 0.6, 0),
                "non_compliant": (0.8, 0, 0),
            }.get(report.compliance_status, (0.5, 0.5, 0.5))
            page.insert_text(
                (PDF_MARGIN_LEFT, 240),
                f"Compliance Status: {report.compliance_status.upper()}",
                fontsize=PDF_HEADING_FONT_SIZE,
                color=status_color,
            )

            y = 280

            # User Access Section
            if report.user_access:
                page.insert_text(
                    (PDF_MARGIN_LEFT, y), "USER ACCESS SUMMARY", fontsize=PDF_HEADING_FONT_SIZE
                )
                y += 20
                ua = report.user_access
                for label, value in [
                    ("Total Users", ua.total_users),
                    ("Logins", ua.logins),
                    ("Failed Logins", ua.failed_logins),
                    ("Documents Accessed", ua.unique_documents_accessed),
                ]:
                    page.insert_text(
                        (PDF_INDENT_LEFT, y),
                        f"• {label}: {value}",
                        fontsize=PDF_ITEM_FONT_SIZE,
                    )
                    y += PDF_LINE_HEIGHT
                y += PDF_SECTION_SPACING

            # Encryption Section
            if report.encryption:
                page.insert_text(
                    (PDF_MARGIN_LEFT, y), "ENCRYPTION SUMMARY", fontsize=PDF_HEADING_FONT_SIZE
                )
                y += 20
                enc = report.encryption
                for label, value in [  # type: ignore[assignment]
                    ("Documents Encrypted", enc.documents_encrypted),
                    ("Documents Decrypted", enc.documents_decrypted),
                    ("Encryption Method", enc.encryption_method.upper()),
                    ("PHI Documents Encrypted", enc.phi_documents_encrypted),
                ]:
                    page.insert_text(
                        (PDF_INDENT_LEFT, y),
                        f"• {label}: {value}",
                        fontsize=PDF_ITEM_FONT_SIZE,
                    )
                    y += PDF_LINE_HEIGHT
                y += PDF_SECTION_SPACING

            # Emergency Access Section
            if report.emergency_access:
                page.insert_text(
                    (PDF_MARGIN_LEFT, y),
                    "EMERGENCY ACCESS SUMMARY",
                    fontsize=PDF_HEADING_FONT_SIZE,
                )
                y += 20
                ea = report.emergency_access
                for label, value in [
                    ("Requests Made", ea.requests_made),
                    ("Requests Approved", ea.requests_approved),
                    ("Requests Denied", ea.requests_denied),
                    ("Documents Accessed", ea.documents_accessed),
                ]:
                    page.insert_text(
                        (PDF_INDENT_LEFT, y),
                        f"• {label}: {value}",
                        fontsize=PDF_ITEM_FONT_SIZE,
                    )
                    y += PDF_LINE_HEIGHT
                y += PDF_SECTION_SPACING

            # PHI Access Section
            if report.phi_access:
                if y > PDF_PAGE_BREAK_Y:
                    page = doc.new_page(width=PDF_PAGE_WIDTH, height=PDF_PAGE_HEIGHT)
                    y = PDF_MARGIN_LEFT

                page.insert_text(
                    (PDF_MARGIN_LEFT, y),
                    "PHI DETECTION SUMMARY",
                    fontsize=PDF_HEADING_FONT_SIZE,
                )
                y += 20
                phi = report.phi_access
                for label, value in [
                    ("Documents Scanned", phi.documents_scanned),
                    ("Documents with PHI", phi.documents_with_phi),
                    ("Blocked Operations", phi.blocked_operations),
                ]:
                    page.insert_text(
                        (PDF_INDENT_LEFT, y),
                        f"• {label}: {value}",
                        fontsize=PDF_ITEM_FONT_SIZE,
                    )
                    y += PDF_LINE_HEIGHT

                if phi.phi_types_detected:
                    page.insert_text(
                        (PDF_INDENT_LEFT, y),
                        "• PHI Types Detected:",
                        fontsize=PDF_ITEM_FONT_SIZE,
                    )
                    y += PDF_LINE_HEIGHT
                    for phi_type, count in phi.phi_types_detected.items():
                        page.insert_text(
                            (PDF_INDENT_NESTED, y),
                            f"- {phi_type}: {count}",
                            fontsize=PDF_DETAIL_FONT_SIZE,
                        )
                        y += 14

            # Footer
            page.insert_text(
                (PDF_MARGIN_LEFT, PDF_FOOTER_Y),
                "Generated by PDFSigner HIPAA Compliance Module",
                fontsize=PDF_FOOTER_FONT_SIZE,
                color=(0.5, 0.5, 0.5),
            )

            doc.save(str(path))
        finally:
            doc.close()
        logger.info(f"Exported PDF report to {path}")


def generate_hipaa_report(
    days: int = 30,
    output_path: Path | None = None,
    format: ReportFormat = ReportFormat.PDF,
) -> HIPAAReport:
    """
    Convenience function to generate a HIPAA report for the last N days.

    Args:
        days: Number of days to include in report (default: 30)
        output_path: Optional path to export report file
        format: Export format (default: PDF)

    Returns:
        Generated HIPAAReport object
    """
    config = ReportConfig(
        start_date=datetime.now(UTC) - timedelta(days=days),
        end_date=datetime.now(UTC),
        sections=list(ReportSection),
        format=format,
    )
    generator = HIPAAReportGenerator()
    return generator.generate(config, output_path)
