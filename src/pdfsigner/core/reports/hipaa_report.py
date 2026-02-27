"""
hipaa_report.py - HIPAA compliance audit report generator

Generates comprehensive audit reports for HIPAA compliance verification.
Supports PDF, JSON, and CSV export formats.
"""

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.core.reports.hipaa_pdf_exporter import export_hipaa_pdf
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

# Re-export all types for backward compatibility
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
]


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
        """Generate user access summary from audit logs."""
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
        """Generate encryption usage summary."""
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
        """Generate emergency access summary."""
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
        """Generate PHI detection summary."""
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
        """Export report to file in the requested format."""
        if format == ReportFormat.JSON:
            self._export_json(report, path)
        elif format == ReportFormat.CSV:
            self._export_csv(report, path)
        elif format == ReportFormat.PDF:
            self._export_pdf(report, path)

    def _export_json(self, report: HIPAAReport, path: Path) -> None:
        """Export as JSON."""
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        logger.info(f"Exported JSON report to {path}")

    def _export_csv(self, report: HIPAAReport, path: Path) -> None:
        """Export as CSV (summary only)."""
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
        """Export as PDF using PyMuPDF (delegates to hipaa_pdf_exporter)."""
        export_hipaa_pdf(report, path)


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
