"""
data_export.py - User data export for GDPR compliance

Implements GDPR Article 20: Right to data portability.
Exports all user data in machine-readable format (JSON or CSV).
"""

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit import get_audit_logger
from pdfsigner.core.users import get_user_repository


@dataclass
class UserDataExport:
    """Container for exported user data."""

    user_info: dict
    certificates: list[dict]
    audit_events: list[dict]
    sessions: list[dict]
    generated_at: datetime
    format: str  # "json" | "csv"
    metadata: dict = field(default_factory=dict)


class UserDataExporter:
    """
    Export user data for GDPR Article 20 compliance.

    Exports all data associated with a user including:
    - User profile information
    - Certificate bindings
    - Audit trail (actions performed by user)
    - Session history
    """

    def __init__(self, user_repository=None, audit_logger=None):
        """
        Initialize data exporter.

        Args:
            user_repository: UserRepository instance (default: singleton)
            audit_logger: AuditLogger instance (default: singleton)
        """
        self.user_repo = user_repository or get_user_repository()
        self.audit_logger = audit_logger or get_audit_logger()

    def export_user_data(self, user_id: str, format: str = "json") -> UserDataExport | None:
        """
        Export all data for a user (GDPR Article 20).

        Args:
            user_id: User ID to export data for
            format: Export format ("json" or "csv")

        Returns:
            UserDataExport with all user data, or None if user not found
        """
        logger.info(f"Exporting user data: {user_id} (format={format})")

        try:
            # Get user
            user = self.user_repo.get_user_by_id(user_id)
            if not user:
                logger.error(f"Cannot export: User not found: {user_id}")
                return None

            # Collect user information
            user_info = user.to_dict()

            # Collect certificate information
            certificates = []
            if user.certificate_serial and user.certificate_issuer:
                certificates.append(
                    {
                        "serial": user.certificate_serial,
                        "issuer": user.certificate_issuer,
                        "common_name": user.certificate_cn,
                        "bound_at": user.created_at.isoformat(),
                    }
                )

            # Collect audit events
            audit_events = []
            if self.audit_logger.enabled:
                events = self.audit_logger.get_events_filtered(user_id=user_id, limit=10000)
                audit_events = [
                    {
                        "event_id": e.event_id,
                        "timestamp": e.timestamp.isoformat(),
                        "event_type": e.event_type.value,
                        "status": e.status,
                        "document_path": e.document_path,
                        "details": e.details,
                    }
                    for e in events
                ]

            # Collect session information
            sessions = self._get_user_sessions(user_id)

            # Create export
            export = UserDataExport(
                user_info=user_info,
                certificates=certificates,
                audit_events=audit_events,
                sessions=sessions,
                generated_at=datetime.now(UTC),
                format=format,
                metadata={
                    "user_id": user_id,
                    "username": user.username,
                    "export_reason": "GDPR Article 20 - Right to data portability",
                },
            )

            logger.info(
                f"User data exported: {user_id} "
                f"(events={len(audit_events)}, sessions={len(sessions)})"
            )

            return export

        except Exception as e:
            logger.error(f"Failed to export user data for {user_id}: {e}")
            return None

    def export_to_file(self, user_id: str, output_path: str | Path, format: str = "json") -> bool:
        """
        Export user data to file.

        Args:
            user_id: User ID to export
            output_path: Output file path
            format: Export format ("json" or "csv")

        Returns:
            True if export succeeded
        """
        logger.info(f"Exporting user data to file: {user_id} -> {output_path}")

        try:
            # Export data
            export = self.export_user_data(user_id, format=format)
            if not export:
                return False

            output_path = Path(output_path)

            # Write to file
            if format == "json":
                self._write_json_export(export, output_path)
            elif format == "csv":
                self._write_csv_export(export, output_path)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False

            logger.info(f"User data exported to file: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export user data to file: {e}")
            return False

    def export_to_json_string(self, user_id: str) -> str | None:
        """
        Export user data as JSON string.

        Args:
            user_id: User ID to export

        Returns:
            JSON string with all user data, or None if export failed
        """
        try:
            export = self.export_user_data(user_id, format="json")
            if not export:
                return None

            data = {
                "user_info": export.user_info,
                "certificates": export.certificates,
                "audit_events": export.audit_events,
                "sessions": export.sessions,
                "generated_at": export.generated_at.isoformat(),
                "metadata": export.metadata,
            }

            return json.dumps(data, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Failed to export user data as JSON: {e}")
            return None

    def _write_json_export(self, export: UserDataExport, output_path: Path) -> None:
        """Write export data to JSON file."""
        data = {
            "user_info": export.user_info,
            "certificates": export.certificates,
            "audit_events": export.audit_events,
            "sessions": export.sessions,
            "generated_at": export.generated_at.isoformat(),
            "metadata": export.metadata,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _write_csv_export(self, export: UserDataExport, output_path: Path) -> None:
        """Write export data to CSV files (multiple files in ZIP)."""
        import zipfile

        # Create ZIP file with multiple CSV files
        with zipfile.ZipFile(output_path, "w") as zf:
            # User info CSV
            user_csv = self._dict_to_csv([export.user_info], "User Information")
            zf.writestr("user_info.csv", user_csv)

            # Certificates CSV
            if export.certificates:
                cert_csv = self._dict_to_csv(export.certificates, "Certificates")
                zf.writestr("certificates.csv", cert_csv)

            # Audit events CSV
            if export.audit_events:
                events_csv = self._dict_to_csv(export.audit_events, "Audit Events")
                zf.writestr("audit_events.csv", events_csv)

            # Sessions CSV
            if export.sessions:
                sessions_csv = self._dict_to_csv(export.sessions, "Sessions")
                zf.writestr("sessions.csv", sessions_csv)

            # Metadata
            metadata_csv = self._dict_to_csv([export.metadata], "Export Metadata")
            zf.writestr("metadata.csv", metadata_csv)

    def _dict_to_csv(self, data: list[dict], title: str = "") -> str:
        """Convert list of dicts to CSV string."""
        if not data:
            return ""

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())

        if title:
            writer.writerow({k: title for k in data[0].keys()})

        writer.writeheader()
        for row in data:
            # Convert nested dicts/lists to JSON strings
            cleaned_row = {}
            for k, v in row.items():
                if isinstance(v, (dict, list)):
                    cleaned_row[k] = json.dumps(v)
                else:
                    cleaned_row[k] = v
            writer.writerow(cleaned_row)

        return output.getvalue()

    def _get_user_sessions(self, user_id: str) -> list[dict]:
        """
        Get user session history.

        Args:
            user_id: User ID

        Returns:
            List of session dicts
        """
        try:
            from pdfsigner.core.session import get_session_manager

            session_manager = get_session_manager()
            sessions = session_manager.get_user_sessions(user_id)

            return [
                {
                    "session_id": s.session_id,
                    "created_at": s.created_at.isoformat(),
                    "last_activity": s.last_activity.isoformat(),
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent,
                    "is_active": s.is_active,
                }
                for s in sessions
            ]

        except Exception as e:
            logger.warning(f"Failed to get user sessions: {e}")
            return []


# Singleton instance
_user_data_exporter: UserDataExporter | None = None


def get_user_data_exporter() -> UserDataExporter:
    """Get singleton user data exporter."""
    global _user_data_exporter
    if _user_data_exporter is None:
        _user_data_exporter = UserDataExporter()
    return _user_data_exporter
