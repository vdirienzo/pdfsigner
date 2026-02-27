"""
audit_query.py - Audit event query and export service

Author: Homero Thompson del Lago del Terror

Read-only operations for querying and exporting audit events
from JSON Lines log files with date/type/user filtering.
"""

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType


class AuditQueryService:
    """
    Query and export audit events from JSON Lines log files.

    Provides read-only access to audit logs with filtering by date range,
    event type, user, session, PHI access, and status. Also supports
    CSV export.
    """

    def __init__(self, log_dir: Path, enabled: bool = True):
        """
        Initialize query service.

        Args:
            log_dir: Directory containing audit log files
            enabled: Whether querying is enabled
        """
        self.log_dir = log_dir
        self.enabled = enabled

    def get_events(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        event_types: list[AuditEventType] | None = None,
    ) -> list[AuditEvent]:
        """
        Query events with filters.

        Args:
            start_date: Filter events after this date (inclusive)
            end_date: Filter events before this date (inclusive)
            event_types: Filter by event types (None = all types)

        Returns:
            List of matching AuditEvent objects, sorted by timestamp
        """
        if not self.enabled:
            return []

        events: list[AuditEvent] = []

        try:
            # Determine which log files to read
            log_files = self._get_log_files_in_range(start_date, end_date)

            # Read and filter events
            for log_file in log_files:
                if not log_file.exists():
                    continue

                with open(log_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            event = AuditEvent.from_dict(data)

                            # Apply filters
                            if start_date and event.timestamp < start_date:
                                continue
                            if end_date and event.timestamp > end_date:
                                # Events are chronological; stop reading this file
                                break
                            if event_types and event.event_type not in event_types:
                                continue

                            events.append(event)

                        except Exception as e:
                            logger.warning(f"Skipping invalid audit entry: {e}")

            # Sort by timestamp
            events.sort(key=lambda e: e.timestamp)

        except Exception as e:
            logger.error(f"Error querying audit events: {e}")

        return events

    def get_events_filtered(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        event_types: list[AuditEventType] | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        phi_accessed: bool | None = None,
        status: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        """
        Get filtered audit events with HIPAA-compliant filters.

        Args:
            start_date: Filter from date
            end_date: Filter to date
            event_types: Filter by event types
            user_id: Filter by user ID
            session_id: Filter by session ID
            phi_accessed: Filter by PHI access flag
            status: Filter by status (SUCCESS, FAILURE, ERROR)
            limit: Maximum number of events to return

        Returns:
            List of matching events
        """
        if not self.enabled:
            return []

        events: list[AuditEvent] = []

        try:
            # Determine which log files to read
            log_files = self._get_log_files_in_range(start_date, end_date)

            # Read and filter events
            for log_file in log_files:
                if not log_file.exists():
                    continue

                with open(log_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            event = AuditEvent.from_dict(data)

                            # Apply filters
                            if start_date and event.timestamp < start_date:
                                continue
                            if end_date and event.timestamp > end_date:
                                # Events are chronological; stop reading this file
                                break
                            if event_types and event.event_type not in event_types:
                                continue
                            if user_id and event.user_id != user_id:
                                continue
                            if session_id and event.session_id != session_id:
                                continue
                            if phi_accessed is not None and event.phi_accessed != phi_accessed:
                                continue
                            if status and event.status != status:
                                continue

                            events.append(event)

                        except Exception as e:
                            logger.warning(f"Skipping invalid audit entry: {e}")

            # Sort all events first, then apply limit for consistent ordering
            events.sort(key=lambda e: e.timestamp)

            if limit and len(events) > limit:
                events = events[:limit]

        except Exception as e:
            logger.error(f"Error querying filtered audit events: {e}")

        return events

    def _get_log_files_in_range(
        self,
        start_date: datetime | None,
        end_date: datetime | None,
    ) -> list[Path]:
        """
        Get log files that may contain events in the date range.

        Args:
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of log file paths to check
        """
        if not self.log_dir.exists():
            return []

        # If no range specified, return all log files
        if start_date is None and end_date is None:
            return sorted(self.log_dir.glob("audit_*.jsonl"))

        # Generate list of year-months to check
        year_months = set()

        # Use current month as default end
        current = start_date or datetime.now(UTC)
        end = end_date or datetime.now(UTC)

        while current <= end:
            year_months.add(current.strftime("%Y-%m"))
            # Move to first day of next month (avoids "day out of range" errors)
            if current.month == 12:
                current = current.replace(year=current.year + 1, month=1, day=1)
            else:
                current = current.replace(month=current.month + 1, day=1)

        # Get matching files
        log_files = []
        for ym in sorted(year_months):
            log_file = self.log_dir / f"audit_{ym}.jsonl"
            if log_file.exists():
                log_files.append(log_file)

        return log_files

    def export_csv(self, events: list[AuditEvent]) -> str:
        """
        Export events to CSV format.

        Args:
            events: List of AuditEvent objects to export

        Returns:
            CSV string with header and event rows
        """
        if not events:
            return ""

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(
            [
                "Event ID",
                "Timestamp",
                "Event Type",
                "Status",
                "User CN",
                "Hostname",
                "Document Path",
                "Document Hash",
                "Certificate Serial",
                "Certificate Issuer",
                "Error Message",
                "Details",
            ]
        )

        # Rows
        for event in events:
            writer.writerow(
                [
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.status,
                    event.user_cn or "",
                    event.hostname,
                    event.document_path or "",
                    event.document_hash_sha256 or "",
                    event.certificate_serial or "",
                    event.certificate_issuer or "",
                    event.error_message or "",
                    json.dumps(event.details) if event.details else "",
                ]
            )

        return output.getvalue()
