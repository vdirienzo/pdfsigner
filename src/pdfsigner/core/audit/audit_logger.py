"""
audit_logger.py - Audit event logger

Author: Homero Thompson del Lago del Terror

Singleton logger that writes audit events to JSON Lines files with
monthly rotation and configurable retention.
"""

import csv
import io
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType

if TYPE_CHECKING:
    from pdfsigner.core.audit.audit_integrity import AuditIntegrityManager


class AuditLogger:
    """
    Singleton audit logger that writes to JSON Lines files.

    Features:
    - Monthly log rotation (audit_YYYY-MM.jsonl)
    - Thread-safe operation
    - Automatic cleanup of old logs
    - Query interface with date and type filters
    - CSV export capability
    """

    _instance: "AuditLogger | None" = None
    _lock = threading.Lock()

    def __init__(
        self,
        log_dir: Path | None = None,
        enabled: bool = True,
        retention_days: int = 90,
        sign_events: bool = False,
        integrity_manager: "AuditIntegrityManager | None" = None,
        siem_exporter: "SIEMExporter | None" = None,
    ):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for audit logs (default: ~/.local/share/pdfsigner/audit)
            enabled: Enable/disable audit logging
            retention_days: Days to keep logs (1-3650)
            sign_events: Enable event signing with HMAC (requires integrity_manager)
            integrity_manager: AuditIntegrityManager instance for event signing
            siem_exporter: SIEMExporter instance for SIEM integration (optional)
        """
        if log_dir is None:
            log_dir = Path.home() / ".local" / "share" / "pdfsigner" / "audit"

        self.log_dir = Path(log_dir)
        self.enabled = enabled
        self.retention_days = max(1, min(retention_days, 3650))  # Clamp to 1-3650 days
        self.sign_events = sign_events
        self.integrity_manager = integrity_manager
        self.siem_exporter = siem_exporter
        self._write_lock = threading.Lock()

        # Validate integrity manager if signing is enabled
        if self.sign_events and self.integrity_manager is None:
            logger.warning(
                "Event signing enabled but no integrity_manager provided. Signing disabled."
            )
            self.sign_events = False

        # Create log directory if it doesn't exist
        if self.enabled:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Audit logger initialized: {self.log_dir}")

    @classmethod
    def get_instance(
        cls,
        log_dir: Path | None = None,
        enabled: bool = True,
        retention_days: int = 90,
        sign_events: bool = False,
        integrity_manager: "AuditIntegrityManager | None" = None,
        siem_exporter: "SIEMExporter | None" = None,
    ) -> "AuditLogger":
        """
        Get or create singleton instance.

        Thread-safe singleton pattern with double-checked locking.

        Args:
            log_dir: Directory for audit logs
            enabled: Enable/disable audit logging
            retention_days: Days to keep logs
            sign_events: Enable event signing with HMAC
            integrity_manager: AuditIntegrityManager instance for event signing
            siem_exporter: SIEMExporter instance for SIEM integration (optional)

        Returns:
            AuditLogger singleton instance
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(
                        log_dir,
                        enabled,
                        retention_days,
                        sign_events,
                        integrity_manager,
                        siem_exporter,
                    )
        return cls._instance

    def _get_log_file_path(self, timestamp: datetime) -> Path:
        """
        Get log file path for a given timestamp.

        Monthly rotation: audit_YYYY-MM.jsonl

        Args:
            timestamp: Timestamp to determine log file

        Returns:
            Path to log file
        """
        year_month = timestamp.strftime("%Y-%m")
        return self.log_dir / f"audit_{year_month}.jsonl"

    def log_event(self, event: AuditEvent) -> None:
        """
        Write event to current log file.

        Thread-safe write operation. Each line is a JSON object.
        If sign_events is enabled, event will be signed before writing.

        Args:
            event: AuditEvent to log
        """
        if not self.enabled:
            return

        self._write_event(event)

    def _write_event(self, event: AuditEvent) -> None:
        """
        Internal method to write event with optional signing.

        Thread-safe write operation. Signs event if sign_events is enabled.
        Exports to SIEM if siem_exporter is configured.

        Args:
            event: AuditEvent to log
        """
        try:
            # Sign event if integrity manager is available
            if self.sign_events and self.integrity_manager is not None:
                event = self.integrity_manager.sign_event(event)

            log_file = self._get_log_file_path(event.timestamp)

            with self._write_lock:
                with open(log_file, "a", encoding="utf-8") as f:
                    json.dump(event.to_dict(), f, ensure_ascii=False)
                    f.write("\n")

            logger.debug(f"Audit event logged: {event.event_type.value} [{event.event_id}]")

            # Export to SIEM if configured
            if self.siem_exporter and self.siem_exporter.config.enabled:
                try:
                    self.siem_exporter.export_event(event)
                except Exception as e:
                    logger.error(f"Failed to export event to SIEM: {e}")

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

    def log_encryption_event(
        self,
        document_path: str | Path,
        success: bool,
        method: str,
        strength: str,
        user_id: str | None = None,
        session_id: str | None = None,
        error: str | None = None,
        details: dict | None = None,
    ) -> None:
        """
        Log encryption/decryption event.

        Args:
            document_path: Path to document being encrypted/decrypted
            success: Whether operation succeeded
            method: Encryption method ("password" or "certificate")
            strength: Encryption strength ("aes128" or "aes256")
            user_id: User ID performing the operation
            session_id: Session ID
            error: Error message if operation failed
            details: Additional details about the operation
        """
        # Determine event type based on success
        if success:
            event_type = AuditEventType.ENCRYPT_SUCCESS
            status = "SUCCESS"
        else:
            event_type = AuditEventType.ENCRYPT_FAILURE
            status = "FAILURE"

        # Prepare details
        event_details = details or {}
        event_details.update(
            {
                "method": method,
                "strength": strength,
            }
        )

        # Create and log event
        event = AuditEvent(
            event_type=event_type,
            status=status,
            document_path=str(document_path),
            user_id=user_id,
            session_id=session_id,
            error_message=error,
            details=event_details,
            phi_accessed=True,  # Encryption events involve document access
        )

        self._write_event(event)

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
                                continue
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
                                continue
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

                            # Early exit if limit reached
                            if limit and len(events) >= limit:
                                break

                        except Exception as e:
                            logger.warning(f"Skipping invalid audit entry: {e}")

                # Early exit if limit reached
                if limit and len(events) >= limit:
                    break

            # Sort by timestamp
            events.sort(key=lambda e: e.timestamp)

            # Apply limit after sorting (to get most recent)
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
        current = start_date or datetime.now()
        end = end_date or datetime.now()

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

    def cleanup_old_logs(self) -> int:
        """
        Remove logs older than retention_days.

        Returns:
            Number of log files deleted
        """
        if not self.enabled or not self.log_dir.exists():
            return 0

        deleted_count = 0
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)

        try:
            for log_file in self.log_dir.glob("audit_*.jsonl"):
                # Parse year-month from filename
                try:
                    # Format: audit_YYYY-MM.jsonl
                    year_month = log_file.stem.replace("audit_", "")
                    file_date = datetime.strptime(year_month, "%Y-%m")

                    # Delete if older than cutoff (check end of month)
                    if file_date.replace(day=28) < cutoff_date:
                        log_file.unlink()
                        deleted_count += 1
                        logger.info(f"Deleted old audit log: {log_file.name}")

                except ValueError:
                    logger.warning(f"Invalid audit log filename: {log_file.name}")

        except Exception as e:
            logger.error(f"Error cleaning up audit logs: {e}")

        return deleted_count

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
