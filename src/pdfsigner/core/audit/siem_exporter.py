"""
siem_exporter.py - SIEM integration for audit events

Author: Homero Thompson del Lago del Terror

Export audit events to SIEM systems via syslog or file output.
Supports multiple formats: CEF, LEEF, JSON, Syslog.
"""

import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEvent
from pdfsigner.core.audit.formatters import CEFFormatter, JSONFormatter, LEEFFormatter


class SIEMFormat(str, Enum):
    """SIEM export formats."""

    CEF = "cef"  # Common Event Format (ArcSight, Splunk)
    LEEF = "leef"  # Log Event Extended Format (IBM QRadar)
    JSON = "json"  # JSON Lines
    SYSLOG = "syslog"  # RFC 5424


class SyslogProtocol(str, Enum):
    """Syslog transport protocols."""

    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


@dataclass
class SIEMConfig:
    """Configuration for SIEM export."""

    enabled: bool = False
    format: SIEMFormat = SIEMFormat.CEF

    # Syslog settings
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: SyslogProtocol = SyslogProtocol.UDP

    # File export settings
    file_path: str = ""
    file_rotation_mb: int = 100
    file_retention_days: int = 90

    # TLS settings for secure syslog
    tls_cert_path: str = ""
    tls_verify: bool = True


@dataclass
class ExportResult:
    """Result of a batch export operation."""

    success: bool
    events_exported: int
    errors: list[str]
    timestamp: datetime


class SIEMExporter:
    """
    Export audit events to SIEM systems.

    Features:
    - Multiple formats: CEF, LEEF, JSON
    - Syslog transport: UDP, TCP, TLS
    - File export with rotation and retention
    - Thread-safe operations
    - Connection testing
    - Event streaming
    """

    def __init__(self, config: SIEMConfig):
        """
        Initialize SIEM exporter.

        Args:
            config: SIEM configuration
        """
        self.config = config
        self._socket: socket.socket | None = None
        self._file_lock = threading.Lock()
        self._current_file_size = 0

        # Validate configuration
        if self.config.enabled:
            self._validate_config()

    def _validate_config(self) -> None:
        """Validate SIEM configuration."""
        if not self.config.syslog_host and not self.config.file_path:
            logger.warning("SIEM enabled but no syslog host or file path configured")

        if self.config.syslog_host:
            # Validate syslog configuration
            if not 1 <= self.config.syslog_port <= 65535:
                raise ValueError(f"Invalid syslog port: {self.config.syslog_port}")

            if self.config.syslog_protocol == SyslogProtocol.TLS:
                if self.config.tls_cert_path and not Path(self.config.tls_cert_path).exists():
                    raise ValueError(f"TLS certificate not found: {self.config.tls_cert_path}")

        if self.config.file_path:
            # Validate file configuration
            file_dir = Path(self.config.file_path).parent
            if not file_dir.exists():
                file_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created SIEM export directory: {file_dir}")

    def export_event(self, event: AuditEvent) -> bool:
        """
        Export single event to configured SIEM.

        Args:
            event: AuditEvent to export

        Returns:
            True if export succeeded, False otherwise
        """
        if not self.config.enabled:
            return True

        success = True

        try:
            # Export to syslog if configured
            if self.config.syslog_host:
                if not self.export_to_syslog(event):
                    success = False

            # Export to file if configured
            if self.config.file_path:
                if not self.export_to_file(event):
                    success = False

        except Exception as e:
            logger.error(f"Failed to export event to SIEM: {e}")
            success = False

        return success

    def export_batch(self, events: list[AuditEvent]) -> ExportResult:
        """
        Export batch of events.

        Args:
            events: List of AuditEvent objects to export

        Returns:
            ExportResult with statistics
        """
        errors = []
        exported = 0

        for event in events:
            try:
                if self.export_event(event):
                    exported += 1
                else:
                    errors.append(f"Failed to export event {event.event_id}")
            except Exception as e:
                errors.append(f"Error exporting event {event.event_id}: {e}")

        return ExportResult(
            success=len(errors) == 0,
            events_exported=exported,
            errors=errors,
            timestamp=datetime.now(),
        )

    def export_to_syslog(self, event: AuditEvent) -> bool:
        """
        Send event to syslog server.

        Args:
            event: AuditEvent to send

        Returns:
            True if successful, False otherwise
        """
        try:
            # Format event
            formatted = self._format_event(event)

            # Add syslog header (RFC 5424)
            # <Priority>Version Timestamp Hostname AppName ProcID MsgID StructuredData Message
            priority = self._calculate_syslog_priority(event)
            timestamp = event.timestamp.isoformat()
            hostname = event.hostname or socket.gethostname()
            app_name = "pdfsigner"
            proc_id = "-"
            msg_id = event.event_type.value

            syslog_msg = (
                f"<{priority}>1 {timestamp} {hostname} {app_name} "
                f"{proc_id} {msg_id} - {formatted}\n"
            )

            # Send to syslog server
            return self._send_to_syslog(syslog_msg.encode("utf-8"))

        except Exception as e:
            logger.error(f"Failed to export event to syslog: {e}")
            return False

    def _send_to_syslog(self, message: bytes) -> bool:
        """
        Send message to syslog server via configured protocol.

        Args:
            message: Formatted syslog message

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.config.syslog_protocol == SyslogProtocol.UDP:
                return self._send_udp(message)
            elif self.config.syslog_protocol == SyslogProtocol.TCP:
                return self._send_tcp(message)
            elif self.config.syslog_protocol == SyslogProtocol.TLS:
                return self._send_tls(message)
            else:
                logger.error(f"Unsupported syslog protocol: {self.config.syslog_protocol}")
                return False

        except Exception as e:
            logger.error(f"Failed to send to syslog: {e}")
            # Close socket on error
            self.close()
            return False

    def _send_udp(self, message: bytes) -> bool:
        """Send message via UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message, (self.config.syslog_host, self.config.syslog_port))
            return True
        finally:
            sock.close()

    def _send_tcp(self, message: bytes) -> bool:
        """Send message via TCP (with connection reuse)."""
        if self._socket is None or self._socket.fileno() == -1:
            # Create new TCP connection
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(10.0)
            self._socket.connect((self.config.syslog_host, self.config.syslog_port))

        self._socket.sendall(message)
        return True

    def _send_tls(self, message: bytes) -> bool:
        """Send message via TLS."""
        if self._socket is None or self._socket.fileno() == -1:
            # Create TLS connection
            context = ssl.create_default_context()

            if self.config.tls_cert_path:
                context.load_verify_locations(self.config.tls_cert_path)

            if not self.config.tls_verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(10.0)
            self._socket = context.wrap_socket(raw_socket, server_hostname=self.config.syslog_host)
            self._socket.connect((self.config.syslog_host, self.config.syslog_port))

        self._socket.sendall(message)
        return True

    def export_to_file(self, event: AuditEvent) -> bool:
        """
        Write event to rotating log file.

        Args:
            event: AuditEvent to write

        Returns:
            True if successful, False otherwise
        """
        try:
            # Format event
            formatted = self._format_event(event)

            with self._file_lock:
                # Check if rotation needed
                self._rotate_file_if_needed()

                # Write to file
                file_path = Path(self.config.file_path)
                with open(file_path, "a", encoding="utf-8") as f:
                    f.write(formatted + "\n")
                    self._current_file_size += len(formatted) + 1

            return True

        except Exception as e:
            logger.error(f"Failed to export event to file: {e}")
            return False

    def _rotate_file_if_needed(self) -> None:
        """Rotate log file if size limit exceeded."""
        if not self.config.file_path:
            return

        file_path = Path(self.config.file_path)
        if not file_path.exists():
            self._current_file_size = 0
            return

        # Check actual file size
        actual_size = file_path.stat().st_size
        self._current_file_size = actual_size

        max_size_bytes = self.config.file_rotation_mb * 1024 * 1024

        if self._current_file_size >= max_size_bytes:
            # Rotate file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_path = file_path.with_suffix(f".{timestamp}{file_path.suffix}")
            file_path.rename(rotated_path)
            self._current_file_size = 0

            logger.info(f"Rotated SIEM log file to {rotated_path}")

            # Cleanup old files
            self._cleanup_old_files()

    def _cleanup_old_files(self) -> None:
        """Remove rotated files older than retention period."""
        if not self.config.file_path:
            return

        file_path = Path(self.config.file_path)
        # Pattern: filename.TIMESTAMP.ext (e.g., siem_export.20200101_120000.log)
        pattern = f"{file_path.stem}.*{file_path.suffix}"

        cutoff = datetime.now().timestamp() - (self.config.file_retention_days * 86400)

        for old_file in file_path.parent.glob(pattern):
            if old_file == file_path:
                continue  # Skip current file

            # Check if it's a rotated file (has timestamp in name)
            if not old_file.stem.startswith(file_path.stem + "."):
                continue

            if old_file.stat().st_mtime < cutoff:
                try:
                    old_file.unlink()
                    logger.info(f"Deleted old SIEM log file: {old_file}")
                except Exception as e:
                    logger.error(f"Failed to delete old SIEM log file {old_file}: {e}")

    def _format_event(self, event: AuditEvent) -> str:
        """
        Format event using configured format.

        Args:
            event: AuditEvent to format

        Returns:
            Formatted string
        """
        if self.config.format == SIEMFormat.CEF:
            return CEFFormatter.format(event)
        elif self.config.format == SIEMFormat.LEEF:
            return LEEFFormatter.format(event)
        elif self.config.format == SIEMFormat.JSON:
            return JSONFormatter.format(event)
        elif self.config.format == SIEMFormat.SYSLOG:
            # For syslog format, use JSON as the message payload
            return JSONFormatter.format(event)
        else:
            raise ValueError(f"Unsupported SIEM format: {self.config.format}")

    def _calculate_syslog_priority(self, event: AuditEvent) -> int:
        """
        Calculate syslog priority (PRI) value.

        PRI = Facility * 8 + Severity
        Facility: 16 (local0)
        Severity: 3 (ERROR), 4 (WARNING), 6 (INFO), 7 (DEBUG)

        Returns:
            Priority value (0-191)
        """
        facility = 16  # local0

        # Map event status to syslog severity
        if event.status == "SUCCESS":
            severity = 6  # Informational
        elif event.status == "FAILURE":
            severity = 4  # Warning
        else:  # ERROR
            severity = 3  # Error

        return facility * 8 + severity

    def stream_events(self, callback: Callable[[AuditEvent], None]) -> None:
        """
        Stream events in real-time to callback.

        This method is intended to be called with each new event
        as it's logged. The callback will be invoked for each event.

        Args:
            callback: Function to call with each event
        """
        # This is a pass-through method that can be extended
        # for real-time streaming functionality
        # In practice, this would be called by AuditLogger for each event
        pass

    def test_connection(self) -> tuple[bool, str]:
        """
        Test SIEM connection.

        Returns:
            Tuple of (success, message)
        """
        messages = []

        # Test syslog connection
        if self.config.syslog_host:
            try:
                from pdfsigner.core.audit.audit_event import AuditEventType

                # Create test event
                test_event = AuditEvent(
                    event_type=AuditEventType.SYSTEM_EVENT,
                    status="SUCCESS",
                    details={"test": "SIEM connection test"},
                )

                if self.export_to_syslog(test_event):
                    messages.append(
                        f"Syslog connection OK ({self.config.syslog_protocol.value}://"
                        f"{self.config.syslog_host}:{self.config.syslog_port})"
                    )
                else:
                    return False, "Failed to send test event to syslog"

            except Exception as e:
                return False, f"Syslog connection failed: {e}"

        # Test file export
        if self.config.file_path:
            try:
                from pdfsigner.core.audit.audit_event import AuditEventType

                file_path = Path(self.config.file_path)
                if not file_path.parent.exists():
                    return False, f"File directory does not exist: {file_path.parent}"

                # Try writing test event
                test_event = AuditEvent(
                    event_type=AuditEventType.SYSTEM_EVENT,
                    status="SUCCESS",
                    details={"test": "SIEM file export test"},
                )

                if self.export_to_file(test_event):
                    messages.append(f"File export OK ({file_path})")
                else:
                    return False, "Failed to write test event to file"

            except Exception as e:
                return False, f"File export failed: {e}"

        if messages:
            return True, "; ".join(messages)
        else:
            return False, "No syslog host or file path configured"

    def close(self) -> None:
        """Close any open connections."""
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.debug(f"Error closing socket: {e}")
            finally:
                self._socket = None
