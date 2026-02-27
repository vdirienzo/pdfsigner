"""
siem_exporter.py - SIEM integration for audit events

Author: Homero Thompson del Lago del Terror

Export audit events to SIEM systems via syslog or file output.
Supports multiple formats: CEF, LEEF, JSON, Syslog.
"""

import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEvent
from pdfsigner.core.audit.formatters import CEFFormatter, JSONFormatter, LEEFFormatter
from pdfsigner.core.audit.siem_transport import SIEMTransport


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
    tls_verify: bool = True  # DEPRECATED: Use allow_insecure_tls=True to disable verification
    allow_insecure_tls: bool = False  # Explicitly allow insecure TLS (disables verification)


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
    - Syslog transport: UDP, TCP, TLS (via SIEMTransport)
    - File export with rotation and retention (via SIEMTransport)
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
        self._transport = SIEMTransport(config)

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
            timestamp=datetime.now(UTC),
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

            # Send via transport
            return self._transport.send_to_syslog(syslog_msg.encode("utf-8"))

        except Exception as e:
            logger.error(f"Failed to export event to syslog: {e}")
            return False

    def export_to_file(self, event: AuditEvent) -> bool:
        """
        Write event to rotating log file.

        Args:
            event: AuditEvent to write

        Returns:
            True if successful, False otherwise
        """
        try:
            formatted = self._format_event(event)
            return self._transport.export_to_file(formatted)
        except Exception as e:
            logger.error(f"Failed to export event to file: {e}")
            return False

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

        Args:
            callback: Function to call with each event
        """
        raise NotImplementedError("Real-time streaming not yet implemented")

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
        self._transport.close()

    # -- Backward-compatible private methods for tests that patch them --

    @property
    def _socket(self) -> "socket.socket | None":
        """Backward-compatible access to transport socket."""
        return self._transport._socket

    @_socket.setter
    def _socket(self, value: "socket.socket | None") -> None:
        """Backward-compatible setter for transport socket."""
        self._transport._socket = value

    def _send_to_syslog(self, message: bytes) -> bool:
        """Backward-compatible delegate to transport."""
        return self._transport.send_to_syslog(message)

    def _send_udp(self, message: bytes) -> bool:
        """Backward-compatible delegate to transport."""
        return self._transport._send_udp(message)

    def _send_tcp(self, message: bytes) -> bool:
        """Backward-compatible delegate to transport."""
        return self._transport._send_tcp(message)

    def _send_tls(self, message: bytes) -> bool:
        """Backward-compatible delegate to transport."""
        return self._transport._send_tls(message)

    def _rotate_file_if_needed(self) -> None:
        """Backward-compatible delegate to transport."""
        self._transport._rotate_file_if_needed()

    def _cleanup_old_files(self) -> None:
        """Backward-compatible delegate to transport."""
        self._transport._cleanup_old_files()
