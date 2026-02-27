"""
siem_transport.py - SIEM transport layer for audit events

Author: Homero Thompson del Lago del Terror

Handles low-level transport of formatted SIEM messages via
UDP, TCP, TLS syslog and file export with rotation/retention.
"""

import socket
import ssl
import threading
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from pdfsigner.core.audit.siem_exporter import SIEMConfig


class SIEMTransport:
    """
    Low-level transport for SIEM messages.

    Handles sending formatted messages to syslog servers (UDP/TCP/TLS)
    and writing to rotating log files. Thread-safe operations with
    connection reuse for TCP/TLS.
    """

    def __init__(self, config: "SIEMConfig"):
        """
        Initialize SIEM transport.

        Args:
            config: SIEM configuration with host/port/protocol/file settings
        """
        self.config = config
        self._socket: socket.socket | None = None
        self._file_lock = threading.Lock()
        self._current_file_size = 0

    def send_to_syslog(self, message: bytes) -> bool:
        """
        Send message to syslog server via configured protocol.

        Args:
            message: Formatted syslog message

        Returns:
            True if successful, False otherwise
        """
        try:
            if self.config.syslog_protocol.value == "udp":
                return self._send_udp(message)
            elif self.config.syslog_protocol.value == "tcp":
                return self._send_tcp(message)
            elif self.config.syslog_protocol.value == "tls":
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

            # Security: TLS verification should always be enabled by default
            # Check for deprecated tls_verify parameter
            if not self.config.tls_verify:
                warnings.warn(
                    "tls_verify parameter is deprecated. Use allow_insecure_tls=True instead.",
                    DeprecationWarning,
                    stacklevel=3,
                )
                logger.warning(
                    "DEPRECATED: tls_verify=False is deprecated. "
                    "Use allow_insecure_tls=True to explicitly disable TLS verification."
                )

            # Only disable TLS verification if explicitly allowed
            if self.config.allow_insecure_tls or not self.config.tls_verify:
                host_port = f"{self.config.syslog_host}:{self.config.syslog_port}"
                logger.warning(
                    "SECURITY WARNING: TLS certificate verification is "
                    f"DISABLED for SIEM connection to {host_port}. "
                    "This connection is vulnerable to man-in-the-middle attacks."
                )
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                # Enforce secure TLS verification (default)
                logger.debug(
                    f"TLS certificate verification enabled for SIEM connection to "
                    f"{self.config.syslog_host}:{self.config.syslog_port}"
                )

            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(10.0)
            self._socket = context.wrap_socket(raw_socket, server_hostname=self.config.syslog_host)
            self._socket.connect((self.config.syslog_host, self.config.syslog_port))

        self._socket.sendall(message)
        return True

    def export_to_file(self, formatted: str) -> bool:
        """
        Write formatted event to rotating log file.

        Args:
            formatted: Pre-formatted event string

        Returns:
            True if successful, False otherwise
        """
        try:
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
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
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

        cutoff = datetime.now(UTC).timestamp() - (self.config.file_retention_days * 86400)

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

    def close(self) -> None:
        """Close any open connections."""
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception as e:
                logger.debug(f"Error closing socket: {e}")
            finally:
                self._socket = None
