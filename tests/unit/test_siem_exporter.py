"""
test_siem_exporter.py - Tests for SIEM export functionality

Author: Homero Thompson del Lago del Terror

Tests CEF, LEEF, JSON formatters and SIEM export capabilities.
"""

import json
import socket
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.audit.formatters import CEFFormatter, JSONFormatter, LEEFFormatter
from pdfsigner.core.audit.siem_exporter import (
    SIEMConfig,
    SIEMExporter,
    SIEMFormat,
    SyslogProtocol,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_event() -> AuditEvent:
    """Create a sample audit event for testing."""
    return AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        timestamp=datetime(2026, 2, 1, 14, 30, 0),
        event_id="test-event-123",
        user_cn="John Doe",
        hostname="workstation01",
        document_path="/home/user/document.pdf",
        document_hash_sha256="abc123def456",
        certificate_serial="1234567890",
        certificate_issuer="CN=Test CA",
        status="SUCCESS",
        user_id="user123",
        session_id="session-456",
        ip_address="192.168.1.100",
        user_agent="PDFSigner-GUI/1.7.0",
        phi_accessed=True,
        details={"signature_type": "PAdES-LTA", "timestamp_used": True},
    )


@pytest.fixture
def failure_event() -> AuditEvent:
    """Create a failure event for testing."""
    return AuditEvent(
        event_type=AuditEventType.SIGN_FAILURE,
        timestamp=datetime(2026, 2, 1, 15, 0, 0),
        event_id="test-failure-789",
        user_cn="Jane Smith",
        hostname="workstation02",
        status="FAILURE",
        error_message="PIN verification failed",
    )


@pytest.fixture
def siem_config_file(tmp_path: Path) -> SIEMConfig:
    """Create SIEM config for file export."""
    return SIEMConfig(
        enabled=True,
        format=SIEMFormat.CEF,
        file_path=str(tmp_path / "siem_export.log"),
        file_rotation_mb=1,  # Small size for testing rotation
        file_retention_days=7,
    )


@pytest.fixture
def siem_config_syslog() -> SIEMConfig:
    """Create SIEM config for syslog export."""
    return SIEMConfig(
        enabled=True,
        format=SIEMFormat.CEF,
        syslog_host="syslog.example.com",
        syslog_port=514,
        syslog_protocol=SyslogProtocol.UDP,
    )


# ============================================================================
# CEF Formatter Tests
# ============================================================================


def test_cef_formatter_basic(sample_event: AuditEvent) -> None:
    """Test basic CEF formatting."""
    result = CEFFormatter.format(sample_event)

    # Check header format
    assert result.startswith("CEF:0|PDFSigner|AuditLogger|1.7.0|1001|")
    assert "|3|" in result  # Severity 3 (INFO) for SUCCESS

    # Check extension fields
    assert "src=192.168.1.100" in result
    assert "suser=John Doe" in result
    assert "fname=/home/user/document.pdf" in result
    assert "outcome=success" in result
    assert "externalId=test-event-123" in result


def test_cef_formatter_escaping() -> None:
    """Test CEF field escaping."""
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        user_cn="User|With=Pipes",
        error_message="Error with = and | chars",
    )

    result = CEFFormatter.format(event)

    # Header fields should escape |
    assert "User\\|With=Pipes" in result or "suser=User|With\\=Pipes" in result

    # Extension fields should escape =
    assert "Error with \\= and | chars" in result


def test_cef_formatter_severity_mapping(failure_event: AuditEvent) -> None:
    """Test CEF severity mapping for different statuses."""
    result = CEFFormatter.format(failure_event)

    # FAILURE status should map to WARNING severity (5)
    assert "|5|" in result

    # Error event
    error_event = AuditEvent(
        event_type=AuditEventType.SIGN_FAILURE, status="ERROR", error_message="System error"
    )
    result = CEFFormatter.format(error_event)
    assert "|7|" in result  # ERROR severity


def test_cef_formatter_signature_ids() -> None:
    """Test CEF signature ID mapping."""
    event_encrypt = AuditEvent(event_type=AuditEventType.ENCRYPT_SUCCESS)
    result = CEFFormatter.format(event_encrypt)
    assert "|1003|" in result  # Encrypt signature ID

    event_mfa = AuditEvent(event_type=AuditEventType.MFA_VERIFIED)
    result = CEFFormatter.format(event_mfa)
    assert "|2004|" in result  # MFA signature ID


def test_cef_formatter_phi_flag(sample_event: AuditEvent) -> None:
    """Test CEF formatting includes PHI access flag."""
    result = CEFFormatter.format(sample_event)
    assert "cs4Label=PHIAccessed cs4=true" in result


def test_cef_formatter_newlines_removed() -> None:
    """Test that newlines are removed from CEF extension fields."""
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        error_message="Error\nwith\nnewlines",
    )

    result = CEFFormatter.format(event)
    assert "\n" not in result.split("|")[-1]  # No newlines in extension
    assert "Error with newlines" in result


# ============================================================================
# LEEF Formatter Tests
# ============================================================================


def test_leef_formatter_basic(sample_event: AuditEvent) -> None:
    """Test basic LEEF formatting."""
    result = LEEFFormatter.format(sample_event)

    # Check header format
    assert result.startswith("LEEF:2.0|PDFSigner|AuditLogger|1.7.0|1001|")

    # Check extension fields (tab-separated)
    assert "src=192.168.1.100" in result
    assert "usrName=John Doe" in result
    assert "fileName=/home/user/document.pdf" in result
    assert "result=success" in result
    assert "eventId=test-event-123" in result


def test_leef_formatter_escaping() -> None:
    """Test LEEF field escaping."""
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        user_cn="User\tWith=Tabs",
        error_message="Error with \t tabs \n newlines",
    )

    result = LEEFFormatter.format(event)

    # Extension fields should escape tabs and newlines
    assert "\\t" in result
    assert "\\n" in result
    assert "\t" in result  # Tab separator is present


def test_leef_formatter_severity_mapping(failure_event: AuditEvent) -> None:
    """Test LEEF severity mapping."""
    result = LEEFFormatter.format(failure_event)

    # FAILURE status should map to severity 5 (medium)
    assert "sev=5" in result


def test_leef_formatter_timestamp_format(sample_event: AuditEvent) -> None:
    """Test LEEF uses ISO 8601 timestamp format."""
    result = LEEFFormatter.format(sample_event)
    assert "devTime=2026-02-01T14:30:00" in result


# ============================================================================
# JSON Formatter Tests
# ============================================================================


def test_json_formatter_basic(sample_event: AuditEvent) -> None:
    """Test basic JSON formatting."""
    result = JSONFormatter.format(sample_event)

    # Should be valid JSON
    data = json.loads(result)

    assert data["event_type"] == "sign_success"
    assert data["event_id"] == "test-event-123"
    assert data["user_cn"] == "John Doe"
    assert data["status"] == "SUCCESS"
    assert data["@timestamp"] == "2026-02-01T14:30:00"


def test_json_formatter_severity_fields(sample_event: AuditEvent) -> None:
    """Test JSON includes severity fields."""
    result = JSONFormatter.format(sample_event)
    data = json.loads(result)

    assert data["severity"] == 3  # INFO
    assert data["severity_label"] == "INFO"


def test_json_formatter_none_values() -> None:
    """Test JSON formatter converts None to empty strings."""
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        user_cn=None,
        document_path=None,
    )

    result = JSONFormatter.format(event)
    data = json.loads(result)

    assert data["user_cn"] == ""
    assert data["document_path"] == ""


def test_json_formatter_unicode() -> None:
    """Test JSON formatter handles Unicode correctly."""
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        user_cn="José García",
        document_path="/home/user/documentación.pdf",
    )

    result = JSONFormatter.format(event)
    data = json.loads(result)

    assert data["user_cn"] == "José García"
    assert data["document_path"] == "/home/user/documentación.pdf"


# ============================================================================
# SIEMExporter Configuration Tests
# ============================================================================


def test_siem_config_validation_invalid_port() -> None:
    """Test SIEM config validation rejects invalid ports."""
    config = SIEMConfig(
        enabled=True,
        syslog_host="syslog.example.com",
        syslog_port=99999,  # Invalid
    )

    with pytest.raises(ValueError, match="Invalid syslog port"):
        SIEMExporter(config)


def test_siem_config_validation_missing_tls_cert() -> None:
    """Test SIEM config validation checks TLS certificate."""
    config = SIEMConfig(
        enabled=True,
        syslog_host="syslog.example.com",
        syslog_protocol=SyslogProtocol.TLS,
        tls_cert_path="/nonexistent/cert.pem",
    )

    with pytest.raises(ValueError, match="TLS certificate not found"):
        SIEMExporter(config)


def test_siem_config_validation_creates_file_directory(tmp_path: Path) -> None:
    """Test SIEM exporter creates file directory if needed."""
    file_path = tmp_path / "subdir" / "siem.log"
    config = SIEMConfig(enabled=True, file_path=str(file_path))

    _ = SIEMExporter(config)
    assert file_path.parent.exists()


# ============================================================================
# File Export Tests
# ============================================================================


def test_siem_exporter_file_export(siem_config_file: SIEMConfig, sample_event: AuditEvent) -> None:
    """Test exporting event to file."""
    exporter = SIEMExporter(siem_config_file)

    result = exporter.export_event(sample_event)
    assert result is True

    # Check file was created
    file_path = Path(siem_config_file.file_path)
    assert file_path.exists()

    # Check content
    content = file_path.read_text()
    assert "CEF:0|PDFSigner" in content
    assert "test-event-123" in content


def test_siem_exporter_file_rotation(
    siem_config_file: SIEMConfig, sample_event: AuditEvent
) -> None:
    """Test file rotation when size limit reached."""
    exporter = SIEMExporter(siem_config_file)
    file_path = Path(siem_config_file.file_path)

    # Write enough events to trigger rotation (1MB limit)
    large_event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        details={"large_field": "x" * 100000},  # 100KB event
    )

    for _ in range(15):  # 15 * 100KB = 1.5MB > 1MB limit
        exporter.export_event(large_event)

    # Check that rotation occurred (rotated file should exist)
    rotated_files = list(file_path.parent.glob(f"{file_path.stem}.*{file_path.suffix}"))
    assert len(rotated_files) > 0  # At least one rotated file


def test_siem_exporter_file_cleanup(siem_config_file: SIEMConfig, tmp_path: Path) -> None:
    """Test cleanup of old rotated files."""
    import os
    import time

    exporter = SIEMExporter(siem_config_file)
    file_path = Path(siem_config_file.file_path)

    # Create old rotated file
    old_file = file_path.parent / f"{file_path.stem}.20200101_120000{file_path.suffix}"
    old_file.write_text("old content")

    # Set modification time to 30 days ago (older than 7 day retention)
    old_timestamp = time.time() - (30 * 86400)
    os.utime(old_file, (old_timestamp, old_timestamp))

    # Trigger cleanup
    exporter._cleanup_old_files()

    # Old file should be deleted (older than 7 days retention)
    assert not old_file.exists()


def test_siem_exporter_batch_export(siem_config_file: SIEMConfig, sample_event: AuditEvent) -> None:
    """Test batch export of multiple events."""
    exporter = SIEMExporter(siem_config_file)

    events = [sample_event for _ in range(5)]
    result = exporter.export_batch(events)

    assert result.success is True
    assert result.events_exported == 5
    assert len(result.errors) == 0


# ============================================================================
# Syslog Export Tests (Mocked)
# ============================================================================


@patch("socket.socket")
def test_siem_exporter_syslog_udp(
    mock_socket: Mock, siem_config_syslog: SIEMConfig, sample_event: AuditEvent
) -> None:
    """Test syslog export via UDP."""
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    exporter = SIEMExporter(siem_config_syslog)
    result = exporter.export_event(sample_event)

    assert result is True
    mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
    mock_sock_instance.sendto.assert_called_once()
    mock_sock_instance.close.assert_called_once()


@patch("socket.socket")
def test_siem_exporter_syslog_tcp(
    mock_socket: Mock, siem_config_syslog: SIEMConfig, sample_event: AuditEvent
) -> None:
    """Test syslog export via TCP."""
    siem_config_syslog.syslog_protocol = SyslogProtocol.TCP
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    exporter = SIEMExporter(siem_config_syslog)
    result = exporter.export_event(sample_event)

    assert result is True
    mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_sock_instance.connect.assert_called_with(("syslog.example.com", 514))
    mock_sock_instance.sendall.assert_called_once()


@patch("ssl.create_default_context")
@patch("socket.socket")
def test_siem_exporter_syslog_tls(
    mock_socket: Mock,
    mock_ssl_context: Mock,
    siem_config_syslog: SIEMConfig,
    sample_event: AuditEvent,
) -> None:
    """Test syslog export via TLS."""
    siem_config_syslog.syslog_protocol = SyslogProtocol.TLS
    siem_config_syslog.tls_verify = False

    mock_context = MagicMock()
    mock_ssl_context.return_value = mock_context
    mock_wrapped_socket = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_socket

    exporter = SIEMExporter(siem_config_syslog)
    result = exporter.export_event(sample_event)

    assert result is True
    mock_ssl_context.assert_called_once()
    mock_context.wrap_socket.assert_called_once()
    mock_wrapped_socket.connect.assert_called_with(("syslog.example.com", 514))
    mock_wrapped_socket.sendall.assert_called_once()


def test_siem_exporter_syslog_priority_calculation(sample_event: AuditEvent) -> None:
    """Test syslog priority calculation."""
    config = SIEMConfig(enabled=True)
    exporter = SIEMExporter(config)

    # SUCCESS -> severity 6 (info), facility 16 (local0)
    priority = exporter._calculate_syslog_priority(sample_event)
    assert priority == 16 * 8 + 6  # 134

    # FAILURE -> severity 4 (warning)
    sample_event.status = "FAILURE"
    priority = exporter._calculate_syslog_priority(sample_event)
    assert priority == 16 * 8 + 4  # 132

    # ERROR -> severity 3 (error)
    sample_event.status = "ERROR"
    priority = exporter._calculate_syslog_priority(sample_event)
    assert priority == 16 * 8 + 3  # 131


# ============================================================================
# Connection Testing
# ============================================================================


@patch("socket.socket")
def test_siem_exporter_test_connection_success(
    mock_socket: Mock, siem_config_syslog: SIEMConfig
) -> None:
    """Test connection testing with successful connection."""
    mock_sock_instance = MagicMock()
    mock_socket.return_value = mock_sock_instance

    exporter = SIEMExporter(siem_config_syslog)
    success, message = exporter.test_connection()

    assert success is True
    assert "Syslog connection OK" in message
    assert "udp://syslog.example.com:514" in message


def test_siem_exporter_test_connection_file(siem_config_file: SIEMConfig) -> None:
    """Test connection testing for file export."""
    exporter = SIEMExporter(siem_config_file)
    success, message = exporter.test_connection()

    assert success is True
    assert "File export OK" in message


def test_siem_exporter_test_connection_no_config() -> None:
    """Test connection testing with no configuration."""
    config = SIEMConfig(enabled=True)  # No syslog or file path
    exporter = SIEMExporter(config)

    success, message = exporter.test_connection()
    assert success is False
    assert "No syslog host or file path configured" in message


# ============================================================================
# Format Selection Tests
# ============================================================================


def test_siem_exporter_format_selection_cef(sample_event: AuditEvent) -> None:
    """Test CEF format selection."""
    config = SIEMConfig(enabled=True, format=SIEMFormat.CEF)
    exporter = SIEMExporter(config)

    formatted = exporter._format_event(sample_event)
    assert formatted.startswith("CEF:0|")


def test_siem_exporter_format_selection_leef(sample_event: AuditEvent) -> None:
    """Test LEEF format selection."""
    config = SIEMConfig(enabled=True, format=SIEMFormat.LEEF)
    exporter = SIEMExporter(config)

    formatted = exporter._format_event(sample_event)
    assert formatted.startswith("LEEF:2.0|")


def test_siem_exporter_format_selection_json(sample_event: AuditEvent) -> None:
    """Test JSON format selection."""
    config = SIEMConfig(enabled=True, format=SIEMFormat.JSON)
    exporter = SIEMExporter(config)

    formatted = exporter._format_event(sample_event)
    data = json.loads(formatted)
    assert data["event_type"] == "sign_success"


def test_siem_exporter_format_selection_syslog(sample_event: AuditEvent) -> None:
    """Test syslog format (uses JSON as payload)."""
    config = SIEMConfig(enabled=True, format=SIEMFormat.SYSLOG)
    exporter = SIEMExporter(config)

    formatted = exporter._format_event(sample_event)
    data = json.loads(formatted)  # Should be valid JSON
    assert data["event_type"] == "sign_success"


# ============================================================================
# Error Handling Tests
# ============================================================================


@patch("socket.socket")
def test_siem_exporter_socket_error_handling(
    mock_socket: Mock, siem_config_syslog: SIEMConfig, sample_event: AuditEvent
) -> None:
    """Test handling of socket errors."""
    mock_socket.side_effect = OSError("Connection refused")

    exporter = SIEMExporter(siem_config_syslog)
    result = exporter.export_event(sample_event)

    assert result is False


def test_siem_exporter_file_write_error(
    siem_config_file: SIEMConfig, sample_event: AuditEvent
) -> None:
    """Test handling of file write errors."""
    exporter = SIEMExporter(siem_config_file)

    # Make the file path invalid after initialization
    exporter.config.file_path = "/root/invalid/file.log"  # Permission denied

    result = exporter.export_event(sample_event)

    assert result is False


def test_siem_exporter_disabled_export(sample_event: AuditEvent) -> None:
    """Test that disabled exporter doesn't export."""
    config = SIEMConfig(enabled=False, file_path="/tmp/test.log")
    exporter = SIEMExporter(config)

    result = exporter.export_event(sample_event)
    assert result is True  # Returns True but doesn't actually export

    # File should not be created
    assert not Path("/tmp/test.log").exists()


def test_siem_exporter_close_socket() -> None:
    """Test closing socket connections."""
    config = SIEMConfig(
        enabled=True,
        syslog_host="syslog.example.com",
        syslog_protocol=SyslogProtocol.TCP,
    )
    exporter = SIEMExporter(config)

    # Create a mock socket
    mock_socket = MagicMock()
    exporter._socket = mock_socket

    exporter.close()
    mock_socket.close.assert_called_once()
    assert exporter._socket is None


# ============================================================================
# Integration Tests
# ============================================================================


def test_siem_exporter_combined_outputs(tmp_path: Path, sample_event: AuditEvent) -> None:
    """Test exporting to both syslog and file simultaneously."""
    config = SIEMConfig(
        enabled=True,
        format=SIEMFormat.CEF,
        syslog_host="syslog.example.com",
        syslog_port=514,
        syslog_protocol=SyslogProtocol.UDP,
        file_path=str(tmp_path / "siem.log"),
    )

    with patch("socket.socket") as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        exporter = SIEMExporter(config)
        result = exporter.export_event(sample_event)

        assert result is True

        # Check both outputs
        mock_sock_instance.sendto.assert_called_once()  # Syslog
        assert (tmp_path / "siem.log").exists()  # File


def test_siem_exporter_batch_with_errors(
    siem_config_file: SIEMConfig, sample_event: AuditEvent
) -> None:
    """Test batch export handles individual failures."""
    # Make file path invalid after creating exporter
    exporter = SIEMExporter(siem_config_file)

    events = [sample_event for _ in range(3)]

    # Corrupt the config to cause failures
    original_path = siem_config_file.file_path
    siem_config_file.file_path = "/invalid/path/file.log"

    result = exporter.export_batch(events)

    assert result.success is False
    assert result.events_exported < len(events)
    assert len(result.errors) > 0

    # Restore path
    siem_config_file.file_path = original_path
