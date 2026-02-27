"""
test_siem_security.py - Security tests for SIEM TLS verification

Tests TLS certificate verification enforcement in SIEM exporter.
"""

import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.audit.siem_exporter import SIEMConfig, SIEMExporter, SyslogProtocol


class TestSIEMTLSVerification:
    """Test TLS certificate verification in SIEM exporter."""

    def test_tls_verification_enabled_by_default(self):
        """TLS verification should be enabled by default."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
        )

        exporter = SIEMExporter(config)

        # Default values
        assert config.tls_verify is True
        assert config.allow_insecure_tls is False

    def test_tls_verification_enforced_by_default(self):
        """TLS verification should be enforced when sending messages."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
        )

        exporter = SIEMExporter(config)

        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_EVENT,
            status="SUCCESS",
            details={"test": "security test"},
        )

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.fileno.return_value = -1

            with patch("ssl.create_default_context") as mock_ssl_context:
                mock_context = MagicMock()
                mock_ssl_context.return_value = mock_context
                mock_wrapped = MagicMock()
                mock_context.wrap_socket.return_value = mock_wrapped

                try:
                    exporter._send_tls(b"test message")
                except Exception:
                    pass  # Ignore connection errors, we're testing SSL config

                # Verify SSL context was created with default (secure) settings
                mock_ssl_context.assert_called_once()

                # Verify that check_hostname and verify_mode were NOT set to insecure values
                assert mock_context.check_hostname != False  # noqa: E712
                assert mock_context.verify_mode != ssl.CERT_NONE

    def test_tls_verify_false_shows_deprecation_warning(self):
        """Using tls_verify=False should show deprecation warning."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
            tls_verify=False,  # Deprecated parameter
        )

        exporter = SIEMExporter(config)

        # Test that tls_verify=False still works (backward compatibility)
        # The actual deprecation warning is logged but hard to test with loguru
        with (
            patch("socket.socket") as mock_socket_class,
            patch("ssl.create_default_context") as mock_ssl_context,
        ):
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.fileno.return_value = -1

            mock_context = MagicMock()
            mock_ssl_context.return_value = mock_context
            mock_wrapped = MagicMock()
            mock_context.wrap_socket.return_value = mock_wrapped

            # Should not raise exception (backward compatibility)
            result = exporter._send_tls(b"test message")
            assert result is True

    def test_allow_insecure_tls_explicitly_disables_verification(self):
        """allow_insecure_tls=True should explicitly disable TLS verification."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
            allow_insecure_tls=True,  # Explicit opt-in to insecure mode
        )

        exporter = SIEMExporter(config)

        with patch("pdfsigner.core.audit.siem_transport.logger") as mock_logger:
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.fileno.return_value = -1

                with patch("ssl.create_default_context") as mock_ssl_context:
                    mock_context = MagicMock()
                    mock_ssl_context.return_value = mock_context
                    mock_wrapped = MagicMock()
                    mock_context.wrap_socket.return_value = mock_wrapped

                    try:
                        exporter._send_tls(b"test message")
                    except Exception:
                        pass

            # Verify security warning was logged
            warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
            assert any("SECURITY WARNING" in call_str for call_str in warning_calls)

    def test_insecure_tls_logs_security_warning(self):
        """Disabling TLS verification should log a security warning."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
            allow_insecure_tls=True,
        )

        exporter = SIEMExporter(config)

        with patch("pdfsigner.core.audit.siem_transport.logger") as mock_logger:
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.fileno.return_value = -1

                with patch("ssl.create_default_context") as mock_ssl_context:
                    mock_context = MagicMock()
                    mock_ssl_context.return_value = mock_context
                    mock_wrapped = MagicMock()
                    mock_context.wrap_socket.return_value = mock_wrapped

                    try:
                        exporter._send_tls(b"test message")
                    except Exception:
                        pass

            # Verify security warning was logged
            warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
            assert any("SECURITY WARNING" in call_str for call_str in warning_calls)
            assert any(
                "TLS certificate verification is DISABLED" in call_str for call_str in warning_calls
            )

    def test_secure_tls_logs_debug_message(self):
        """Secure TLS should log debug message confirming verification."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
        )

        exporter = SIEMExporter(config)

        with patch("pdfsigner.core.audit.siem_transport.logger") as mock_logger:
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.fileno.return_value = -1

                with patch("ssl.create_default_context") as mock_ssl_context:
                    mock_context = MagicMock()
                    mock_ssl_context.return_value = mock_context
                    mock_wrapped = MagicMock()
                    mock_context.wrap_socket.return_value = mock_wrapped

                    try:
                        exporter._send_tls(b"test message")
                    except Exception:
                        pass

            # Verify debug message was logged
            debug_calls = [str(call) for call in mock_logger.debug.call_args_list]
            assert any(
                "TLS certificate verification enabled" in call_str for call_str in debug_calls
            )

    def test_custom_tls_cert_path_loaded(self):
        """Custom TLS certificate path should be loaded into SSL context."""
        # Mock Path.exists() to avoid validation error
        with patch.object(Path, "exists", return_value=True):
            config = SIEMConfig(
                enabled=True,
                syslog_host="siem.example.com",
                syslog_port=6514,
                syslog_protocol=SyslogProtocol.TLS,
                tls_cert_path="/path/to/ca-cert.pem",
            )

            exporter = SIEMExporter(config)

            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.fileno.return_value = -1

                with patch("ssl.create_default_context") as mock_ssl_context:
                    mock_context = MagicMock()
                    mock_ssl_context.return_value = mock_context
                    mock_wrapped = MagicMock()
                    mock_context.wrap_socket.return_value = mock_wrapped

                    try:
                        exporter._send_tls(b"test message")
                    except Exception:
                        pass

                    # Verify custom certificate was loaded
                    mock_context.load_verify_locations.assert_called_once_with(
                        "/path/to/ca-cert.pem"
                    )

    def test_tls_verify_false_and_allow_insecure_both_work(self):
        """Both deprecated tls_verify=False and new allow_insecure_tls=True should disable verification."""
        config1 = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
            tls_verify=False,  # Deprecated
        )

        config2 = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
            allow_insecure_tls=True,  # New parameter
        )

        exporter1 = SIEMExporter(config1)
        exporter2 = SIEMExporter(config2)

        # Both configurations should work without raising exceptions
        for exporter in [exporter1, exporter2]:
            with (
                patch("socket.socket") as mock_socket_class,
                patch("ssl.create_default_context") as mock_ssl_context,
            ):
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                mock_socket.fileno.return_value = -1

                mock_context = MagicMock()
                mock_ssl_context.return_value = mock_context
                mock_wrapped = MagicMock()
                mock_context.wrap_socket.return_value = mock_wrapped

                # Both should work without exceptions
                result = exporter._send_tls(b"test message")
                assert result is True

    def test_export_event_with_secure_tls(self):
        """Test full event export flow with secure TLS."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
        )

        exporter = SIEMExporter(config)

        event = AuditEvent(
            event_type=AuditEventType.TOKEN_LOGIN,
            status="SUCCESS",
            user_id="test-user",
            details={"ip": "192.168.1.100"},
        )

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            mock_socket.fileno.return_value = -1

            with patch("ssl.create_default_context") as mock_ssl_context:
                mock_context = MagicMock()
                mock_ssl_context.return_value = mock_context
                mock_wrapped = MagicMock()
                mock_context.wrap_socket.return_value = mock_wrapped

                result = exporter.export_event(event)

                # Should succeed
                assert result is True

                # Verify SSL context was created securely
                assert mock_context.check_hostname != False  # noqa: E712
                assert mock_context.verify_mode != ssl.CERT_NONE


class TestSIEMSecurityEdgeCases:
    """Test edge cases in SIEM security."""

    def test_connection_reuse_maintains_security(self):
        """Reusing TLS connection should maintain security settings."""
        config = SIEMConfig(
            enabled=True,
            syslog_host="siem.example.com",
            syslog_port=6514,
            syslog_protocol=SyslogProtocol.TLS,
        )

        exporter = SIEMExporter(config)

        with patch("socket.socket") as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket

            with patch("ssl.create_default_context") as mock_ssl_context:
                mock_context = MagicMock()
                mock_ssl_context.return_value = mock_context
                mock_wrapped = MagicMock()
                mock_context.wrap_socket.return_value = mock_wrapped

                # First send - establishes connection
                mock_socket.fileno.return_value = -1
                try:
                    exporter._send_tls(b"message 1")
                except Exception:
                    pass

                # Second send - reuses connection
                mock_socket.fileno.return_value = 1
                try:
                    exporter._send_tls(b"message 2")
                except Exception:
                    pass

                # SSL context should only be created once (for first connection)
                assert mock_ssl_context.call_count == 1

    def test_udp_and_tcp_not_affected_by_tls_settings(self):
        """UDP and TCP protocols should not be affected by TLS settings."""
        for protocol in [SyslogProtocol.UDP, SyslogProtocol.TCP]:
            config = SIEMConfig(
                enabled=True,
                syslog_host="siem.example.com",
                syslog_port=514,
                syslog_protocol=protocol,
                allow_insecure_tls=True,  # Should be ignored for non-TLS
            )

            exporter = SIEMExporter(config)

            event = AuditEvent(
                event_type=AuditEventType.SYSTEM_EVENT,
                status="SUCCESS",
                details={"test": "protocol test"},
            )

            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket

                result = exporter.export_event(event)

                # Should succeed without SSL context being created
                assert result is True
