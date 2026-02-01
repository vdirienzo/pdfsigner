"""
test_vuln_scanner.py - Tests for vulnerability scanner

Tests Semgrep and pip-audit integration for NIST RA-5 compliance.
"""

from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.security import (
    PipAuditScanner,
    ScannerNotAvailableError,
    SemgrepScanner,
    VulnSeverity,
    VulnSource,
)


class TestSemgrepScanner:
    """Test Semgrep scanner integration."""

    def test_scanner_initialization_available(self):
        """Test scanner initialization when Semgrep is available."""
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            scanner = SemgrepScanner()
            assert scanner.available is True

    def test_scanner_initialization_unavailable(self):
        """Test scanner initialization when Semgrep is not available."""
        with patch("shutil.which", return_value=None):
            scanner = SemgrepScanner()
            assert scanner.available is False

    def test_scan_path_not_available_raises_error(self):
        """Test scan_path raises error when scanner not available."""
        with patch("shutil.which", return_value=None):
            scanner = SemgrepScanner()
            with pytest.raises(ScannerNotAvailableError):
                scanner.scan_path("/fake/path")

    def test_parse_semgrep_output_empty(self):
        """Test parsing empty Semgrep output."""
        scanner = SemgrepScanner()
        output = {"results": []}
        vulnerabilities = scanner.parse_semgrep_output(output)
        assert len(vulnerabilities) == 0

    def test_parse_semgrep_output_single_finding(self):
        """Test parsing Semgrep output with one finding."""
        scanner = SemgrepScanner()
        output = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-system-call",
                    "path": "src/example.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Detected use of os.system()",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": [78],
                            "confidence": "HIGH",
                            "fix": "Use subprocess with shell=False",
                        },
                        "lines": "os.system(user_input)",
                    },
                }
            ]
        }

        vulnerabilities = scanner.parse_semgrep_output(output)

        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.title == "python.lang.security.audit.dangerous-system-call"
        assert vuln.description == "Detected use of os.system()"
        assert vuln.severity == VulnSeverity.HIGH
        assert vuln.source == VulnSource.SEMGREP
        assert vuln.file_path == "src/example.py"
        assert vuln.line_number == 42
        assert vuln.cwe_id == "CWE-78"
        assert vuln.remediation == "Use subprocess with shell=False"
        assert vuln.metadata["confidence"] == "HIGH"

    def test_parse_semgrep_output_severity_mapping(self):
        """Test Semgrep severity mapping to VulnSeverity."""
        scanner = SemgrepScanner()

        # Test ERROR -> HIGH
        output = {
            "results": [
                {
                    "check_id": "test-rule",
                    "path": "test.py",
                    "start": {"line": 1},
                    "extra": {"message": "Test", "severity": "ERROR"},
                }
            ]
        }
        vulns = scanner.parse_semgrep_output(output)
        assert vulns[0].severity == VulnSeverity.HIGH

        # Test WARNING -> MEDIUM
        output["results"][0]["extra"]["severity"] = "WARNING"
        vulns = scanner.parse_semgrep_output(output)
        assert vulns[0].severity == VulnSeverity.MEDIUM

        # Test INFO -> LOW
        output["results"][0]["extra"]["severity"] = "INFO"
        vulns = scanner.parse_semgrep_output(output)
        assert vulns[0].severity == VulnSeverity.LOW

    def test_scan_path_timeout(self):
        """Test scan_path handles timeout gracefully."""
        import subprocess

        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            scanner = SemgrepScanner()

            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300)):
                vulnerabilities = scanner.scan_path("/fake/path")
                assert len(vulnerabilities) == 0


class TestPipAuditScanner:
    """Test pip-audit scanner integration."""

    def test_scanner_initialization_available(self):
        """Test scanner initialization when pip-audit is available."""
        with patch("shutil.which", return_value="/usr/bin/pip-audit"):
            scanner = PipAuditScanner()
            assert scanner.available is True

    def test_scanner_initialization_unavailable(self):
        """Test scanner initialization when pip-audit is not available."""
        with patch("shutil.which", return_value=None):
            scanner = PipAuditScanner()
            assert scanner.available is False

    def test_scan_dependencies_not_available_raises_error(self):
        """Test scan_dependencies raises error when scanner not available."""
        with patch("shutil.which", return_value=None):
            scanner = PipAuditScanner()
            with pytest.raises(ScannerNotAvailableError):
                scanner.scan_dependencies()

    def test_parse_pip_audit_output_empty(self):
        """Test parsing empty pip-audit output."""
        scanner = PipAuditScanner()
        output = {"dependencies": []}
        vulnerabilities = scanner.parse_pip_audit_output(output)
        assert len(vulnerabilities) == 0

    def test_parse_pip_audit_output_single_vuln(self):
        """Test parsing pip-audit output with one vulnerability."""
        scanner = PipAuditScanner()
        output = {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-123",
                            "description": "Server-side request forgery vulnerability",
                            "aliases": ["CVE-2023-12345", "CVSS:8.5/HIGH"],
                            "fix_versions": ["2.31.0"],
                        }
                    ],
                }
            ]
        }

        vulnerabilities = scanner.parse_pip_audit_output(output)

        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.title == "requests 2.25.0: PYSEC-2023-123"
        assert vuln.description == "Server-side request forgery vulnerability"
        assert vuln.severity == VulnSeverity.HIGH
        assert vuln.source == VulnSource.PIP_AUDIT
        assert vuln.cvss_score == 8.5
        assert vuln.remediation == "Upgrade requests to 2.31.0"
        assert vuln.metadata["package"] == "requests"
        assert vuln.metadata["version"] == "2.25.0"

    def test_cvss_to_severity_mapping(self):
        """Test CVSS score to severity mapping."""
        scanner = PipAuditScanner()

        assert scanner._cvss_to_severity(9.5) == VulnSeverity.CRITICAL
        assert scanner._cvss_to_severity(7.5) == VulnSeverity.HIGH
        assert scanner._cvss_to_severity(5.0) == VulnSeverity.MEDIUM
        assert scanner._cvss_to_severity(2.0) == VulnSeverity.LOW
        assert scanner._cvss_to_severity(0.0) == VulnSeverity.INFO
        assert scanner._cvss_to_severity(None) == VulnSeverity.MEDIUM

    def test_parse_pip_audit_output_no_fix_versions(self):
        """Test parsing pip-audit output without fix versions."""
        scanner = PipAuditScanner()
        output = {
            "dependencies": [
                {
                    "name": "vulnerable-pkg",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "VULN-001",
                            "description": "Test vulnerability",
                            "aliases": [],
                            "fix_versions": [],
                        }
                    ],
                }
            ]
        }

        vulnerabilities = scanner.parse_pip_audit_output(output)

        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.remediation == "Upgrade vulnerable-pkg to latest"

    def test_scan_dependencies_json_decode_error(self):
        """Test scan_dependencies handles JSON decode errors."""

        with patch("shutil.which", return_value="/usr/bin/pip-audit"):
            scanner = PipAuditScanner()

            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "invalid json{"

            with patch("subprocess.run", return_value=mock_result):
                vulnerabilities = scanner.scan_dependencies()
                assert len(vulnerabilities) == 0


class TestRunAllScans:
    """Test run_all_scans function."""

    def test_run_all_scans_no_scanners_available(self):
        """Test run_all_scans when no scanners available."""
        with patch("shutil.which", return_value=None):
            from pdfsigner.core.security.vuln_scanner import run_all_scans

            vulnerabilities = run_all_scans()
            assert len(vulnerabilities) == 0

    def test_run_all_scans_with_mocked_scanners(self):
        """Test run_all_scans with mocked scanner results."""
        from pdfsigner.core.security import Vulnerability
        from pdfsigner.core.security.vuln_scanner import run_all_scans

        mock_vuln = Vulnerability(
            title="Test vulnerability",
            description="Test description",
            severity=VulnSeverity.HIGH,
            source=VulnSource.SEMGREP,
        )

        with patch("pdfsigner.core.security.vuln_scanner.SemgrepScanner") as MockSemgrep:
            with patch("pdfsigner.core.security.vuln_scanner.PipAuditScanner") as MockPipAudit:
                # Setup mocks
                mock_semgrep_instance = MockSemgrep.return_value
                mock_semgrep_instance.available = True
                mock_semgrep_instance.scan_path.return_value = [mock_vuln]

                mock_pip_instance = MockPipAudit.return_value
                mock_pip_instance.available = True
                mock_pip_instance.scan_dependencies.return_value = []

                vulnerabilities = run_all_scans()

                assert len(vulnerabilities) == 1
                assert vulnerabilities[0].title == "Test vulnerability"
