"""
vuln_scanner.py - Vulnerability scanner integration

Integrates with security scanning tools:
- Semgrep: SAST (Static Application Security Testing)
- pip-audit: Dependency vulnerability scanning

NIST: RA-5 - Vulnerability scanning
"""

import json
import shutil
import subprocess
from pathlib import Path

from loguru import logger

from pdfsigner.core.security.vuln_types import Vulnerability, VulnSeverity, VulnSource


class ScannerNotAvailableError(Exception):
    """Raised when scanner tool is not installed."""

    pass


class SemgrepScanner:
    """
    Semgrep SAST scanner integration.

    Scans code for security vulnerabilities using Semgrep rules.
    """

    def __init__(self):
        """Initialize scanner and check availability."""
        self.available = shutil.which("semgrep") is not None
        if not self.available:
            logger.warning("Semgrep not found in PATH. Install with: pip install semgrep")

    def scan_path(self, path: str | Path, config: str = "auto") -> list[Vulnerability]:
        """
        Scan path for vulnerabilities.

        Args:
            path: Path to scan (file or directory)
            config: Semgrep config (auto, p/security-audit, p/owasp-top-ten, etc.)

        Returns:
            List of discovered vulnerabilities

        Raises:
            ScannerNotAvailableError: If semgrep not installed
        """
        if not self.available:
            raise ScannerNotAvailableError("Semgrep not available")

        path = Path(path).resolve()
        logger.info(f"Running Semgrep scan on {path} with config={config}")

        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config", config, "--json", str(path)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                shell=False,
            )

            if result.returncode in (0, 1):  # 0=no findings, 1=findings
                output = json.loads(result.stdout)
                vulnerabilities = self.parse_semgrep_output(output)
                logger.info(f"Semgrep found {len(vulnerabilities)} issues in {path}")
                return vulnerabilities
            else:
                logger.error(f"Semgrep scan failed: {result.stderr}")
                return []

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out after 5 minutes")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return []
        except Exception as e:
            logger.error(f"Semgrep scan error: {e}")
            return []

    def parse_semgrep_output(self, output: dict) -> list[Vulnerability]:
        """
        Parse Semgrep JSON output to Vulnerability objects.

        Args:
            output: Semgrep JSON output dictionary

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        for result in output.get("results", []):
            # Map Semgrep severity to our enum
            semgrep_severity = result.get("extra", {}).get("severity", "INFO").upper()
            severity_map = {
                "ERROR": VulnSeverity.HIGH,
                "WARNING": VulnSeverity.MEDIUM,
                "INFO": VulnSeverity.LOW,
            }
            severity = severity_map.get(semgrep_severity, VulnSeverity.INFO)

            # Extract CWE if available
            cwe_ids = result.get("extra", {}).get("metadata", {}).get("cwe", [])
            cwe_id = f"CWE-{cwe_ids[0]}" if cwe_ids else None

            vuln = Vulnerability(
                title=result.get("check_id", "Unknown"),
                description=result.get("extra", {}).get("message", ""),
                severity=severity,
                source=VulnSource.SEMGREP,
                file_path=result.get("path"),
                line_number=result.get("start", {}).get("line"),
                cwe_id=cwe_id,
                remediation=result.get("extra", {}).get("metadata", {}).get("fix", None),
                metadata={
                    "rule_id": result.get("check_id"),
                    "confidence": result.get("extra", {})
                    .get("metadata", {})
                    .get("confidence", "UNKNOWN"),
                    "code_snippet": result.get("extra", {}).get("lines", ""),
                },
            )
            vulnerabilities.append(vuln)

        return vulnerabilities


class PipAuditScanner:
    """
    pip-audit dependency scanner integration.

    Scans Python dependencies for known vulnerabilities.
    """

    def __init__(self):
        """Initialize scanner and check availability."""
        self.available = shutil.which("pip-audit") is not None
        if not self.available:
            logger.warning("pip-audit not found in PATH. Install with: pip install pip-audit")

    def scan_dependencies(self, requirements_file: str | Path | None = None) -> list[Vulnerability]:
        """
        Scan dependencies for vulnerabilities.

        Args:
            requirements_file: Optional path to requirements.txt

        Returns:
            List of discovered vulnerabilities

        Raises:
            ScannerNotAvailableError: If pip-audit not installed
        """
        if not self.available:
            raise ScannerNotAvailableError("pip-audit not available")

        logger.info("Running pip-audit scan on dependencies")

        cmd = ["pip-audit", "--format", "json"]
        if requirements_file:
            cmd.extend(["--requirement", str(requirements_file)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                shell=False,
            )

            if result.returncode in (0, 1):  # 0=no findings, 1=findings
                output = json.loads(result.stdout)
                vulnerabilities = self.parse_pip_audit_output(output)
                logger.info(f"pip-audit found {len(vulnerabilities)} vulnerable dependencies")
                return vulnerabilities
            else:
                logger.error(f"pip-audit scan failed: {result.stderr}")
                return []

        except subprocess.TimeoutExpired:
            logger.error("pip-audit scan timed out after 5 minutes")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse pip-audit output: {e}")
            return []
        except Exception as e:
            logger.error(f"pip-audit scan error: {e}")
            return []

    def parse_pip_audit_output(self, output: dict) -> list[Vulnerability]:
        """
        Parse pip-audit JSON output to Vulnerability objects.

        Args:
            output: pip-audit JSON output dictionary

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        for dep in output.get("dependencies", []):
            package_name = dep.get("name")
            package_version = dep.get("version")

            for vuln_data in dep.get("vulns", []):
                # Map CVSS score to severity
                cvss_score = None
                for alias in vuln_data.get("aliases", []):
                    if "CVSS:" in alias:
                        try:
                            cvss_score = float(alias.split("CVSS:")[1].split("/")[0])
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Failed to parse CVSS score from alias '{alias}': {e}")

                severity = self._cvss_to_severity(cvss_score)

                # Determine fix version
                fix_versions = vuln_data.get("fix_versions", [])
                fix_version = fix_versions[0] if fix_versions else "latest"

                vuln = Vulnerability(
                    title=f"{package_name} {package_version}: {vuln_data.get('id')}",
                    description=vuln_data.get("description", "No description available"),
                    severity=severity,
                    source=VulnSource.PIP_AUDIT,
                    cvss_score=cvss_score,
                    remediation=f"Upgrade {package_name} to {fix_version}",
                    metadata={
                        "package": package_name,
                        "version": package_version,
                        "vulnerability_id": vuln_data.get("id"),
                        "fix_versions": vuln_data.get("fix_versions", []),
                        "aliases": vuln_data.get("aliases", []),
                    },
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _cvss_to_severity(self, cvss_score: float | None) -> VulnSeverity:
        """Convert CVSS score to VulnSeverity."""
        if cvss_score is None:
            return VulnSeverity.MEDIUM

        if cvss_score >= 9.0:
            return VulnSeverity.CRITICAL
        elif cvss_score >= 7.0:
            return VulnSeverity.HIGH
        elif cvss_score >= 4.0:
            return VulnSeverity.MEDIUM
        elif cvss_score > 0.0:
            return VulnSeverity.LOW
        else:
            return VulnSeverity.INFO


def run_all_scans(
    code_path: str | Path | None = None,
    requirements_file: str | Path | None = None,
) -> list[Vulnerability]:
    """
    Run all available vulnerability scans.

    Args:
        code_path: Path to scan with Semgrep (defaults to src/)
        requirements_file: Path to requirements.txt for pip-audit

    Returns:
        Combined list of vulnerabilities from all scanners
    """
    all_vulns = []

    # Default to src/ if no path specified
    if code_path is None:
        code_path = Path.cwd() / "src"

    # Run Semgrep
    semgrep = SemgrepScanner()
    if semgrep.available and Path(code_path).exists():
        try:
            all_vulns.extend(semgrep.scan_path(code_path))
        except ScannerNotAvailableError as e:
            logger.debug(f"Semgrep scanner not available: {e}")

    # Run pip-audit
    pip_audit = PipAuditScanner()
    if pip_audit.available:
        try:
            all_vulns.extend(pip_audit.scan_dependencies(requirements_file))
        except ScannerNotAvailableError as e:
            logger.debug(f"pip-audit scanner not available: {e}")

    logger.info(f"Total vulnerabilities found: {len(all_vulns)}")
    return all_vulns


__all__ = [
    "ScannerNotAvailableError",
    "SemgrepScanner",
    "PipAuditScanner",
    "run_all_scans",
]
