"""
vuln_report.py - Vulnerability reporting

Generates various vulnerability reports for compliance and management.
NIST: RA-5 - Vulnerability reporting and metrics
"""

import csv
import io
from datetime import datetime, timedelta

from loguru import logger

from pdfsigner.core.security.vuln_repository import VulnRepository, get_vuln_repository
from pdfsigner.core.security.vuln_types import VulnSeverity, VulnStatus


class VulnReporter:
    """
    Vulnerability reporting and analytics.

    Generates reports for:
    - Executive summaries
    - Detailed findings
    - Monthly/quarterly metrics
    - CSV exports
    """

    def __init__(self, repository: VulnRepository | None = None):
        """
        Initialize reporter.

        Args:
            repository: Vulnerability repository (uses singleton if None)
        """
        self.repository = repository or get_vuln_repository()

    def generate_summary_report(self) -> dict:
        """
        Generate executive summary report.

        Returns:
            Dictionary with high-level vulnerability statistics
        """
        stats = self.repository.get_statistics()

        # Calculate additional metrics
        high_critical_open = stats.get("high_critical_open", 0)
        total_open = stats.get("open", 0)

        # Get overdue vulnerabilities (30+ days)
        overdue = self._count_overdue_vulnerabilities(days=30)

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_vulnerabilities": stats["total"],
                "open": total_open,
                "resolved": stats["by_status"].get("resolved", 0),
                "high_critical_open": high_critical_open,
                "overdue_30_days": overdue,
            },
            "by_severity": stats["by_severity"],
            "by_status": stats["by_status"],
            "risk_score": self._calculate_risk_score(stats),
        }

        logger.debug("Generated summary report")
        return report

    def generate_detailed_report(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        severity: VulnSeverity | None = None,
    ) -> dict:
        """
        Generate detailed vulnerability report.

        Args:
            start_date: Filter vulnerabilities discovered after this date
            end_date: Filter vulnerabilities discovered before this date
            severity: Filter by severity level

        Returns:
            Dictionary with detailed vulnerability information
        """
        # Get all vulnerabilities
        vulnerabilities = self.repository.list_vulnerabilities(
            severity=severity,
            limit=10000,
        )

        # Filter by date range
        if start_date:
            vulnerabilities = [v for v in vulnerabilities if v.discovered_at >= start_date]
        if end_date:
            vulnerabilities = [v for v in vulnerabilities if v.discovered_at <= end_date]

        # Sort by severity (critical first) then by date
        vulnerabilities.sort(key=lambda v: (-list(VulnSeverity).index(v.severity), v.discovered_at))

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "filters": {
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
                "severity": severity.value if severity else None,
            },
            "total_count": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "status": v.status.value,
                    "source": v.source.value,
                    "file": v.file_path,
                    "line": v.line_number,
                    "cwe": v.cwe_id,
                    "cvss": v.cvss_score,
                    "discovered": v.discovered_at.isoformat(),
                    "resolved": v.resolved_at.isoformat() if v.resolved_at else None,
                    "days_open": v.days_open(),
                    "assignee": v.assignee,
                }
                for v in vulnerabilities
            ],
        }

        logger.debug(f"Generated detailed report with {len(vulnerabilities)} vulnerabilities")
        return report

    def generate_monthly_report(self, year: int, month: int) -> dict:
        """
        Generate monthly vulnerability metrics report.

        Args:
            year: Year (e.g., 2024)
            month: Month (1-12)

        Returns:
            Dictionary with monthly metrics
        """
        # Date range for the month
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)

        # Get vulnerabilities discovered in this month
        all_vulns = self.repository.list_vulnerabilities(limit=10000)
        discovered = [v for v in all_vulns if start_date <= v.discovered_at < end_date]

        # Get vulnerabilities resolved in this month
        resolved = [
            v for v in all_vulns if v.resolved_at and start_date <= v.resolved_at < end_date
        ]

        # Calculate MTTR (Mean Time To Resolution)
        mttr = self._calculate_mttr(resolved)

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "period": {
                "year": year,
                "month": month,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            "metrics": {
                "discovered": len(discovered),
                "resolved": len(resolved),
                "discovered_by_severity": self._count_by_severity(discovered),
                "resolved_by_severity": self._count_by_severity(resolved),
                "mttr_days": mttr,
            },
        }

        logger.debug(f"Generated monthly report for {year}-{month:02d}")
        return report

    def export_to_csv(
        self,
        vulnerabilities: list | None = None,
        severity: VulnSeverity | None = None,
    ) -> str:
        """
        Export vulnerabilities to CSV format.

        Args:
            vulnerabilities: List of vulnerabilities (or None to get all)
            severity: Filter by severity

        Returns:
            CSV string
        """
        if vulnerabilities is None:
            vulnerabilities = self.repository.list_vulnerabilities(
                severity=severity,
                limit=10000,
            )

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "ID",
                "Title",
                "Severity",
                "Status",
                "Source",
                "File",
                "Line",
                "CWE",
                "CVSS",
                "Discovered",
                "Resolved",
                "Days Open",
                "Assignee",
            ]
        )

        # Write rows
        for v in vulnerabilities:
            writer.writerow(
                [
                    v.id,
                    v.title,
                    v.severity.value,
                    v.status.value,
                    v.source.value,
                    v.file_path or "",
                    v.line_number or "",
                    v.cwe_id or "",
                    v.cvss_score or "",
                    v.discovered_at.isoformat(),
                    v.resolved_at.isoformat() if v.resolved_at else "",
                    v.days_open(),
                    v.assignee or "",
                ]
            )

        csv_content = output.getvalue()
        logger.debug(f"Exported {len(vulnerabilities)} vulnerabilities to CSV")
        return csv_content

    # --- Private Helpers ---

    def _calculate_risk_score(self, stats: dict) -> int:
        """
        Calculate overall risk score (0-100).

        Higher score = higher risk
        """
        # Weight by severity
        severity_weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1,
            "info": 0,
        }

        by_severity = stats.get("by_severity", {})

        # Calculate weighted sum of open vulnerabilities
        open_score = 0
        for severity, count in by_severity.items():
            weight = severity_weights.get(severity, 0)
            # Only count open/in_progress vulnerabilities
            open_count = (
                count
                if severity == "all"
                else len(
                    self.repository.list_vulnerabilities(
                        severity=VulnSeverity(severity),
                        status=VulnStatus.OPEN,
                        limit=1000,
                    )
                )
                + len(
                    self.repository.list_vulnerabilities(
                        severity=VulnSeverity(severity),
                        status=VulnStatus.IN_PROGRESS,
                        limit=1000,
                    )
                )
            )
            open_score += weight * open_count

        # Cap at 100
        risk_score = min(100, open_score)
        return risk_score

    def _count_overdue_vulnerabilities(self, days: int = 30) -> int:
        """Count vulnerabilities open for more than specified days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        all_open = self.repository.list_vulnerabilities(
            status=VulnStatus.OPEN,
            limit=1000,
        )
        all_open.extend(
            self.repository.list_vulnerabilities(
                status=VulnStatus.IN_PROGRESS,
                limit=1000,
            )
        )
        return len([v for v in all_open if v.discovered_at < cutoff])

    def _count_by_severity(self, vulnerabilities: list) -> dict:
        """Count vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in VulnSeverity}
        for v in vulnerabilities:
            counts[v.severity.value] += 1
        return counts

    def _calculate_mttr(self, resolved_vulns: list) -> float:
        """Calculate Mean Time To Resolution in days."""
        if not resolved_vulns:
            return 0.0

        total_days = sum(v.days_open() for v in resolved_vulns)
        return round(total_days / len(resolved_vulns), 1)


# Singleton instance
_vuln_reporter: VulnReporter | None = None


def get_vuln_reporter() -> VulnReporter:
    """Get singleton vulnerability reporter."""
    global _vuln_reporter
    if _vuln_reporter is None:
        _vuln_reporter = VulnReporter()
    return _vuln_reporter


__all__ = ["VulnReporter", "get_vuln_reporter"]
