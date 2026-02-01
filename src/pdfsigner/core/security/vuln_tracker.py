"""
vuln_tracker.py - Vulnerability tracking and workflow

Manages vulnerability lifecycle, deduplication, and SLA tracking.
NIST: RA-5 - Vulnerability remediation process
"""

from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.core.security.vuln_repository import VulnRepository, get_vuln_repository
from pdfsigner.core.security.vuln_types import Vulnerability, VulnStatus


class VulnTracker:
    """
    Vulnerability tracking and workflow manager.

    Handles:
    - Vulnerability deduplication
    - Status updates with audit trail
    - SLA monitoring
    - Scan result imports
    """

    def __init__(self, repository: VulnRepository | None = None):
        """
        Initialize tracker.

        Args:
            repository: Vulnerability repository (uses singleton if None)
        """
        self.repository = repository or get_vuln_repository()

    def add_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """
        Add vulnerability with deduplication.

        If a similar vulnerability exists (same title, file, line),
        updates existing instead of creating duplicate.

        Args:
            vuln: Vulnerability to add

        Returns:
            Saved or updated vulnerability
        """
        # Check for existing similar vulnerability
        existing = self._find_similar(vuln)

        if existing:
            logger.debug(f"Found similar vulnerability {existing.id}, updating instead of creating")
            # Update severity if new finding is more severe
            if vuln.severity > existing.severity:
                existing.severity = vuln.severity
            # Reopen if it was previously resolved/accepted
            if existing.status in {
                VulnStatus.RESOLVED,
                VulnStatus.ACCEPTED,
                VulnStatus.FALSE_POSITIVE,
            }:
                existing.status = VulnStatus.OPEN
                existing.resolved_at = None
                logger.info(f"Reopened previously closed vulnerability {existing.id}")
            # Update metadata
            existing.metadata["last_seen"] = datetime.utcnow().isoformat()
            return self.repository.save_vulnerability(existing)
        else:
            # New vulnerability
            vuln.metadata["first_seen"] = datetime.utcnow().isoformat()
            return self.repository.save_vulnerability(vuln)

    def update_status(
        self,
        vuln_id: str,
        new_status: VulnStatus,
        notes: str | None = None,
        assignee: str | None = None,
    ) -> bool:
        """
        Update vulnerability status with audit trail.

        Args:
            vuln_id: Vulnerability ID
            new_status: New status
            notes: Optional status change notes
            assignee: Optional assignee

        Returns:
            True if updated, False if not found
        """
        vuln = self.repository.get_vulnerability(vuln_id)
        if not vuln:
            logger.warning(f"Vulnerability {vuln_id} not found")
            return False

        old_status = vuln.status
        vuln.status = new_status

        if new_status == VulnStatus.RESOLVED:
            vuln.resolved_at = datetime.utcnow()

        if assignee:
            vuln.assignee = assignee

        # Add status change to metadata
        if "status_history" not in vuln.metadata:
            vuln.metadata["status_history"] = []

        vuln.metadata["status_history"].append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "from": old_status.value,
                "to": new_status.value,
                "notes": notes,
                "assignee": assignee,
            }
        )

        self.repository.save_vulnerability(vuln)
        logger.info(f"Updated vulnerability {vuln_id}: {old_status.value} -> {new_status.value}")
        return True

    def assign_vulnerability(self, vuln_id: str, assignee: str) -> bool:
        """
        Assign vulnerability to user.

        Args:
            vuln_id: Vulnerability ID
            assignee: Username to assign

        Returns:
            True if assigned, False if not found
        """
        vuln = self.repository.get_vulnerability(vuln_id)
        if not vuln:
            return False

        vuln.assignee = assignee
        vuln.metadata["assigned_at"] = datetime.utcnow().isoformat()

        self.repository.save_vulnerability(vuln)
        logger.info(f"Assigned vulnerability {vuln_id} to {assignee}")
        return True

    def get_overdue_vulnerabilities(self, sla_days: int = 30) -> list[Vulnerability]:
        """
        Get vulnerabilities that exceed SLA.

        Args:
            sla_days: SLA in days (default 30)

        Returns:
            List of overdue open vulnerabilities
        """
        cutoff_date = datetime.utcnow() - timedelta(days=sla_days)
        all_open = self.repository.list_vulnerabilities(
            status=VulnStatus.OPEN,
            limit=1000,
        )

        # Add IN_PROGRESS status
        all_open.extend(
            self.repository.list_vulnerabilities(
                status=VulnStatus.IN_PROGRESS,
                limit=1000,
            )
        )

        overdue = [v for v in all_open if v.discovered_at < cutoff_date]
        logger.debug(f"Found {len(overdue)} overdue vulnerabilities (SLA: {sla_days} days)")
        return overdue

    def import_scan_results(
        self,
        vulnerabilities: list[Vulnerability],
        mark_missing_as_resolved: bool = False,
    ) -> dict:
        """
        Import scan results with deduplication.

        Args:
            vulnerabilities: List of vulnerabilities from scan
            mark_missing_as_resolved: If True, mark existing vulnerabilities
                not found in scan as resolved

        Returns:
            Dictionary with import statistics
        """
        stats = {
            "total_scanned": len(vulnerabilities),
            "new": 0,
            "updated": 0,
            "resolved": 0,
        }

        # Track seen vulnerability identifiers
        seen_identifiers = set()

        # Import each vulnerability
        for vuln in vulnerabilities:
            identifier = self._get_vuln_identifier(vuln)
            seen_identifiers.add(identifier)

            existing = self._find_similar(vuln)
            if existing:
                # Update existing
                if existing.severity != vuln.severity or existing.status in {
                    VulnStatus.RESOLVED,
                    VulnStatus.FALSE_POSITIVE,
                }:
                    self.add_vulnerability(vuln)
                    stats["updated"] += 1
            else:
                # New vulnerability
                self.add_vulnerability(vuln)
                stats["new"] += 1

        # Mark missing vulnerabilities as resolved (if enabled)
        if mark_missing_as_resolved:
            all_open = self.repository.list_vulnerabilities(status=VulnStatus.OPEN, limit=1000)
            for vuln in all_open:
                identifier = self._get_vuln_identifier(vuln)
                if identifier not in seen_identifiers and vuln.source == vulnerabilities[0].source:
                    self.update_status(
                        vuln.id, VulnStatus.RESOLVED, notes="Not found in recent scan"
                    )
                    stats["resolved"] += 1

        logger.info(
            f"Import complete: {stats['new']} new, "
            f"{stats['updated']} updated, {stats['resolved']} resolved"
        )
        return stats

    # --- Private Helpers ---

    def _find_similar(self, vuln: Vulnerability) -> Vulnerability | None:
        """
        Find similar existing vulnerability.

        Matches on: title, file_path, line_number (if available)
        """
        # Get all vulnerabilities from same source
        candidates = self.repository.list_vulnerabilities(
            source=vuln.source,
            limit=1000,
        )

        for candidate in candidates:
            # Match by title and location
            if candidate.title == vuln.title:
                # If both have file/line info, match on that
                if vuln.file_path and candidate.file_path:
                    if (
                        vuln.file_path == candidate.file_path
                        and vuln.line_number == candidate.line_number
                    ):
                        return candidate
                # Otherwise, just title match is enough
                elif not vuln.file_path and not candidate.file_path:
                    return candidate

        return None

    def _get_vuln_identifier(self, vuln: Vulnerability) -> str:
        """Get unique identifier for vulnerability."""
        parts = [vuln.source.value, vuln.title]
        if vuln.file_path:
            parts.append(str(Path(vuln.file_path).resolve()))
        if vuln.line_number:
            parts.append(str(vuln.line_number))
        return "|".join(parts)


# Singleton instance
_vuln_tracker: VulnTracker | None = None


def get_vuln_tracker() -> VulnTracker:
    """Get singleton vulnerability tracker."""
    global _vuln_tracker
    if _vuln_tracker is None:
        _vuln_tracker = VulnTracker()
    return _vuln_tracker


__all__ = ["VulnTracker", "get_vuln_tracker"]
