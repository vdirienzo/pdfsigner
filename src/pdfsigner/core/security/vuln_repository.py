"""
vuln_repository.py - Vulnerability persistence with SQLite

Provides CRUD operations for vulnerability management.
NIST: RA-5 - Vulnerability scanning and tracking
"""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.security.vuln_types import (
    Vulnerability,
    VulnSeverity,
    VulnSource,
    VulnStatus,
)


class VulnRepository:
    """
    SQLite-based vulnerability repository.

    Stores vulnerabilities with full CRUD operations.
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize repository.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/vulnerabilities.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "vulnerabilities.db"

        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with automatic cleanup."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    cwe_id TEXT,
                    cvss_score REAL,
                    discovered_at TEXT NOT NULL,
                    resolved_at TEXT,
                    assignee TEXT,
                    remediation TEXT,
                    metadata TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
                CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status);
                CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source);
                CREATE INDEX IF NOT EXISTS idx_vuln_discovered ON vulnerabilities(discovered_at);
            """)

    # --- CRUD Operations ---

    def save_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """
        Save or update vulnerability.

        Args:
            vuln: Vulnerability to save

        Returns:
            Saved vulnerability
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities (
                    id, title, description, severity, status, source,
                    file_path, line_number, cwe_id, cvss_score,
                    discovered_at, resolved_at, assignee, remediation, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.id,
                    vuln.title,
                    vuln.description,
                    vuln.severity.value,
                    vuln.status.value,
                    vuln.source.value,
                    vuln.file_path,
                    vuln.line_number,
                    vuln.cwe_id,
                    vuln.cvss_score,
                    vuln.discovered_at.isoformat(),
                    vuln.resolved_at.isoformat() if vuln.resolved_at else None,
                    vuln.assignee,
                    vuln.remediation,
                    json.dumps(vuln.metadata),
                ),
            )
        logger.debug(f"Saved vulnerability: {vuln.id} - {vuln.title}")
        return vuln

    def get_vulnerability(self, vuln_id: str) -> Vulnerability | None:
        """Get vulnerability by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
            return self._row_to_vuln(row) if row else None

    def list_vulnerabilities(
        self,
        status: VulnStatus | None = None,
        severity: VulnSeverity | None = None,
        source: VulnSource | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Vulnerability]:
        """
        List vulnerabilities with optional filters.

        Args:
            status: Filter by status
            severity: Filter by severity
            source: Filter by source
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching vulnerabilities
        """
        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params: list = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if source:
            query += " AND source = ?"
            params.append(source.value)

        query += " ORDER BY discovered_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_vuln(row) for row in rows]

    def update_status(self, vuln_id: str, new_status: VulnStatus) -> bool:
        """
        Update vulnerability status.

        Args:
            vuln_id: Vulnerability ID
            new_status: New status

        Returns:
            True if updated, False if not found
        """
        resolved_at = datetime.utcnow().isoformat() if new_status == VulnStatus.RESOLVED else None

        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE vulnerabilities SET status = ?, resolved_at = ? WHERE id = ?",
                (new_status.value, resolved_at, vuln_id),
            )
            updated = cursor.rowcount > 0

        if updated:
            logger.info(f"Updated vulnerability {vuln_id} status to {new_status.value}")
        return updated

    def get_by_severity(self, severity: VulnSeverity) -> list[Vulnerability]:
        """Get all vulnerabilities of specified severity."""
        return self.list_vulnerabilities(severity=severity, limit=1000)

    def get_open_count(self) -> int:
        """Count open vulnerabilities (OPEN or IN_PROGRESS)."""
        with self._get_connection() as conn:
            result = conn.execute(
                """
                SELECT COUNT(*) FROM vulnerabilities
                WHERE status IN ('open', 'in_progress')
                """
            ).fetchone()
            return result[0]

    def get_statistics(self) -> dict:
        """
        Get vulnerability statistics.

        Returns:
            Dictionary with counts by severity and status
        """
        with self._get_connection() as conn:
            # Count by severity
            severity_counts = {}
            rows = conn.execute(
                "SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity"
            ).fetchall()
            for row in rows:
                severity_counts[row["severity"]] = row["count"]

            # Count by status
            status_counts = {}
            rows = conn.execute(
                "SELECT status, COUNT(*) as count FROM vulnerabilities GROUP BY status"
            ).fetchall()
            for row in rows:
                status_counts[row["status"]] = row["count"]

            # Total count
            total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

            # Open high/critical count
            high_critical_open = conn.execute(
                """
                SELECT COUNT(*) FROM vulnerabilities
                WHERE severity IN ('high', 'critical')
                AND status IN ('open', 'in_progress')
                """
            ).fetchone()[0]

        return {
            "total": total,
            "open": self.get_open_count(),
            "high_critical_open": high_critical_open,
            "by_severity": severity_counts,
            "by_status": status_counts,
        }

    def delete_vulnerability(self, vuln_id: str) -> bool:
        """Delete vulnerability (hard delete)."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
            deleted = cursor.rowcount > 0

        if deleted:
            logger.info(f"Deleted vulnerability: {vuln_id}")
        return deleted

    # --- Helpers ---

    def _row_to_vuln(self, row: sqlite3.Row) -> Vulnerability:
        """Convert database row to Vulnerability object."""
        data = dict(row)
        data["metadata"] = json.loads(data.get("metadata") or "{}")
        return Vulnerability.from_dict(data)


# Singleton instance
_vuln_repository: VulnRepository | None = None


def get_vuln_repository() -> VulnRepository:
    """Get singleton vulnerability repository."""
    global _vuln_repository
    if _vuln_repository is None:
        _vuln_repository = VulnRepository()
    return _vuln_repository


__all__ = ["VulnRepository", "get_vuln_repository"]
