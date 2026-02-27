"""SQLite storage for archive timestamp scheduling.

Encapsulates all database operations for tracking registered PDFs
and their timestamp status.
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.signer.archive_ts_types import RegisteredPDF


class ArchiveTSStorage:
    """SQLite-backed storage for archive timestamp scheduling.

    Thread-safe for concurrent access via an internal lock.
    """

    def __init__(self, db_path: Path):
        """Initialize storage with SQLite database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Create database schema if not exists."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS registered_pdfs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pdf_path TEXT UNIQUE NOT NULL,
                        registered_at TEXT NOT NULL,
                        last_checked_at TEXT,
                        last_timestamp_at TEXT,
                        check_interval_days INTEGER DEFAULT 1825,
                        hash_sha256 TEXT
                    )
                    """
                )
                conn.commit()
                logger.debug("Archive TS database schema initialized")
            finally:
                conn.close()

    def insert_pdf(
        self,
        pdf_path: Path,
        registered_at: datetime,
        check_interval_days: int,
        hash_sha256: str | None,
    ) -> None:
        """Insert or replace a PDF registration.

        Args:
            pdf_path: Resolved path to PDF file
            registered_at: Registration timestamp
            check_interval_days: Days between timestamp checks
            hash_sha256: SHA256 hash of PDF file

        Raises:
            ValueError: If PDF already registered (IntegrityError)
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO registered_pdfs
                    (pdf_path, registered_at, check_interval_days, hash_sha256)
                    VALUES (?, ?, ?, ?)
                    """,
                    (str(pdf_path), registered_at.isoformat(), check_interval_days, hash_sha256),
                )
                conn.commit()
            except sqlite3.IntegrityError as e:
                raise ValueError(f"PDF already registered: {pdf_path}") from e
            finally:
                conn.close()

    def delete_pdf(self, pdf_path: Path) -> bool:
        """Remove a PDF from the registry.

        Args:
            pdf_path: Resolved path to PDF file

        Returns:
            True if PDF was removed, False if not found
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "DELETE FROM registered_pdfs WHERE pdf_path = ?",
                    (str(pdf_path),),
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def list_all(self) -> list[RegisteredPDF]:
        """List all registered PDFs.

        Returns:
            List of RegisteredPDF objects sorted by registration date (newest first)
        """
        pdfs: list[RegisteredPDF] = []

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    """
                    SELECT pdf_path, registered_at, last_checked_at,
                           last_timestamp_at, check_interval_days, hash_sha256
                    FROM registered_pdfs
                    ORDER BY registered_at DESC
                    """
                )

                for row in cursor.fetchall():
                    pdfs.append(
                        RegisteredPDF(
                            pdf_path=Path(row[0]),
                            registered_at=datetime.fromisoformat(row[1]),
                            last_checked_at=datetime.fromisoformat(row[2]) if row[2] else None,
                            last_timestamp_at=datetime.fromisoformat(row[3]) if row[3] else None,
                            check_interval_days=row[4],
                            hash_sha256=row[5],
                        )
                    )
            finally:
                conn.close()

        return pdfs

    def update_last_checked(self, pdf_path: Path, timestamp: datetime) -> None:
        """Update last_checked_at timestamp for PDF."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "UPDATE registered_pdfs SET last_checked_at = ? WHERE pdf_path = ?",
                    (timestamp.isoformat(), str(pdf_path)),
                )
                conn.commit()
            finally:
                conn.close()

    def update_last_timestamp(self, pdf_path: Path, timestamp: datetime) -> None:
        """Update last_timestamp_at timestamp for PDF."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "UPDATE registered_pdfs SET last_timestamp_at = ? WHERE pdf_path = ?",
                    (timestamp.isoformat(), str(pdf_path)),
                )
                conn.commit()
            finally:
                conn.close()

    def update_hash(self, pdf_path: Path, hash_sha256: str) -> None:
        """Update hash for PDF."""
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "UPDATE registered_pdfs SET hash_sha256 = ? WHERE pdf_path = ?",
                    (hash_sha256, str(pdf_path)),
                )
                conn.commit()
            finally:
                conn.close()


__all__ = [
    "ArchiveTSStorage",
]
