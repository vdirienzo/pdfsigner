"""Archive Timestamp scheduler for long-term PDF monitoring.

Manages SQLite database of PDFs requiring periodic archive timestamps
for long-term validation (PAdES-LTA compliance).
"""

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampManager


@dataclass
class RegisteredPDF:
    """Information about a registered PDF for monitoring."""

    pdf_path: Path
    registered_at: datetime
    last_checked_at: datetime | None
    last_timestamp_at: datetime | None
    check_interval_days: int
    hash_sha256: str | None = None


@dataclass
class PendingPDF:
    """PDF that needs a new archive timestamp."""

    pdf_path: Path
    reason: str  # "no_timestamp", "expired", "weak_algorithm", "not_found"


class ArchiveTSScheduler:
    """
    Scheduler for managing periodic archive timestamps on PDFs.

    Uses SQLite to track registered PDFs and their timestamp status.
    Integrates with ArchiveTimestampManager for checking and adding timestamps.

    Thread-safe for concurrent access.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize scheduler with SQLite database.

        Args:
            db_path: Path to SQLite database (default: ~/.config/pdfsigner/archive_ts.db)
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "archive_ts.db"

        self.db_path = Path(db_path)
        self._lock = threading.Lock()

        # Initialize database
        self._init_db()
        logger.debug(f"ArchiveTSScheduler initialized: {self.db_path}")

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

    def _compute_hash(self, pdf_path: Path) -> str | None:
        """
        Compute SHA256 hash of PDF file.

        Args:
            pdf_path: Path to PDF

        Returns:
            Hex string of SHA256 hash, or None if file not found
        """
        try:
            if not pdf_path.exists():
                return None

            hasher = hashlib.sha256()
            with open(pdf_path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)

            return hasher.hexdigest()

        except Exception as e:
            logger.warning(f"Failed to compute hash for {pdf_path}: {e}")
            return None

    def register_pdf(
        self,
        pdf_path: Path,
        check_interval_days: int = 365 * 5,
    ) -> None:
        """
        Register a PDF for periodic archive timestamp monitoring.

        Args:
            pdf_path: Path to PDF file
            check_interval_days: Days between timestamp checks (default: 5 years)

        Raises:
            ValueError: If check_interval_days is invalid
        """
        if check_interval_days < 1:
            raise ValueError(f"Invalid check_interval_days: {check_interval_days}")

        pdf_path = pdf_path.resolve()
        registered_at = datetime.now()
        hash_sha256 = self._compute_hash(pdf_path)

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
                logger.info(
                    f"Registered PDF for archive TS monitoring: {pdf_path.name} "
                    f"(check every {check_interval_days} days)"
                )

            except sqlite3.IntegrityError as e:
                logger.warning(f"PDF already registered: {pdf_path}")
                raise ValueError(f"PDF already registered: {pdf_path}") from e

            finally:
                conn.close()

    def unregister_pdf(self, pdf_path: Path) -> bool:
        """
        Remove PDF from monitoring.

        Args:
            pdf_path: Path to PDF file

        Returns:
            True if PDF was unregistered, False if not found
        """
        pdf_path = pdf_path.resolve()

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "DELETE FROM registered_pdfs WHERE pdf_path = ?",
                    (str(pdf_path),),
                )
                conn.commit()

                if cursor.rowcount > 0:
                    logger.info(f"Unregistered PDF from monitoring: {pdf_path.name}")
                    return True
                else:
                    logger.debug(f"PDF not found in registry: {pdf_path.name}")
                    return False

            finally:
                conn.close()

    def get_pending_pdfs(
        self,
        tsa_urls: list[str] | None = None,
    ) -> list[PendingPDF]:
        """
        Get list of PDFs that need new archive timestamps.

        Checks each registered PDF using ArchiveTimestampManager.needs_archive_timestamp().
        Updates last_checked_at timestamp for all checked PDFs.

        Args:
            tsa_urls: TSA URLs for ArchiveTimestampManager (required for checking)

        Returns:
            List of PendingPDF objects needing timestamps
        """
        pending: list[PendingPDF] = []
        registered = self.list_registered()

        # Need TSA URLs to create manager for checking
        if not tsa_urls:
            logger.warning("No TSA URLs provided, cannot check timestamp status")
            return pending

        manager = ArchiveTimestampManager(tsa_urls=tsa_urls)
        now = datetime.now()

        for reg_pdf in registered:
            pdf_path = reg_pdf.pdf_path

            # Check if file exists
            if not pdf_path.exists():
                logger.warning(f"Registered PDF not found: {pdf_path}")
                pending.append(PendingPDF(pdf_path=pdf_path, reason="not_found"))
                self._update_last_checked(pdf_path, now)
                continue

            # Check if hash changed (file modified)
            current_hash = self._compute_hash(pdf_path)
            if current_hash and reg_pdf.hash_sha256 and current_hash != reg_pdf.hash_sha256:
                logger.info(f"PDF modified since registration: {pdf_path.name}")
                self._update_hash(pdf_path, current_hash)

            # Check if timestamp needed
            try:
                if manager.needs_archive_timestamp(
                    pdf_path,
                    algorithm_threshold_years=reg_pdf.check_interval_days // 365,
                ):
                    # Determine reason
                    timestamps = manager.get_archive_timestamps(pdf_path)

                    if not timestamps:
                        reason = "no_timestamp"
                    elif any(
                        ts.hash_algorithm.lower() in {"sha1", "md5", "md2"} for ts in timestamps
                    ):
                        reason = "weak_algorithm"
                    else:
                        reason = "expired"

                    logger.debug(f"PDF needs archive timestamp: {pdf_path.name} ({reason})")
                    pending.append(PendingPDF(pdf_path=pdf_path, reason=reason))

            except Exception as e:
                logger.error(f"Error checking {pdf_path.name}: {e}")
                # Don't add to pending if we can't determine status

            # Update last checked timestamp
            self._update_last_checked(pdf_path, now)

        logger.info(f"Found {len(pending)} PDFs needing archive timestamps")
        return pending

    def check_and_update(
        self,
        pdf_path: Path,
        tsa_urls: list[str],
    ) -> bool:
        """
        Check if PDF needs timestamp and add it if needed.

        Updates last_checked_at and last_timestamp_at in database.

        Args:
            pdf_path: Path to PDF
            tsa_urls: TSA URLs for timestamping

        Returns:
            True if timestamp was added, False otherwise

        Raises:
            FileNotFoundError: If PDF doesn't exist
            Exception: If timestamping fails
        """
        pdf_path = pdf_path.resolve()

        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")

        if not tsa_urls:
            raise ValueError("No TSA URLs provided")

        manager = ArchiveTimestampManager(tsa_urls=tsa_urls)
        now = datetime.now()

        # Check if timestamp needed
        needs_ts = manager.needs_archive_timestamp(pdf_path)
        self._update_last_checked(pdf_path, now)

        if not needs_ts:
            logger.debug(f"PDF does not need archive timestamp: {pdf_path.name}")
            return False

        # Add timestamp (overwrites PDF in place)
        try:
            logger.info(f"Adding archive timestamp to {pdf_path.name}")
            manager.add_archive_timestamp(pdf_path, output_path=pdf_path)

            # Update database
            self._update_last_timestamp(pdf_path, now)

            # Update hash
            new_hash = self._compute_hash(pdf_path)
            if new_hash:
                self._update_hash(pdf_path, new_hash)

            logger.info(f"Successfully added archive timestamp to {pdf_path.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to add archive timestamp to {pdf_path.name}: {e}")
            raise

    def list_registered(self) -> list[RegisteredPDF]:
        """
        List all registered PDFs.

        Returns:
            List of RegisteredPDF objects sorted by registration date
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

    def _update_last_checked(self, pdf_path: Path, timestamp: datetime) -> None:
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

    def _update_last_timestamp(self, pdf_path: Path, timestamp: datetime) -> None:
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

    def _update_hash(self, pdf_path: Path, hash_sha256: str) -> None:
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
