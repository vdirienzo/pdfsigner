"""Tests for ArchiveTSScheduler."""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from pdfsigner.core.signer.archive_ts_manager import (
    ArchiveTimestampInfo,
    ArchiveTimestampManager,
)
from pdfsigner.core.signer.archive_ts_scheduler import (
    ArchiveTSScheduler,
    PendingPDF,
    RegisteredPDF,
)


class TestRegisteredPDF:
    """Tests for RegisteredPDF dataclass."""

    def test_creation_with_all_fields(self):
        """Test dataclass creation with all fields."""
        now = datetime.now()
        pdf = RegisteredPDF(
            pdf_path=Path("/test/file.pdf"),
            registered_at=now,
            last_checked_at=now,
            last_timestamp_at=now,
            check_interval_days=1825,
            hash_sha256="abc123",
        )

        assert pdf.pdf_path == Path("/test/file.pdf")
        assert pdf.registered_at == now
        assert pdf.last_checked_at == now
        assert pdf.last_timestamp_at == now
        assert pdf.check_interval_days == 1825
        assert pdf.hash_sha256 == "abc123"

    def test_creation_with_none_optional_fields(self):
        """Test dataclass creation with None optional fields."""
        pdf = RegisteredPDF(
            pdf_path=Path("/test/file.pdf"),
            registered_at=datetime.now(),
            last_checked_at=None,
            last_timestamp_at=None,
            check_interval_days=365,
        )

        assert pdf.last_checked_at is None
        assert pdf.last_timestamp_at is None
        assert pdf.hash_sha256 is None


class TestPendingPDF:
    """Tests for PendingPDF dataclass."""

    def test_creation_with_reason_no_timestamp(self):
        """Test dataclass creation with no_timestamp reason."""
        pdf = PendingPDF(pdf_path=Path("/test/file.pdf"), reason="no_timestamp")

        assert pdf.pdf_path == Path("/test/file.pdf")
        assert pdf.reason == "no_timestamp"

    def test_creation_with_different_reasons(self):
        """Test dataclass creation with different reasons."""
        reasons = ["no_timestamp", "expired", "weak_algorithm", "not_found"]

        for reason in reasons:
            pdf = PendingPDF(pdf_path=Path("/test/file.pdf"), reason=reason)
            assert pdf.reason == reason


class TestArchiveTSScheduler:
    """Tests for ArchiveTSScheduler class."""

    @pytest.fixture
    def db_path(self, tmp_path):
        """Create temporary database path."""
        return tmp_path / "test_archive_ts.db"

    @pytest.fixture
    def scheduler(self, db_path):
        """Create scheduler with test database."""
        return ArchiveTSScheduler(db_path=db_path)

    @pytest.fixture
    def mock_pdf(self, tmp_path):
        """Create mock PDF file."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 test content")
        return pdf_path

    def test_init_creates_database(self, scheduler, db_path):
        """Test initialization creates database file."""
        assert db_path.exists()

    def test_init_creates_schema(self, scheduler, db_path):
        """Test initialization creates database schema."""
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='registered_pdfs'"
            )
            assert cursor.fetchone() is not None
        finally:
            conn.close()

    def test_init_with_default_path(self, tmp_path):
        """Test initialization with default database path."""
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            scheduler = ArchiveTSScheduler()

            expected_path = tmp_path / ".config" / "pdfsigner" / "archive_ts.db"
            assert scheduler.db_path == expected_path
            assert expected_path.exists()

    def test_register_pdf_success(self, scheduler, mock_pdf):
        """Test registering a PDF successfully."""
        scheduler.register_pdf(mock_pdf, check_interval_days=365)

        # Verify in database
        pdfs = scheduler.list_registered()
        assert len(pdfs) == 1
        assert pdfs[0].pdf_path == mock_pdf.resolve()
        assert pdfs[0].check_interval_days == 365

    def test_register_pdf_custom_interval(self, scheduler, mock_pdf):
        """Test registering PDF with custom check interval."""
        scheduler.register_pdf(mock_pdf, check_interval_days=730)

        pdfs = scheduler.list_registered()
        assert pdfs[0].check_interval_days == 730

    def test_register_pdf_computes_hash(self, scheduler, mock_pdf):
        """Test register_pdf computes SHA256 hash."""
        scheduler.register_pdf(mock_pdf)

        pdfs = scheduler.list_registered()
        assert pdfs[0].hash_sha256 is not None
        assert len(pdfs[0].hash_sha256) == 64  # SHA256 hex length

    def test_register_pdf_invalid_interval_raises_error(self, scheduler, mock_pdf):
        """Test register_pdf raises ValueError for invalid interval."""
        with pytest.raises(ValueError, match="Invalid check_interval_days"):
            scheduler.register_pdf(mock_pdf, check_interval_days=0)

        with pytest.raises(ValueError, match="Invalid check_interval_days"):
            scheduler.register_pdf(mock_pdf, check_interval_days=-10)

    def test_register_pdf_nonexistent_file(self, scheduler, tmp_path):
        """Test registering nonexistent PDF stores path but no hash."""
        nonexistent = tmp_path / "nonexistent.pdf"
        scheduler.register_pdf(nonexistent)

        pdfs = scheduler.list_registered()
        assert len(pdfs) == 1
        assert pdfs[0].pdf_path == nonexistent.resolve()
        assert pdfs[0].hash_sha256 is None

    def test_register_pdf_resolves_path(self, scheduler, mock_pdf):
        """Test register_pdf resolves relative paths."""
        # Create relative path
        relative_path = Path(mock_pdf.name)

        with patch.object(Path, "resolve", return_value=mock_pdf.resolve()):
            scheduler.register_pdf(relative_path)

        pdfs = scheduler.list_registered()
        assert pdfs[0].pdf_path == mock_pdf.resolve()

    def test_unregister_pdf_success(self, scheduler, mock_pdf):
        """Test unregistering a PDF successfully."""
        scheduler.register_pdf(mock_pdf)
        result = scheduler.unregister_pdf(mock_pdf)

        assert result is True
        assert len(scheduler.list_registered()) == 0

    def test_unregister_pdf_not_found(self, scheduler, tmp_path):
        """Test unregistering non-registered PDF returns False."""
        nonexistent = tmp_path / "nonexistent.pdf"
        result = scheduler.unregister_pdf(nonexistent)

        assert result is False

    def test_list_registered_empty(self, scheduler):
        """Test list_registered returns empty list initially."""
        pdfs = scheduler.list_registered()
        assert pdfs == []

    def test_list_registered_multiple_pdfs(self, scheduler, tmp_path):
        """Test list_registered returns all registered PDFs."""
        pdf1 = tmp_path / "test1.pdf"
        pdf2 = tmp_path / "test2.pdf"
        pdf1.write_bytes(b"%PDF-1.4 content1")
        pdf2.write_bytes(b"%PDF-1.4 content2")

        scheduler.register_pdf(pdf1)
        scheduler.register_pdf(pdf2)

        pdfs = scheduler.list_registered()
        assert len(pdfs) == 2
        paths = {pdf.pdf_path for pdf in pdfs}
        assert pdf1.resolve() in paths
        assert pdf2.resolve() in paths

    def test_list_registered_sorted_by_date(self, scheduler, tmp_path):
        """Test list_registered returns PDFs sorted by registration date."""
        pdf1 = tmp_path / "test1.pdf"
        pdf2 = tmp_path / "test2.pdf"
        pdf1.write_bytes(b"%PDF-1.4 content1")
        pdf2.write_bytes(b"%PDF-1.4 content2")

        # Register with small delay to ensure different timestamps
        scheduler.register_pdf(pdf1)
        scheduler.register_pdf(pdf2)

        pdfs = scheduler.list_registered()
        # Should be in descending order (newest first)
        assert pdfs[0].registered_at >= pdfs[1].registered_at

    def test_get_pending_pdfs_no_tsa_urls(self, scheduler, mock_pdf):
        """Test get_pending_pdfs returns empty list without TSA URLs."""
        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=None)

        assert pending == []

    def test_get_pending_pdfs_empty_tsa_urls(self, scheduler, mock_pdf):
        """Test get_pending_pdfs returns empty list with empty TSA URLs."""
        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=[])

        assert pending == []

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_file_not_found(self, mock_manager_class, scheduler, tmp_path):
        """Test get_pending_pdfs handles missing files."""
        nonexistent = tmp_path / "nonexistent.pdf"
        scheduler.register_pdf(nonexistent)

        pending = scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        assert len(pending) == 1
        assert pending[0].pdf_path == nonexistent.resolve()
        assert pending[0].reason == "not_found"

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_no_timestamp(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs detects PDFs without timestamps."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.get_archive_timestamps.return_value = []
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        assert len(pending) == 1
        assert pending[0].pdf_path == mock_pdf.resolve()
        assert pending[0].reason == "no_timestamp"

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_weak_algorithm(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs detects weak hash algorithms."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.get_archive_timestamps.return_value = [
            ArchiveTimestampInfo(
                timestamp=datetime.now(),
                tsa_url="https://tsa.example.com",
                hash_algorithm="sha1",  # Weak
                covers_dss=True,
            )
        ]
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        assert len(pending) == 1
        assert pending[0].reason == "weak_algorithm"

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_expired(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs detects expired timestamps."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.get_archive_timestamps.return_value = [
            ArchiveTimestampInfo(
                timestamp=datetime.now() - timedelta(days=11 * 365),
                tsa_url="https://tsa.example.com",
                hash_algorithm="sha256",
                covers_dss=True,
            )
        ]
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        assert len(pending) == 1
        assert pending[0].reason == "expired"

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_up_to_date(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs returns empty for up-to-date PDFs."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = False
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        assert pending == []

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_updates_last_checked(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs updates last_checked_at timestamp."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = False
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)

        # Initially no last_checked_at
        pdfs = scheduler.list_registered()
        assert pdfs[0].last_checked_at is None

        # After checking
        scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        pdfs = scheduler.list_registered()
        assert pdfs[0].last_checked_at is not None

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_handles_check_errors(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs handles errors gracefully."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.side_effect = RuntimeError("Check failed")
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        pending = scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        # Should not add to pending on error
        assert pending == []

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_get_pending_pdfs_detects_hash_change(self, mock_manager_class, scheduler, mock_pdf):
        """Test get_pending_pdfs detects file modifications via hash."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = False
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)

        # Modify file
        mock_pdf.write_bytes(b"%PDF-1.4 modified content")

        scheduler.get_pending_pdfs(tsa_urls=["https://tsa.example.com"])

        # Hash should be updated
        pdfs = scheduler.list_registered()
        new_hash = scheduler._compute_hash(mock_pdf)
        assert pdfs[0].hash_sha256 == new_hash

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_check_and_update_file_not_found(self, mock_manager_class, scheduler, tmp_path):
        """Test check_and_update raises FileNotFoundError for missing PDF."""
        nonexistent = tmp_path / "nonexistent.pdf"

        with pytest.raises(FileNotFoundError, match="PDF not found"):
            scheduler.check_and_update(nonexistent, tsa_urls=["https://tsa.example.com"])

    def test_check_and_update_no_tsa_urls(self, scheduler, mock_pdf):
        """Test check_and_update raises ValueError without TSA URLs."""
        with pytest.raises(ValueError, match="No TSA URLs provided"):
            scheduler.check_and_update(mock_pdf, tsa_urls=[])

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_check_and_update_not_needed(self, mock_manager_class, scheduler, mock_pdf):
        """Test check_and_update returns False when timestamp not needed."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = False
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        result = scheduler.check_and_update(mock_pdf, tsa_urls=["https://tsa.example.com"])

        assert result is False
        mock_manager.add_archive_timestamp.assert_not_called()

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_check_and_update_success(self, mock_manager_class, scheduler, mock_pdf):
        """Test check_and_update successfully adds timestamp."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.add_archive_timestamp.return_value = mock_pdf
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        result = scheduler.check_and_update(mock_pdf, tsa_urls=["https://tsa.example.com"])

        assert result is True
        mock_manager.add_archive_timestamp.assert_called_once_with(mock_pdf, output_path=mock_pdf)

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_check_and_update_updates_timestamp(self, mock_manager_class, scheduler, mock_pdf):
        """Test check_and_update updates last_timestamp_at."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.add_archive_timestamp.return_value = mock_pdf
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)

        # Initially no last_timestamp_at
        pdfs = scheduler.list_registered()
        assert pdfs[0].last_timestamp_at is None

        scheduler.check_and_update(mock_pdf, tsa_urls=["https://tsa.example.com"])

        # After adding timestamp
        pdfs = scheduler.list_registered()
        assert pdfs[0].last_timestamp_at is not None

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_check_and_update_updates_hash(self, mock_manager_class, scheduler, mock_pdf):
        """Test check_and_update updates hash after timestamping."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.add_archive_timestamp.return_value = mock_pdf
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)
        old_hash = scheduler.list_registered()[0].hash_sha256

        # Simulate file modification by timestamp
        mock_pdf.write_bytes(b"%PDF-1.4 with timestamp")

        scheduler.check_and_update(mock_pdf, tsa_urls=["https://tsa.example.com"])

        pdfs = scheduler.list_registered()
        assert pdfs[0].hash_sha256 != old_hash

    @patch("pdfsigner.core.signer.archive_ts_scheduler.ArchiveTimestampManager")
    def test_check_and_update_propagates_errors(self, mock_manager_class, scheduler, mock_pdf):
        """Test check_and_update propagates timestamp errors."""
        mock_manager = Mock(spec=ArchiveTimestampManager)
        mock_manager.needs_archive_timestamp.return_value = True
        mock_manager.add_archive_timestamp.side_effect = Exception("TSA failed")
        mock_manager_class.return_value = mock_manager

        scheduler.register_pdf(mock_pdf)

        with pytest.raises(Exception, match="TSA failed"):
            scheduler.check_and_update(mock_pdf, tsa_urls=["https://tsa.example.com"])

    def test_compute_hash_success(self, scheduler, mock_pdf):
        """Test _compute_hash computes SHA256 correctly."""
        hash1 = scheduler._compute_hash(mock_pdf)
        hash2 = scheduler._compute_hash(mock_pdf)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length

    def test_compute_hash_different_files(self, scheduler, tmp_path):
        """Test _compute_hash produces different hashes for different files."""
        pdf1 = tmp_path / "test1.pdf"
        pdf2 = tmp_path / "test2.pdf"
        pdf1.write_bytes(b"%PDF-1.4 content1")
        pdf2.write_bytes(b"%PDF-1.4 content2")

        hash1 = scheduler._compute_hash(pdf1)
        hash2 = scheduler._compute_hash(pdf2)

        assert hash1 != hash2

    def test_compute_hash_nonexistent_file(self, scheduler, tmp_path):
        """Test _compute_hash returns None for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.pdf"
        result = scheduler._compute_hash(nonexistent)

        assert result is None

    def test_thread_safety_concurrent_registration(self, scheduler, tmp_path):
        """Test scheduler handles concurrent registrations safely."""
        import threading

        pdfs = []
        for i in range(5):
            pdf = tmp_path / f"test{i}.pdf"
            pdf.write_bytes(b"%PDF-1.4 content")
            pdfs.append(pdf)

        def register_pdf(pdf):
            scheduler.register_pdf(pdf)

        threads = [threading.Thread(target=register_pdf, args=(pdf,)) for pdf in pdfs]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        registered = scheduler.list_registered()
        assert len(registered) == 5

    def test_database_persistence(self, db_path, mock_pdf):
        """Test database persists across scheduler instances."""
        # Create first scheduler and register PDF
        scheduler1 = ArchiveTSScheduler(db_path=db_path)
        scheduler1.register_pdf(mock_pdf)

        # Create second scheduler with same database
        scheduler2 = ArchiveTSScheduler(db_path=db_path)
        pdfs = scheduler2.list_registered()

        assert len(pdfs) == 1
        assert pdfs[0].pdf_path == mock_pdf.resolve()
