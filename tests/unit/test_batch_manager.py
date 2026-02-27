"""
test_batch_manager.py - Tests for BatchManager

Author: Homero Thompson del Lago del Terror
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.signer.batch_manager import (
    BatchManager,
    BatchProgress,
    BatchResult,
    create_batch_manager,
)
from pdfsigner.core.signer.pdf_signer import SignatureAppearance, SigningResult


class TestBatchProgress:
    """Tests for BatchProgress dataclass."""

    def test_pending_calculation(self):
        """Test pending files calculation."""
        progress = BatchProgress(
            total=10,
            completed=3,
            failed=2,
            current_file="test.pdf",
        )

        assert progress.pending == 5

    def test_percentage_calculation(self):
        """Test percentage calculation."""
        progress = BatchProgress(
            total=10,
            completed=6,
            failed=2,
            current_file="test.pdf",
        )

        assert progress.percentage == 80.0

    def test_percentage_empty_batch(self):
        """Test percentage with empty batch."""
        progress = BatchProgress(
            total=0,
            completed=0,
            failed=0,
            current_file=None,
        )

        assert progress.percentage == 100.0

    def test_current_file(self):
        """Test current file tracking."""
        progress = BatchProgress(
            total=5,
            completed=2,
            failed=0,
            current_file="document.pdf",
        )

        assert progress.current_file == "document.pdf"


class TestBatchResult:
    """Tests for BatchResult dataclass."""

    def test_all_successful(self):
        """Test all_successful property."""
        result = BatchResult(
            total=5,
            successful=5,
            failed=0,
        )

        assert result.all_successful is True

    def test_not_all_successful(self):
        """Test all_successful when there are failures."""
        result = BatchResult(
            total=5,
            successful=3,
            failed=2,
        )

        assert result.all_successful is False

    def test_duration_seconds(self):
        """Test duration calculation."""
        start = datetime(2024, 1, 1, 10, 0, 0)
        end = datetime(2024, 1, 1, 10, 0, 30)

        result = BatchResult(
            total=5,
            successful=5,
            failed=0,
            started_at=start,
            finished_at=end,
        )

        assert result.duration_seconds == 30.0

    def test_duration_seconds_not_finished(self):
        """Test duration when not finished."""
        result = BatchResult(
            total=5,
            successful=0,
            failed=0,
            started_at=datetime.now(),
            finished_at=None,
        )

        assert result.duration_seconds is None

    def test_get_failed_files(self, temp_dir: Path):
        """Test getting failed files list."""
        results = [
            SigningResult(
                success=True, input_path=temp_dir / "a.pdf", output_path=temp_dir / "a_signed.pdf"
            ),
            SigningResult(
                success=False, input_path=temp_dir / "b.pdf", output_path=None, error="Failed"
            ),
            SigningResult(
                success=False, input_path=temp_dir / "c.pdf", output_path=None, error="Error"
            ),
        ]

        result = BatchResult(
            total=3,
            successful=1,
            failed=2,
            results=results,
        )

        failed = result.get_failed_files()

        assert len(failed) == 2
        assert failed[0][0] == temp_dir / "b.pdf"
        assert failed[0][1] == "Failed"
        assert failed[1][0] == temp_dir / "c.pdf"

    def test_get_successful_files(self, temp_dir: Path):
        """Test getting successful files list."""
        results = [
            SigningResult(
                success=True, input_path=temp_dir / "a.pdf", output_path=temp_dir / "a_signed.pdf"
            ),
            SigningResult(
                success=True, input_path=temp_dir / "b.pdf", output_path=temp_dir / "b_signed.pdf"
            ),
            SigningResult(
                success=False, input_path=temp_dir / "c.pdf", output_path=None, error="Error"
            ),
        ]

        result = BatchResult(
            total=3,
            successful=2,
            failed=1,
            results=results,
        )

        successful = result.get_successful_files()

        assert len(successful) == 2
        assert temp_dir / "a_signed.pdf" in successful
        assert temp_dir / "b_signed.pdf" in successful


class TestBatchManager:
    """Tests for BatchManager class."""

    @pytest.fixture
    def mock_nss_handler(self):
        """Create mock NSS handler."""
        return MagicMock()

    @pytest.fixture
    def mock_lta_handler(self):
        """Create mock LTA handler."""
        return MagicMock()

    def test_initialization(self, mock_nss_handler):
        """Test BatchManager initialization."""
        manager = BatchManager(mock_nss_handler)

        assert manager.nss_handler == mock_nss_handler
        assert manager.lta_handler is None
        assert not manager._cancelled.is_set()
        assert manager._signer is None

    def test_initialization_with_lta(self, mock_nss_handler, mock_lta_handler):
        """Test BatchManager with LTA handler."""
        manager = BatchManager(mock_nss_handler, mock_lta_handler)

        assert manager.lta_handler == mock_lta_handler

    def test_cancel(self, mock_nss_handler):
        """Test cancellation request."""
        manager = BatchManager(mock_nss_handler)

        manager.cancel()

        assert manager._cancelled.is_set()

    def test_reset(self, mock_nss_handler):
        """Test reset after cancellation."""
        manager = BatchManager(mock_nss_handler)
        manager._cancelled.set()

        manager.reset()

        assert not manager._cancelled.is_set()

    def test_sign_batch_empty_list(self, mock_nss_handler):
        """Test signing empty batch."""
        manager = BatchManager(mock_nss_handler)

        result = manager.sign_batch([])

        assert result.total == 0
        assert result.successful == 0
        assert result.failed == 0
        assert result.finished_at is not None

    def test_sign_batch_progress_callback(self, mock_nss_handler, temp_dir: Path):
        """Test progress callback is called."""
        manager = BatchManager(mock_nss_handler)

        # Create test PDFs
        pdf_files = []
        for i in range(3):
            pdf = temp_dir / f"test_{i}.pdf"
            pdf.write_bytes(b"%PDF-1.4 test content")
            pdf_files.append(pdf)

        progress_calls = []

        def progress_callback(progress: BatchProgress):
            progress_calls.append(progress)

        # Mock the signer
        with patch.object(manager, "_get_signer") as mock_get_signer:
            mock_signer = MagicMock()
            mock_signer.sign_pdf.return_value = SigningResult(
                success=True,
                input_path=pdf_files[0],
                output_path=temp_dir / "output.pdf",
            )
            mock_get_signer.return_value = mock_signer

            manager.sign_batch(pdf_files, progress_callback=progress_callback)

        # Should have progress calls
        assert len(progress_calls) > 0

    def test_sign_batch_respects_cancellation(self, mock_nss_handler, temp_dir: Path):
        """Test batch respects cancellation."""
        manager = BatchManager(mock_nss_handler)

        # Create test PDFs
        pdf_files = []
        for i in range(5):
            pdf = temp_dir / f"test_{i}.pdf"
            pdf.write_bytes(b"%PDF-1.4 test content")
            pdf_files.append(pdf)

        # Mock signer to trigger cancellation after first file
        call_count = 0

        def mock_sign(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                manager.cancel()
            return SigningResult(
                success=True,
                input_path=pdf_files[0],
                output_path=temp_dir / "output.pdf",
            )

        with patch.object(manager, "_get_signer") as mock_get_signer:
            mock_signer = MagicMock()
            mock_signer.sign_pdf.side_effect = mock_sign
            mock_get_signer.return_value = mock_signer

            result = manager.sign_batch(pdf_files)

        # Should not process all files
        assert result.successful + result.failed < result.total

    def test_sign_batch_with_appearance(self, mock_nss_handler, temp_dir: Path):
        """Test batch signing with appearance settings."""
        manager = BatchManager(mock_nss_handler)

        pdf = temp_dir / "test.pdf"
        pdf.write_bytes(b"%PDF-1.4 test content")

        appearance = SignatureAppearance(visible=True)

        with patch.object(manager, "_get_signer") as mock_get_signer:
            mock_signer = MagicMock()
            mock_signer.sign_pdf.return_value = SigningResult(
                success=True,
                input_path=pdf,
                output_path=temp_dir / "output.pdf",
            )
            mock_get_signer.return_value = mock_signer

            manager.sign_batch([pdf], appearance=appearance)

            # Verify appearance was passed
            mock_signer.sign_pdf.assert_called_once()
            call_kwargs = mock_signer.sign_pdf.call_args.kwargs
            assert call_kwargs["appearance"] == appearance

    def test_sign_batch_handles_failures(self, mock_nss_handler, temp_dir: Path):
        """Test batch handles individual file failures."""
        manager = BatchManager(mock_nss_handler)

        pdf_files = []
        for i in range(3):
            pdf = temp_dir / f"test_{i}.pdf"
            pdf.write_bytes(b"%PDF-1.4 test content")
            pdf_files.append(pdf)

        # Mock signer to fail on second file
        call_count = 0

        def mock_sign(input_path, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                return SigningResult(
                    success=False,
                    input_path=input_path,
                    output_path=None,
                    error="Test error",
                )
            return SigningResult(
                success=True,
                input_path=input_path,
                output_path=temp_dir / "output.pdf",
            )

        with patch.object(manager, "_get_signer") as mock_get_signer:
            mock_signer = MagicMock()
            mock_signer.sign_pdf.side_effect = mock_sign
            mock_get_signer.return_value = mock_signer

            result = manager.sign_batch(pdf_files)

        assert result.total == 3
        assert result.successful == 2
        assert result.failed == 1


class TestCreateBatchManager:
    """Tests for create_batch_manager factory function."""

    def test_create_without_lta(self):
        """Test factory without LTA handler."""
        nss = MagicMock()

        manager = create_batch_manager(nss)

        assert isinstance(manager, BatchManager)
        assert manager.nss_handler == nss
        assert manager.lta_handler is None

    def test_create_with_lta(self):
        """Test factory with LTA handler."""
        nss = MagicMock()
        lta = MagicMock()

        manager = create_batch_manager(nss, lta)

        assert isinstance(manager, BatchManager)
        assert manager.nss_handler == nss
        assert manager.lta_handler == lta
