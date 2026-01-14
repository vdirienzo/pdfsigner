"""
test_mock_batch.py - Tests for MockBatchManager (dry-run mode)

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path

import pytest

from pdfsigner.core.mock.mock_batch import MockBatchManager


class TestMockBatchManager:
    """Tests for MockBatchManager class."""

    @pytest.fixture
    def mock_batch_manager(self):
        """Create MockBatchManager instance."""
        return MockBatchManager()

    def test_initialization(self, mock_batch_manager):
        """Test MockBatchManager initialization."""
        assert mock_batch_manager is not None

    def test_has_sign_batch_method(self, mock_batch_manager):
        """Test MockBatchManager has sign_batch method."""
        assert hasattr(mock_batch_manager, "sign_batch")
        assert callable(mock_batch_manager.sign_batch)

    def test_sign_batch_with_single_file(self, mock_batch_manager, sample_pdf: Path):
        """Test sign_batch with single file."""
        result = mock_batch_manager.sign_batch(
            files=[sample_pdf],
            pin="1234",
            visible=False,
        )

        # Should return a result object
        assert result is not None

    def test_sign_batch_with_visible_stamp(self, mock_batch_manager, sample_pdf: Path):
        """Test sign_batch with visible stamp option."""
        result = mock_batch_manager.sign_batch(
            files=[sample_pdf],
            pin="1234",
            visible=True,
            page="last",
            position="bottom_right",
        )

        # Should complete without error
        assert result is not None

    def test_sign_batch_multiple_files(self, mock_batch_manager, temp_dir: Path):
        """Test sign_batch with multiple files."""
        # Create multiple test PDFs
        pdf_content = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer << /Size 4 /Root 1 0 R >>
startxref
196
%%EOF"""

        input_files = []
        for i in range(3):
            pdf_path = temp_dir / f"test_{i}.pdf"
            pdf_path.write_bytes(pdf_content)
            input_files.append(pdf_path)

        # Sign all files
        result = mock_batch_manager.sign_batch(
            files=input_files,
            pin="1234",
            visible=False,
        )

        # Should process all files
        assert result is not None
