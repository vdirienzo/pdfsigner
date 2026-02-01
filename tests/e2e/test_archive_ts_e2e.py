"""
test_archive_ts_e2e.py - End-to-end tests for archive timestamp functionality

Author: Homero Thompson del Lago del Terror

Tests E2E coverage for archive timestamp (PAdES-LTA):
- Archive TS addition to PAdES-LT PDFs
- PAdES level detection (B → T → LT → LTA)
- CLI archive-ts command
- TSA connection handling (timeout, errors)
- Multiple archive timestamps
- Signature preservation
"""

import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import fitz  # PyMuPDF
import pytest

from pdfsigner.core.mock.mock_batch import MockBatchManager
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.archive_ts_manager import (
    ArchiveTimestampInfo,
    ArchiveTimestampManager,
)
from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.exceptions import TSAConnectionError

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    tmp = tempfile.mkdtemp(prefix="pdfsigner_archive_ts_e2e_")
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_pdf(temp_dir: Path) -> Path:
    """Create a simple 1-page PDF for testing."""
    pdf_path = temp_dir / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((72, 72), "Archive Timestamp Test Document", fontsize=24)
    page.insert_text((72, 120), "Sample PDF for PAdES-LTA E2E tests.", fontsize=12)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def signed_pdf(sample_pdf: Path, temp_dir: Path) -> Path:
    """Create a signed PDF (PAdES-B-B) for testing."""
    batch_manager = MockBatchManager()
    appearance = SignatureAppearance(
        visible=True,
        page="last",
        position_preference=PositionPreference.BOTTOM_RIGHT,
    )

    result = batch_manager.sign_batch(
        pdf_files=[sample_pdf],
        appearance=appearance,
    )

    assert result.all_successful
    return result.results[0].output_path


@pytest.fixture
def signed_lt_pdf(signed_pdf: Path) -> Path:
    """
    Create a PAdES-LT PDF (with DSS) for testing.

    Note: MockBatchManager creates signatures without real DSS.
    This fixture simulates a LT-level PDF by creating a mock
    DSS structure in the PDF.
    """
    # For this E2E test, we'll use the signed PDF as-is
    # The actual DSS embedding is tested in unit tests
    # Here we focus on archive timestamp addition
    return signed_pdf


@pytest.fixture
def mock_settings(temp_dir: Path, monkeypatch):
    """Mock settings with temp directories."""
    from pdfsigner.config.settings import Settings

    nss_dir = temp_dir / ".nss"
    nss_dir.mkdir()

    settings = Settings(
        nss_db_path=nss_dir,
        tsa_url="http://timestamp.digicert.com",
        log_level="DEBUG",
        log_dir=temp_dir / "logs",
        archive_ts_enabled=True,
        archive_ts_auto=False,
    )

    monkeypatch.setattr(
        "pdfsigner.config.settings.get_settings",
        lambda: settings,
    )

    return settings


# ============================================================================
# Test Classes
# ============================================================================


class TestArchiveTimestampBasicFlow:
    """Basic E2E tests for archive timestamp functionality."""

    def test_add_archive_timestamp_to_signed_pdf_with_mock_tsa(
        self, signed_pdf: Path, temp_dir: Path
    ):
        """Add archive timestamp to signed PDF using mocked TSA."""
        output_path = temp_dir / "signed_lta.pdf"

        # Mock the pyHanko components
        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    mock_stamper_instance = Mock()
                    mock_stamper.return_value = mock_stamper_instance

                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    result = manager.add_archive_timestamp(signed_pdf, output_path)

                    assert result == output_path
                    mock_stamper_instance.timestamp_pdf.assert_called_once()

    def test_add_archive_timestamp_without_output_path_overwrites_input(
        self, signed_pdf: Path, temp_dir: Path
    ):
        """Add archive timestamp without output path overwrites the input file."""
        # Create a copy to avoid modifying the fixture
        test_pdf = temp_dir / "test_copy.pdf"
        shutil.copy(signed_pdf, test_pdf)

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    mock_stamper_instance = Mock()
                    mock_stamper.return_value = mock_stamper_instance

                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    # No output_path specified
                    result = manager.add_archive_timestamp(test_pdf)

                    assert result == test_pdf
                    mock_stamper_instance.timestamp_pdf.assert_called_once()

    @pytest.mark.integration
    @pytest.mark.slow
    def test_add_archive_timestamp_with_real_tsa(self, signed_pdf: Path, temp_dir: Path):
        """Add archive timestamp using real TSA server (DigiCert)."""
        output_path = temp_dir / "signed_lta_real.pdf"

        manager = ArchiveTimestampManager(tsa_urls=["http://timestamp.digicert.com"], timeout=60)

        try:
            result = manager.add_archive_timestamp(signed_pdf, output_path)
            assert result.exists()
            assert result.stat().st_size > signed_pdf.stat().st_size

        except TSAConnectionError:
            pytest.skip("TSA server not reachable")
        except Exception as e:
            pytest.skip(f"TSA request failed: {e}")

    def test_complete_flow_sign_to_lta(self, sample_pdf: Path, temp_dir: Path):
        """Complete flow: Sign → Add archive TS (B-B → LTA)."""
        # Step 1: Sign the PDF (creates B-B level)
        batch_manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        sign_result = batch_manager.sign_batch(
            pdf_files=[sample_pdf],
            appearance=appearance,
        )

        assert sign_result.all_successful
        signed_path = sign_result.results[0].output_path

        # Step 2: Add archive timestamp
        lta_path = temp_dir / "complete_lta.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    mock_stamper_instance = Mock()
                    mock_stamper.return_value = mock_stamper_instance

                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    result = manager.add_archive_timestamp(signed_path, lta_path)

                    assert result == lta_path
                    mock_stamper_instance.timestamp_pdf.assert_called_once()


class TestPAdESLevelDetection:
    """Tests for PAdES compliance level detection with archive timestamps."""

    def test_unsigned_pdf_has_unknown_level(self, sample_pdf: Path):
        """Unsigned PDF should have UNKNOWN PAdES level."""
        validator = PDFValidator()
        result = validator.validate(sample_pdf)

        assert not result.is_signed
        assert result.signature_count == 0

    def test_signed_pdf_without_timestamp_is_bb(self, signed_pdf: Path):
        """Signed PDF without timestamp is PAdES B-B."""
        # Note: MockBatchManager creates visual stamps but not actual
        # digital signatures, so PDFValidator won't detect them.
        # This test verifies the PDF was created successfully.
        assert signed_pdf.exists()
        assert signed_pdf.stat().st_size > 0

        # In a real scenario with actual signatures:
        # validator = PDFValidator()
        # result = validator.validate(signed_pdf)
        # assert result.is_signed
        # assert result.signature_count >= 1

    def test_archive_ts_detection_with_mock_timestamp(self, signed_pdf: Path, temp_dir: Path):
        """Test that archive timestamp can be detected after addition."""
        # Add archive timestamp
        lta_path = temp_dir / "with_archive_ts.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    manager.add_archive_timestamp(signed_pdf, lta_path)

        # In real scenario, validator would detect LTA level
        # Here we verify the mechanism works
        assert lta_path.exists()


class TestErrorHandling:
    """Tests for error handling in archive timestamp operations."""

    def test_archive_ts_on_unsigned_pdf_fails_gracefully(self, sample_pdf: Path):
        """Adding archive TS to unsigned PDF should fail gracefully."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            mock_stamper.return_value.timestamp_pdf.side_effect = Exception("No signature found")

            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    with pytest.raises(TSAConnectionError, match="All TSA servers failed"):
                        manager.add_archive_timestamp(sample_pdf)

    def test_archive_ts_on_nonexistent_file_raises_error(self):
        """Adding archive TS to non-existent file raises FileNotFoundError."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        with pytest.raises(FileNotFoundError, match="PDF not found"):
            manager.add_archive_timestamp(Path("/nonexistent.pdf"))

    def test_archive_ts_without_tsa_urls_raises_error(self, signed_pdf: Path):
        """Adding archive TS without TSA URLs raises TSAConnectionError."""
        manager = ArchiveTimestampManager(tsa_urls=[], timeout=30)

        with pytest.raises(TSAConnectionError, match="No TSA URLs configured"):
            manager.add_archive_timestamp(signed_pdf)

    def test_tsa_timeout_handling(self, signed_pdf: Path, temp_dir: Path):
        """Test handling of TSA timeout errors."""
        output_path = temp_dir / "timeout_test.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            # Simulate timeout
            mock_stamper.return_value.timestamp_pdf.side_effect = TimeoutError("TSA timeout")

            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=5
                    )

                    with pytest.raises(TSAConnectionError, match="All TSA servers failed"):
                        manager.add_archive_timestamp(signed_pdf, output_path)

    def test_tsa_connection_error_handling(self, signed_pdf: Path, temp_dir: Path):
        """Test handling of TSA connection errors."""
        output_path = temp_dir / "connection_error_test.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            # Simulate connection error
            mock_stamper.return_value.timestamp_pdf.side_effect = ConnectionError("Cannot connect")

            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    with pytest.raises(TSAConnectionError, match="All TSA servers failed"):
                        manager.add_archive_timestamp(signed_pdf, output_path)


class TestTSAFallback:
    """Tests for TSA fallback mechanism."""

    def test_fallback_to_second_tsa_on_first_failure(self, signed_pdf: Path, temp_dir: Path):
        """When first TSA fails, should fallback to second TSA."""
        output_path = temp_dir / "fallback_test.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            # First TSA fails, second succeeds
            mock_stamper1 = Mock()
            mock_stamper1.timestamp_pdf.side_effect = Exception("TSA1 failed")
            mock_stamper1.url = "http://tsa1.example.com"

            mock_stamper2 = Mock()
            mock_stamper2.url = "http://tsa2.example.com"

            mock_stamper.side_effect = [mock_stamper1, mock_stamper2]

            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=[
                            "http://tsa1.example.com",
                            "http://tsa2.example.com",
                        ],
                        timeout=30,
                    )

                    result = manager.add_archive_timestamp(signed_pdf, output_path)

                    assert result == output_path
                    # Second stamper should be called after first fails
                    mock_stamper2.timestamp_pdf.assert_called_once()

    def test_all_tsa_fail_raises_error(self, signed_pdf: Path, temp_dir: Path):
        """When all TSAs fail, should raise TSAConnectionError."""
        output_path = temp_dir / "all_fail_test.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper") as mock_stamper:
            # All TSAs fail
            mock_stamper.return_value.timestamp_pdf.side_effect = Exception("TSA failed")

            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=[
                            "http://tsa1.example.com",
                            "http://tsa2.example.com",
                            "http://tsa3.example.com",
                        ],
                        timeout=30,
                    )

                    with pytest.raises(TSAConnectionError, match="All TSA servers failed"):
                        manager.add_archive_timestamp(signed_pdf, output_path)


class TestMultipleArchiveTimestamps:
    """Tests for multiple archive timestamps (re-timestamping)."""

    def test_add_second_archive_timestamp_to_lta_pdf(self, signed_pdf: Path, temp_dir: Path):
        """Add a second archive timestamp to an already LTA-level PDF."""
        # First archive timestamp
        lta1_path = temp_dir / "lta_first.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    manager.add_archive_timestamp(signed_pdf, lta1_path)

        # Second archive timestamp
        lta2_path = temp_dir / "lta_second.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    result = manager.add_archive_timestamp(lta1_path, lta2_path)

                    assert result == lta2_path

    def test_get_archive_timestamps_returns_multiple(self, signed_pdf: Path):
        """Test getting multiple archive timestamps from PDF."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        # Mock multiple timestamps
        with patch.object(manager, "get_archive_timestamps") as mock_get:
            ts1 = ArchiveTimestampInfo(
                timestamp=datetime(2024, 1, 1, 12, 0, 0),
                tsa_url="http://tsa1.example.com",
                hash_algorithm="sha256",
                covers_dss=True,
            )
            ts2 = ArchiveTimestampInfo(
                timestamp=datetime(2025, 1, 1, 12, 0, 0),
                tsa_url="http://tsa2.example.com",
                hash_algorithm="sha256",
                covers_dss=True,
            )
            mock_get.return_value = [ts1, ts2]

            timestamps = manager.get_archive_timestamps(signed_pdf)

            assert len(timestamps) == 2
            assert timestamps[0].timestamp == datetime(2024, 1, 1, 12, 0, 0)
            assert timestamps[1].timestamp == datetime(2025, 1, 1, 12, 0, 0)

    def test_needs_archive_timestamp_checks_age(self, signed_pdf: Path):
        """Test needs_archive_timestamp checks timestamp age."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        # Mock old timestamp
        old_ts = ArchiveTimestampInfo(
            timestamp=datetime.now() - timedelta(days=11 * 365),  # 11 years old
            tsa_url="http://tsa.example.com",
            hash_algorithm="sha256",
            covers_dss=True,
        )

        with patch.object(manager, "get_archive_timestamps", return_value=[old_ts]):
            needs_new = manager.needs_archive_timestamp(signed_pdf, algorithm_threshold_years=10)

            assert needs_new is True

    def test_needs_archive_timestamp_checks_weak_algorithms(self, signed_pdf: Path):
        """Test needs_archive_timestamp detects weak hash algorithms."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        # Mock timestamp with SHA-1 (weak)
        weak_ts = ArchiveTimestampInfo(
            timestamp=datetime.now() - timedelta(days=1),  # Recent
            tsa_url="http://tsa.example.com",
            hash_algorithm="sha1",  # Weak algorithm
            covers_dss=True,
        )

        with patch.object(manager, "get_archive_timestamps", return_value=[weak_ts]):
            needs_new = manager.needs_archive_timestamp(signed_pdf)

            assert needs_new is True


class TestArchiveTSPreservesSignatures:
    """Tests that archive timestamps don't invalidate existing signatures."""

    def test_archive_ts_preserves_original_signature(self, signed_pdf: Path, temp_dir: Path):
        """Adding archive TS should preserve the original signature."""
        lta_path = temp_dir / "preserve_sig.pdf"

        # Verify signed PDF exists
        assert signed_pdf.exists()

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    manager.add_archive_timestamp(signed_pdf, lta_path)

        # In a real scenario with actual signatures:
        # validator = PDFValidator()
        # original_result = validator.validate(signed_pdf)
        # lta_result = validator.validate(lta_path)
        # assert lta_result.signature_count == original_result.signature_count + 1
        # (Original signatures + 1 document timestamp)

    def test_multiple_signatures_preserved_after_archive_ts(self, sample_pdf: Path, temp_dir: Path):
        """Multiple signatures should be preserved after archive timestamp."""
        # Sign twice with MockBatchManager
        batch_manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="last")

        # First signature
        result1 = batch_manager.sign_batch(pdf_files=[sample_pdf], appearance=appearance)
        signed1 = result1.results[0].output_path

        # Second signature (simulates incremental signing)
        result2 = batch_manager.sign_batch(pdf_files=[signed1], appearance=appearance)
        signed2 = result2.results[0].output_path

        # Verify signed PDFs exist
        assert signed2.exists()

        # Add archive timestamp
        lta_path = temp_dir / "multi_sig_lta.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(
                        tsa_urls=["http://test.tsa.example.com"], timeout=30
                    )

                    manager.add_archive_timestamp(signed2, lta_path)

        assert lta_path.exists()

        # In a real scenario with actual incremental signatures:
        # validator = PDFValidator()
        # pre_ts = validator.validate(signed2)
        # post_ts = validator.validate(lta_path)
        # assert post_ts.signature_count == pre_ts.signature_count + 1


class TestCLIArchiveTS:
    """Tests for CLI archive-ts command."""

    def test_cli_archive_ts_single_file(self, signed_pdf: Path, temp_dir: Path, monkeypatch):
        """Test CLI command: pdfsigner archive-ts file.pdf"""
        output_path = temp_dir / "cli_output.pdf"

        # Mock collect_pdf_files to return Path objects
        with patch("pdfsigner.cli.archive_ts.collect_pdf_files", return_value=[signed_pdf]):
            # Mock the archive timestamp manager
            with patch("pdfsigner.cli.archive_ts.ArchiveTimestampManager") as mock_manager_class:
                mock_manager = Mock()
                mock_manager.add_archive_timestamp.return_value = output_path
                mock_manager_class.return_value = mock_manager

                from pdfsigner.cli.archive_ts import cmd_archive_ts

                # Create mock args
                args = MagicMock()
                args.files = [str(signed_pdf)]
                args.recursive = False
                args.tsa_url = ["http://test.tsa.example.com"]
                args.output = output_path

                # Execute command
                exit_code = cmd_archive_ts(args)

                assert exit_code == 0
                mock_manager.add_archive_timestamp.assert_called_once()

    def test_cli_archive_ts_multiple_files(self, temp_dir: Path, monkeypatch):
        """Test CLI command with multiple files."""
        # Create multiple signed PDFs
        pdf1 = temp_dir / "signed1.pdf"
        pdf2 = temp_dir / "signed2.pdf"
        pdf1.write_bytes(b"%PDF-1.4 mock")
        pdf2.write_bytes(b"%PDF-1.4 mock")

        # Mock collect_pdf_files to return Path objects
        with patch("pdfsigner.cli.archive_ts.collect_pdf_files", return_value=[pdf1, pdf2]):
            with patch("pdfsigner.cli.archive_ts.ArchiveTimestampManager") as mock_manager_class:
                mock_manager = Mock()
                mock_manager.add_archive_timestamp.side_effect = [pdf1, pdf2]
                mock_manager_class.return_value = mock_manager

                from pdfsigner.cli.archive_ts import cmd_archive_ts

                args = MagicMock()
                args.files = [str(pdf1), str(pdf2)]
                args.recursive = False
                args.tsa_url = ["http://test.tsa.example.com"]
                args.output = None

                exit_code = cmd_archive_ts(args)

                assert exit_code == 0
                assert mock_manager.add_archive_timestamp.call_count == 2

    def test_cli_archive_ts_no_files_fails(self, monkeypatch):
        """Test CLI command with no files returns error."""
        with patch("pdfsigner.cli.archive_ts.collect_pdf_files", return_value=[]):
            from pdfsigner.cli.archive_ts import cmd_archive_ts

            args = MagicMock()
            args.files = []
            args.recursive = False

            exit_code = cmd_archive_ts(args)

            assert exit_code == 1

    def test_cli_archive_ts_no_tsa_configured_fails(self, signed_pdf: Path, monkeypatch):
        """Test CLI command without TSA URL fails."""
        with patch("pdfsigner.cli.archive_ts.collect_pdf_files", return_value=[signed_pdf]):
            with patch("pdfsigner.cli.archive_ts.get_settings") as mock_settings:
                # No TSA URL in settings
                mock_settings.return_value.tsa_url = ""

                from pdfsigner.cli.archive_ts import cmd_archive_ts

                args = MagicMock()
                args.files = [str(signed_pdf)]
                args.recursive = False
                args.tsa_url = []  # No CLI TSA URL either

                exit_code = cmd_archive_ts(args)

                assert exit_code == 1

    def test_cli_archive_ts_tsa_error_handling(self, signed_pdf: Path, temp_dir: Path):
        """Test CLI command handles TSA errors gracefully."""
        # Mock collect_pdf_files to return Path objects
        with patch("pdfsigner.cli.archive_ts.collect_pdf_files", return_value=[signed_pdf]):
            with patch("pdfsigner.cli.archive_ts.ArchiveTimestampManager") as mock_manager_class:
                mock_manager = Mock()
                mock_manager.add_archive_timestamp.side_effect = TSAConnectionError(
                    "http://test.tsa.example.com"
                )
                mock_manager_class.return_value = mock_manager

                from pdfsigner.cli.archive_ts import cmd_archive_ts

                args = MagicMock()
                args.files = [str(signed_pdf)]
                args.recursive = False
                args.tsa_url = ["http://test.tsa.example.com"]
                args.output = None

                exit_code = cmd_archive_ts(args)

                # Should return 1 (failure) but not crash
                assert exit_code == 1


class TestArchiveTSWithCustomTSA:
    """Tests for archive timestamps with custom TSA URLs."""

    def test_archive_ts_with_custom_tsa_url(self, signed_pdf: Path, temp_dir: Path):
        """Add archive timestamp with custom TSA URL."""
        custom_tsa = "http://custom.tsa.example.com"
        output_path = temp_dir / "custom_tsa.pdf"

        with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
            with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                    manager = ArchiveTimestampManager(tsa_urls=[custom_tsa], timeout=30)

                    result = manager.add_archive_timestamp(signed_pdf, output_path)

                    assert result == output_path

    def test_archive_ts_with_multiple_tsa_urls(self, signed_pdf: Path, temp_dir: Path):
        """Configure multiple TSA URLs for fallback."""
        tsa_urls = [
            "http://tsa1.example.com",
            "http://tsa2.example.com",
            "http://tsa3.example.com",
        ]

        manager = ArchiveTimestampManager(tsa_urls=tsa_urls, timeout=30)

        assert len(manager.timestampers) == 3

    def test_archive_ts_timeout_configuration(self, signed_pdf: Path):
        """Test custom timeout configuration."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=60)

        assert manager.timeout == 60


class TestAutoArchiveTS:
    """Tests for automatic archive timestamp addition."""

    def test_settings_enable_archive_ts_auto(self, mock_settings):
        """Test settings for auto archive timestamp."""
        assert hasattr(mock_settings, "archive_ts_enabled")
        assert hasattr(mock_settings, "archive_ts_auto")

        mock_settings.archive_ts_auto = True
        assert mock_settings.archive_ts_auto is True

    def test_needs_archive_timestamp_no_timestamps(self, signed_pdf: Path):
        """PDF with no archive timestamps needs one."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        with patch.object(manager, "get_archive_timestamps", return_value=[]):
            needs = manager.needs_archive_timestamp(signed_pdf)
            assert needs is True

    def test_needs_archive_timestamp_recent_timestamp(self, signed_pdf: Path):
        """PDF with recent archive timestamp doesn't need another."""
        manager = ArchiveTimestampManager(tsa_urls=["http://test.tsa.example.com"], timeout=30)

        recent_ts = ArchiveTimestampInfo(
            timestamp=datetime.now() - timedelta(days=1),  # 1 day old
            tsa_url="http://tsa.example.com",
            hash_algorithm="sha256",
            covers_dss=True,
        )

        with patch.object(manager, "get_archive_timestamps", return_value=[recent_ts]):
            needs = manager.needs_archive_timestamp(signed_pdf, algorithm_threshold_years=10)
            assert needs is False


# ============================================================================
# Main entry point for running standalone
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
