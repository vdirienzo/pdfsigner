"""Tests for ArchiveTimestampManager."""

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pyhanko.sign.timestamps import HTTPTimeStamper

from pdfsigner.core.signer.archive_ts_manager import (
    ArchiveTimestampInfo,
    ArchiveTimestampManager,
)
from pdfsigner.exceptions import TSAConnectionError


class TestArchiveTimestampInfo:
    """Tests for ArchiveTimestampInfo dataclass."""

    def test_creation_with_all_fields(self):
        """Test dataclass creation with all fields."""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        info = ArchiveTimestampInfo(
            timestamp=timestamp,
            tsa_url="https://tsa.example.com",
            hash_algorithm="SHA-256",
            covers_dss=True,
        )

        assert info.timestamp == timestamp
        assert info.tsa_url == "https://tsa.example.com"
        assert info.hash_algorithm == "SHA-256"
        assert info.covers_dss is True

    def test_creation_with_none_tsa_url(self):
        """Test dataclass creation with None TSA URL."""
        info = ArchiveTimestampInfo(
            timestamp=datetime.now(),
            tsa_url=None,
            hash_algorithm="SHA-512",
            covers_dss=False,
        )

        assert info.tsa_url is None
        assert info.covers_dss is False

    def test_different_hash_algorithms(self):
        """Test dataclass with different hash algorithms."""
        for algo in ["SHA-256", "SHA-384", "SHA-512", "SHA-1"]:
            info = ArchiveTimestampInfo(
                timestamp=datetime.now(),
                tsa_url="https://tsa.example.com",
                hash_algorithm=algo,
                covers_dss=True,
            )
            assert info.hash_algorithm == algo


class TestArchiveTimestampManager:
    """Tests for ArchiveTimestampManager class."""

    @pytest.fixture
    def tsa_urls(self):
        """Create test TSA URLs."""
        return ["https://tsa1.example.com", "https://tsa2.example.com"]

    @pytest.fixture
    def manager(self, tsa_urls):
        """Create manager with test TSAs."""
        return ArchiveTimestampManager(tsa_urls=tsa_urls, timeout=5)

    @pytest.fixture
    def mock_pdf_path(self, tmp_path):
        """Create a mock PDF file."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4 mock content")
        return pdf_path

    def test_init_creates_timestampers(self, manager):
        """Test initialization creates timestampers for each URL."""
        assert len(manager.timestampers) == 2
        assert all(isinstance(ts, HTTPTimeStamper) for ts in manager.timestampers)

    def test_init_empty_urls_filtered(self):
        """Test empty URLs are filtered out during initialization."""
        manager = ArchiveTimestampManager(
            tsa_urls=["", "https://tsa.example.com", "", None, "https://tsa2.example.com"]
        )
        assert len(manager.timestampers) == 2

    def test_init_with_custom_timeout(self):
        """Test initialization with custom timeout."""
        manager = ArchiveTimestampManager(tsa_urls=["https://tsa.example.com"], timeout=15)
        assert manager.timeout == 15

    def test_init_with_no_urls_logs_warning(self):
        """Test initialization with no URLs logs warning."""
        with patch("pdfsigner.core.signer.archive_ts_manager.logger") as mock_logger:
            manager = ArchiveTimestampManager(tsa_urls=[])
            assert len(manager.timestampers) == 0
            mock_logger.warning.assert_called_once()

    def test_add_archive_timestamp_no_tsa_configured(self, mock_pdf_path):
        """Test add_archive_timestamp raises error when no TSAs configured."""
        manager = ArchiveTimestampManager(tsa_urls=[])

        with pytest.raises(TSAConnectionError, match="No TSA URLs configured"):
            manager.add_archive_timestamp(mock_pdf_path)

    def test_add_archive_timestamp_file_not_found(self, manager):
        """Test add_archive_timestamp raises FileNotFoundError for missing PDF."""
        with pytest.raises(FileNotFoundError, match="PDF not found"):
            manager.add_archive_timestamp(Path("/nonexistent.pdf"))

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper")
    @patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter")
    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_add_archive_timestamp_success_first_tsa(
        self, mock_reader, mock_writer, mock_pdf_stamper, manager, mock_pdf_path
    ):
        """Test add_archive_timestamp succeeds with first TSA."""
        mock_stamper_instance = Mock()
        mock_pdf_stamper.return_value = mock_stamper_instance

        with patch("builtins.open", create=True):
            result = manager.add_archive_timestamp(mock_pdf_path)

        assert result == mock_pdf_path
        mock_stamper_instance.timestamp_pdf.assert_called_once()

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper")
    def test_add_archive_timestamp_fallback_to_second_tsa(
        self, mock_pdf_stamper, manager, mock_pdf_path
    ):
        """Test add_archive_timestamp falls back to second TSA on first failure."""
        # First timestamper fails, second succeeds
        mock_stamper1 = Mock()
        mock_stamper1.timestamp_pdf.side_effect = Exception("TSA1 timeout")

        mock_stamper2 = Mock()

        mock_pdf_stamper.side_effect = [mock_stamper1, mock_stamper2]

        with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
            with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                with patch("builtins.open", create=True):
                    result = manager.add_archive_timestamp(mock_pdf_path)

        assert result == mock_pdf_path
        # Second stamper should be called after first fails
        mock_stamper2.timestamp_pdf.assert_called_once()

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper")
    def test_add_archive_timestamp_all_tsa_fail(self, mock_pdf_stamper, manager, mock_pdf_path):
        """Test add_archive_timestamp raises TSAConnectionError when all TSAs fail."""
        mock_stamper = Mock()
        mock_stamper.timestamp_pdf.side_effect = Exception("Connection error")
        mock_pdf_stamper.return_value = mock_stamper

        with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
            with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                with patch("builtins.open", create=True):
                    with pytest.raises(TSAConnectionError, match="All TSA servers failed"):
                        manager.add_archive_timestamp(mock_pdf_path)

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper")
    def test_add_archive_timestamp_with_custom_output_path(
        self, mock_pdf_stamper, manager, mock_pdf_path, tmp_path
    ):
        """Test add_archive_timestamp with custom output path."""
        output_path = tmp_path / "output.pdf"
        mock_stamper = Mock()
        mock_pdf_stamper.return_value = mock_stamper

        with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
            with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                with patch("builtins.open", create=True):
                    result = manager.add_archive_timestamp(mock_pdf_path, output_path)

        assert result == output_path

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_get_archive_timestamps_empty_pdf(self, mock_reader, manager, mock_pdf_path):
        """Test get_archive_timestamps with PDF with no timestamps."""
        mock_reader_instance = Mock()
        mock_reader_instance.root = {}
        mock_reader.return_value = mock_reader_instance

        with patch("builtins.open", create=True):
            result = manager.get_archive_timestamps(mock_pdf_path)

        assert result == []

    def test_get_archive_timestamps_file_not_found(self, manager):
        """Test get_archive_timestamps raises FileNotFoundError for missing PDF."""
        with pytest.raises(FileNotFoundError, match="PDF not found"):
            manager.get_archive_timestamps(Path("/nonexistent.pdf"))

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_get_archive_timestamps_with_dss(self, mock_reader, manager, mock_pdf_path):
        """Test get_archive_timestamps detects DSS dictionary."""
        mock_reader_instance = Mock()
        mock_reader_instance.root = {
            "/DSS": Mock(),
            "/AcroForm": {"/Fields": []},
        }
        mock_reader.return_value = mock_reader_instance

        with patch("builtins.open", create=True):
            result = manager.get_archive_timestamps(mock_pdf_path)

        # No timestamp fields, but DSS should be detected if timestamps existed
        assert result == []

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_get_archive_timestamps_with_signature_field(self, mock_reader, manager, mock_pdf_path):
        """Test get_archive_timestamps with document timestamp field."""
        # Mock signature dictionary with timestamp
        mock_sig_dict = Mock()
        mock_sig_dict.get.side_effect = lambda k: {
            "/SubFilter": "/ETSI.RFC3161",
            "/Contents": b"timestamp_contents",
        }.get(k)

        # Mock signature value (has get_object method)
        mock_sig_value = Mock()
        mock_sig_value.get_object.return_value = mock_sig_dict

        # Mock field with signature
        mock_field = Mock()
        mock_field.get.side_effect = lambda k: {
            "/FT": "/Sig",
            "/V": mock_sig_value,
        }.get(k)

        # Mock field reference (has get_object method)
        mock_field_ref = Mock()
        mock_field_ref.get_object.return_value = mock_field

        mock_reader_instance = Mock()
        mock_reader_instance.root = {"/AcroForm": {"/Fields": [mock_field_ref]}}
        mock_reader.return_value = mock_reader_instance

        with patch("builtins.open", create=True):
            with patch.object(manager, "_parse_timestamp_token") as mock_parse:
                mock_parse.return_value = ArchiveTimestampInfo(
                    timestamp=datetime(2024, 1, 1, 12, 0, 0),
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha256",
                    covers_dss=False,
                )

                result = manager.get_archive_timestamps(mock_pdf_path)

        assert len(result) == 1
        assert result[0].timestamp == datetime(2024, 1, 1, 12, 0, 0)
        assert result[0].tsa_url == "https://tsa.example.com"

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_get_archive_timestamps_ignores_non_timestamp_signatures(
        self, mock_reader, manager, mock_pdf_path
    ):
        """Test get_archive_timestamps ignores regular signatures."""
        # Mock signature dictionary with regular signature (not timestamp)
        mock_sig_dict = Mock()
        mock_sig_dict.get.side_effect = lambda k: {
            "/SubFilter": "/adbe.pkcs7.detached",
            "/Contents": b"signature_contents",
        }.get(k)

        # Mock signature value
        mock_sig_value = Mock()
        mock_sig_value.get_object.return_value = mock_sig_dict

        # Mock field
        mock_field = Mock()
        mock_field.get.side_effect = lambda k: {
            "/FT": "/Sig",
            "/V": mock_sig_value,
        }.get(k)

        # Mock field reference
        mock_field_ref = Mock()
        mock_field_ref.get_object.return_value = mock_field

        mock_reader_instance = Mock()
        mock_reader_instance.root = {"/AcroForm": {"/Fields": [mock_field_ref]}}
        mock_reader.return_value = mock_reader_instance

        with patch("builtins.open", create=True):
            result = manager.get_archive_timestamps(mock_pdf_path)

        # Regular signature should be ignored
        assert result == []

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_get_archive_timestamps_handles_parse_errors(self, mock_reader, manager, mock_pdf_path):
        """Test get_archive_timestamps handles parsing errors gracefully."""
        # Mock signature dictionary with timestamp
        mock_sig_dict = Mock()
        mock_sig_dict.get.side_effect = lambda k: {
            "/SubFilter": "/ETSI.RFC3161",
            "/Contents": b"timestamp_contents",
        }.get(k)

        # Mock signature value
        mock_sig_value = Mock()
        mock_sig_value.get_object.return_value = mock_sig_dict

        # Mock field
        mock_field = Mock()
        mock_field.get.side_effect = lambda k: {
            "/FT": "/Sig",
            "/V": mock_sig_value,
        }.get(k)

        # Mock field reference
        mock_field_ref = Mock()
        mock_field_ref.get_object.return_value = mock_field

        mock_reader_instance = Mock()
        mock_reader_instance.root = {"/AcroForm": {"/Fields": [mock_field_ref]}}
        mock_reader.return_value = mock_reader_instance

        with patch("builtins.open", create=True):
            with patch.object(manager, "_parse_timestamp_token") as mock_parse:
                mock_parse.side_effect = Exception("Parse error")

                result = manager.get_archive_timestamps(mock_pdf_path)

        # Should return empty list on parse error
        assert result == []

    @patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader")
    def test_needs_archive_timestamp_no_timestamps(self, mock_reader, manager, mock_pdf_path):
        """Test needs_archive_timestamp returns True with no timestamps."""
        mock_reader_instance = Mock()
        mock_reader_instance.root = {}
        mock_reader.return_value = mock_reader_instance

        with patch("builtins.open", create=True):
            result = manager.needs_archive_timestamp(mock_pdf_path)

        assert result is True

    def test_needs_archive_timestamp_file_not_found(self, manager):
        """Test needs_archive_timestamp raises FileNotFoundError for missing PDF."""
        with pytest.raises(FileNotFoundError, match="PDF not found"):
            manager.needs_archive_timestamp(Path("/nonexistent.pdf"))

    def test_needs_archive_timestamp_old_timestamp(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp returns True for old timestamp."""
        old_timestamp = datetime.now() - timedelta(days=11 * 365)  # 11 years old

        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.return_value = [
                ArchiveTimestampInfo(
                    timestamp=old_timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha256",
                    covers_dss=True,
                )
            ]

            result = manager.needs_archive_timestamp(mock_pdf_path, algorithm_threshold_years=10)

        assert result is True

    def test_needs_archive_timestamp_recent_timestamp(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp returns False for recent timestamp."""
        recent_timestamp = datetime.now() - timedelta(days=1)  # 1 day old

        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.return_value = [
                ArchiveTimestampInfo(
                    timestamp=recent_timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha256",
                    covers_dss=True,
                )
            ]

            result = manager.needs_archive_timestamp(mock_pdf_path, algorithm_threshold_years=10)

        assert result is False

    def test_needs_archive_timestamp_weak_algorithm_sha1(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp returns True for SHA-1."""
        recent_timestamp = datetime.now() - timedelta(days=1)

        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.return_value = [
                ArchiveTimestampInfo(
                    timestamp=recent_timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha1",  # Weak algorithm
                    covers_dss=True,
                )
            ]

            result = manager.needs_archive_timestamp(mock_pdf_path)

        assert result is True

    def test_needs_archive_timestamp_weak_algorithm_md5(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp returns True for MD5."""
        recent_timestamp = datetime.now() - timedelta(days=1)

        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.return_value = [
                ArchiveTimestampInfo(
                    timestamp=recent_timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="MD5",  # Weak algorithm (case insensitive)
                    covers_dss=True,
                )
            ]

            result = manager.needs_archive_timestamp(mock_pdf_path)

        assert result is True

    def test_needs_archive_timestamp_multiple_timestamps_uses_latest(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp uses latest timestamp for age check."""
        old_timestamp = datetime.now() - timedelta(days=11 * 365)
        recent_timestamp = datetime.now() - timedelta(days=1)

        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.return_value = [
                ArchiveTimestampInfo(
                    timestamp=old_timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha256",
                    covers_dss=True,
                ),
                ArchiveTimestampInfo(
                    timestamp=recent_timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha256",
                    covers_dss=True,
                ),
            ]

            result = manager.needs_archive_timestamp(mock_pdf_path, algorithm_threshold_years=10)

        # Should use most recent timestamp
        assert result is False

    def test_needs_archive_timestamp_error_returns_true(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp returns True on error (conservative)."""
        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.side_effect = Exception("Parse error")

            result = manager.needs_archive_timestamp(mock_pdf_path)

        # Conservative: assume timestamp needed if can't determine
        assert result is True

    def test_needs_archive_timestamp_custom_threshold(self, manager, mock_pdf_path):
        """Test needs_archive_timestamp with custom threshold."""
        timestamp = datetime.now() - timedelta(days=6 * 365)  # 6 years old

        with patch.object(manager, "get_archive_timestamps") as mock_get:
            mock_get.return_value = [
                ArchiveTimestampInfo(
                    timestamp=timestamp,
                    tsa_url="https://tsa.example.com",
                    hash_algorithm="sha256",
                    covers_dss=True,
                )
            ]

            # With 5 year threshold, should need new timestamp
            result_5y = manager.needs_archive_timestamp(mock_pdf_path, algorithm_threshold_years=5)
            # With 10 year threshold, should not need new timestamp
            result_10y = manager.needs_archive_timestamp(
                mock_pdf_path, algorithm_threshold_years=10
            )

        assert result_5y is True
        assert result_10y is False

    def test_parse_timestamp_token_returns_archive_info(self, manager):
        """Test _parse_timestamp_token returns ArchiveTimestampInfo on invalid input."""
        # Invalid bytes should trigger fallback with sensible defaults
        result = manager._parse_timestamp_token(b"mock_token_bytes")

        assert isinstance(result, ArchiveTimestampInfo)
        assert isinstance(result.timestamp, datetime)
        assert isinstance(result.hash_algorithm, str)
        # Fallback returns "unknown" for unparseable tokens
        assert result.hash_algorithm == "unknown"

    def test_manager_timeout_stored(self, manager):
        """Test manager stores timeout value."""
        assert manager.timeout == 5

    def test_add_archive_timestamp_logs_tsa_attempts(self, manager, mock_pdf_path):
        """Test add_archive_timestamp logs TSA attempt."""
        with patch("pdfsigner.core.signer.archive_ts_manager.logger") as mock_logger:
            with patch("pdfsigner.core.signer.archive_ts_manager.PdfTimeStamper"):
                with patch("pdfsigner.core.signer.archive_ts_manager.IncrementalPdfFileWriter"):
                    with patch("pdfsigner.core.signer.archive_ts_manager.PdfFileReader"):
                        with patch("builtins.open", create=True):
                            manager.add_archive_timestamp(mock_pdf_path)

        # Should log debug message for TSA attempt
        mock_logger.debug.assert_called()
        # Should log info message for success
        mock_logger.info.assert_called()
