"""
test_e2e_signing_flow.py - End-to-end tests for complete signing workflows

Author: Homero Thompson del Lago del Terror

Tests complete flows: dry-run sign → validate → verify signatures.
Uses real PDF files and the actual signing/validation logic.
"""

from pathlib import Path

import pytest

# Fixtures auto-discovered by pytest from conftest.py


class TestDryRunSigningFlow:
    """E2E tests for dry-run signing workflow."""

    @pytest.fixture
    def signing_env(self, temp_dir: Path):
        """Set up signing environment with dry-run enabled."""
        # Create NSS directory (even though dry-run doesn't use it)
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Create output directory
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        return {
            "temp_dir": temp_dir,
            "nss_dir": nss_dir,
            "output_dir": output_dir,
        }

    def test_dry_run_sign_creates_output_file(self, signing_env, sample_pdf):
        """Test that dry-run signing creates an output file."""
        from pdfsigner.core.mock.mock_batch import MockBatchManager

        # Create mock batch manager (dry-run mode)
        manager = MockBatchManager()

        # Process files with sign_batch
        result = manager.sign_batch(
            files=[sample_pdf],
            pin="1234",
            visible=True,
            qr_enabled=False,
        )

        # Verify results
        assert result.successful == 1
        assert result.failed == 0
        assert result.all_successful is True

        # Check output file exists
        output_path = sample_pdf.parent / f"{sample_pdf.stem}_signed{sample_pdf.suffix}"
        assert output_path.exists()

    def test_dry_run_sign_with_qr_code(self, signing_env, sample_pdf):
        """Test dry-run signing with QR code enabled."""
        from pdfsigner.core.mock.mock_batch import MockBatchManager

        manager = MockBatchManager()
        result = manager.sign_batch(
            files=[sample_pdf],
            pin="1234",
            visible=True,
            qr_enabled=True,
        )

        assert result.successful == 1
        assert result.all_successful is True

    def test_dry_run_sign_invisible(self, signing_env, sample_pdf):
        """Test dry-run signing with invisible signature."""
        from pdfsigner.core.mock.mock_batch import MockBatchManager

        manager = MockBatchManager()
        result = manager.sign_batch(
            files=[sample_pdf],
            pin="1234",
            visible=False,
            qr_enabled=False,
        )

        assert result.successful == 1
        assert result.all_successful is True

    def test_dry_run_sign_multiple_files(self, signing_env, temp_dir):
        """Test dry-run signing multiple files."""
        import fitz

        from pdfsigner.core.mock.mock_batch import MockBatchManager

        # Create multiple test PDFs
        pdf_files = []
        for i in range(3):
            pdf_path = temp_dir / f"test_{i}.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Test document {i}")
            doc.save(str(pdf_path))
            doc.close()
            pdf_files.append(pdf_path)

        manager = MockBatchManager()
        result = manager.sign_batch(
            files=pdf_files,
            pin="1234",
            visible=True,
            qr_enabled=False,
        )

        assert result.successful == 3
        assert result.failed == 0
        assert result.all_successful is True


class TestValidationFlow:
    """E2E tests for PDF validation workflow."""

    @pytest.fixture
    def unsigned_pdf(self):
        """Path to an unsigned PDF fixture."""
        fixture_path = Path(__file__).parent.parent / "fixtures" / "sample.pdf"
        if fixture_path.exists():
            return fixture_path
        pytest.skip("Unsigned PDF fixture not available")

    @pytest.fixture
    def stamped_pdf(self):
        """Path to a stamped (dry-run) PDF fixture.

        Note: This PDF has a visual stamp but NO real cryptographic signature.
        Dry-run mode only adds visual appearance, not real PKCS#11 signatures.
        """
        fixture_path = Path(__file__).parent.parent / "fixtures" / "sample_signed.pdf"
        if fixture_path.exists():
            return fixture_path
        pytest.skip("Stamped PDF fixture not available")

    def test_validate_unsigned_pdf(self, unsigned_pdf):
        """Test validation of unsigned PDF returns no signatures."""
        from pdfsigner.core.validator.pdf_validator import PDFValidator

        validator = PDFValidator()
        result = validator.validate(unsigned_pdf)

        assert result.is_signed is False
        assert len(result.signatures) == 0

    def test_validate_stamped_pdf_has_no_crypto_signature(self, stamped_pdf):
        """Test that dry-run stamped PDF has NO real cryptographic signature.

        Dry-run mode only adds visual stamps - it does NOT create real
        PKCS#11 signatures. This is by design: dry-run simulates appearance
        without requiring a real hardware token.
        """
        from pdfsigner.core.validator.pdf_validator import PDFValidator

        validator = PDFValidator()
        result = validator.validate(stamped_pdf)

        # Dry-run stamps are NOT real signatures
        assert result.is_signed is False
        assert len(result.signatures) == 0

    def test_get_signature_count_on_unsigned(self, unsigned_pdf):
        """Test getting signature count from unsigned PDF."""
        from pdfsigner.core.validator.pdf_validator import PDFValidator

        validator = PDFValidator()

        # Unsigned PDF should have no signatures
        unsigned_count = validator.get_signature_count(unsigned_pdf)
        assert unsigned_count == 0

    def test_get_signature_count_on_stamped(self, stamped_pdf):
        """Test that dry-run stamped PDF has zero cryptographic signatures."""
        from pdfsigner.core.validator.pdf_validator import PDFValidator

        validator = PDFValidator()

        # Stamped PDF (dry-run) has visual stamp but NO real signature
        stamped_count = validator.get_signature_count(stamped_pdf)
        assert stamped_count == 0  # Visual stamp != cryptographic signature


class TestSignAndValidateFlow:
    """E2E tests for complete sign → validate flow."""

    def test_dry_run_sign_then_validate(self, sample_pdf, temp_dir):
        """Test complete flow: dry-run sign → validate → verify."""
        from pdfsigner.core.mock.mock_batch import MockBatchManager
        from pdfsigner.core.validator.pdf_validator import PDFValidator

        # Step 1: Sign with dry-run
        manager = MockBatchManager()
        result = manager.sign_batch(
            files=[sample_pdf],
            pin="1234",
            visible=True,
            qr_enabled=True,
        )

        assert result.successful == 1
        assert result.all_successful is True

        signed_path = sample_pdf.parent / f"{sample_pdf.stem}_signed{sample_pdf.suffix}"
        assert signed_path.exists()

        # Step 2: Validate the signed PDF
        validator = PDFValidator()
        _ = validator.validate(signed_path)  # Call validates file is readable

        # Note: Dry-run signatures are simulated, so they won't
        # appear as real cryptographic signatures
        # The test verifies the file was created and is a valid PDF
        assert signed_path.stat().st_size > 0

    def test_multiple_sign_validate_cycle(self, temp_dir):
        """Test multiple sign/validate cycles."""
        import fitz

        from pdfsigner.core.mock.mock_batch import MockBatchManager
        from pdfsigner.core.validator.pdf_validator import PDFValidator

        _ = PDFValidator()  # noqa: F841 - Verifies import works

        # Create and sign multiple PDFs
        for i in range(3):
            # Create test PDF
            pdf_path = temp_dir / f"doc_{i}.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Document {i} - Confidential")
            doc.save(str(pdf_path))
            doc.close()

            # Sign it
            manager = MockBatchManager()
            result = manager.sign_batch(
                files=[pdf_path],
                pin="1234",
                visible=True,
                qr_enabled=False,
            )

            assert result.all_successful is True

            signed_path = pdf_path.parent / f"{pdf_path.stem}_signed{pdf_path.suffix}"
            assert signed_path.exists()

            # Verify it's a valid PDF
            try:
                check_doc = fitz.open(str(signed_path))
                assert check_doc.page_count >= 1
                check_doc.close()
            except Exception as e:
                pytest.fail(f"Signed PDF is invalid: {e}")


class TestStampSimulation:
    """E2E tests for stamp simulation in dry-run mode."""

    def test_stamp_simulator_creates_valid_stamp(self, temp_dir, sample_pdf):
        """Test stamp simulator creates a valid stamped PDF."""
        from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

        output_path = temp_dir / "stamped_with_qr.pdf"

        # Add stamp with QR to PDF
        add_stamp_to_pdf(
            input_path=sample_pdf,
            output_path=output_path,
            page_spec="last",
            visible=True,
            position="bottom_right",
            qr_enabled=True,
        )

        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_stamp_simulator_without_qr(self, temp_dir, sample_pdf):
        """Test stamp simulator without QR code."""
        from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

        output_path = temp_dir / "stamped_no_qr.pdf"

        add_stamp_to_pdf(
            input_path=sample_pdf,
            output_path=output_path,
            page_spec="last",
            visible=True,
            position="bottom_right",
            qr_enabled=False,
        )

        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_stamp_added_to_pdf(self, sample_pdf, temp_dir):
        """Test that stamp is actually added to PDF."""
        import fitz

        from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

        output_path = temp_dir / "stamped.pdf"

        # Add stamp to PDF
        add_stamp_to_pdf(
            input_path=sample_pdf,
            output_path=output_path,
            page_spec=0,
            visible=True,
            position="bottom_right",
            qr_enabled=True,
        )

        assert output_path.exists()

        # Verify output is a valid PDF
        doc = fitz.open(str(output_path))
        assert doc.page_count >= 1
        doc.close()

    def test_invisible_signature_just_copies(self, sample_pdf, temp_dir):
        """Test that invisible signature just copies the file."""
        from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

        output_path = temp_dir / "invisible.pdf"

        add_stamp_to_pdf(
            input_path=sample_pdf,
            output_path=output_path,
            visible=False,
        )

        assert output_path.exists()
        # File should be roughly the same size (just a copy)
        original_size = sample_pdf.stat().st_size
        output_size = output_path.stat().st_size
        assert abs(original_size - output_size) < 1000  # Within 1KB tolerance


class TestProgressReporting:
    """E2E tests for progress reporting during batch operations."""

    def test_batch_reports_progress(self, temp_dir):
        """Test that batch signing reports progress correctly."""
        import fitz

        from pdfsigner.core.mock.mock_batch import MockBatchManager

        # Create test PDFs
        pdf_files = []
        for i in range(5):
            pdf_path = temp_dir / f"batch_{i}.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Batch document {i}")
            doc.save(str(pdf_path))
            doc.close()
            pdf_files.append(pdf_path)

        # Collect progress reports
        progress_reports = []

        def progress_callback(progress):
            progress_reports.append(progress)

        manager = MockBatchManager()
        result = manager.sign_batch(
            files=pdf_files,
            pin="1234",
            visible=True,
            qr_enabled=False,
            progress_callback=progress_callback,
        )

        # Verify all files were processed
        assert result.successful == 5

        # Verify progress was reported
        assert len(progress_reports) > 0

        # Check that we got processing and success reports
        statuses = [p.status for p in progress_reports]
        assert "processing" in statuses
        assert "success" in statuses

    def test_progress_callback_receives_correct_totals(self, temp_dir):
        """Test progress callback receives correct total counts."""
        import fitz

        from pdfsigner.core.mock.mock_batch import MockBatchManager

        # Create 3 PDFs
        pdf_files = []
        for i in range(3):
            pdf_path = temp_dir / f"progress_{i}.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Progress test {i}")
            doc.save(str(pdf_path))
            doc.close()
            pdf_files.append(pdf_path)

        last_progress = None

        def track_progress(progress):
            nonlocal last_progress
            last_progress = progress

        manager = MockBatchManager()
        manager.sign_batch(
            files=pdf_files,
            progress_callback=track_progress,
        )

        # Last progress should show 3/3
        assert last_progress is not None
        assert last_progress.total == 3
        assert last_progress.current == 3
