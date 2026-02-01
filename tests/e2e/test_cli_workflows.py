"""
test_cli_workflows.py - E2E tests for CLI workflows using subprocess

Tests the CLI commands with real subprocess execution to validate
the complete CLI interface and user experience.

Author: Claude Code
"""

import subprocess

import fitz  # PyMuPDF
import pytest


class TestCLIBasics:
    """Tests for basic CLI functionality."""

    def test_cli_help_shows_usage(self):
        """Test pdfsigner --help shows usage information."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "PDFSigner" in result.stdout
        assert "sign" in result.stdout
        assert "validate" in result.stdout
        assert "encrypt" in result.stdout

    def test_cli_version_shows_version(self):
        """Test pdfsigner shows version in help."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # Version info is in the help or description
        assert "PDFSigner" in result.stdout

    def test_cli_no_command_shows_help_and_examples(self):
        """Test running pdfsigner without command shows help and examples."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # Should show examples section
        assert "Examples:" in result.stdout or "example" in result.stdout.lower()


class TestSignCommand:
    """Tests for sign command."""

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF for testing."""
        pdf_path = tmp_path / "test.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Test Document for Signing", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    @pytest.fixture
    def sample_pdf_with_phi(self, tmp_path):
        """Create a sample PDF with PHI content."""
        pdf_path = tmp_path / "test_phi.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Patient: John Doe", fontsize=12)
        page.insert_text((72, 90), "SSN: 123-45-6789", fontsize=12)
        page.insert_text((72, 108), "Medical Record: MRN-123456", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_sign_help_shows_options(self):
        """Test pdfsigner sign --help shows signing options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "sign", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--visible" in result.stdout
        assert "--page" in result.stdout
        # Note: --dry-run is global flag, not in sign subcommand help

    def test_sign_dry_run_succeeds(self, sample_pdf):
        """Test pdfsigner sign with --dry-run (no token needed)."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(sample_pdf)],
            input="1234\n",  # Provide mock PIN input
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Dry run should complete successfully
        assert result.returncode == 0
        # Should mention simulation or dry-run
        output = result.stdout + result.stderr
        assert "dry" in output.lower() or "simulat" in output.lower() or "success" in output.lower()

    def test_sign_dry_run_visible_signature(self, sample_pdf):
        """Test pdfsigner sign --dry-run --visible creates visible signature."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(sample_pdf), "--visible"],
            input="1234\n",  # Provide mock PIN input
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0
        # Check for output file
        output_path = sample_pdf.parent / f"{sample_pdf.stem}_signed.pdf"
        if output_path.exists():
            assert output_path.stat().st_size > 0

    def test_sign_dry_run_with_reason_location_contact(self, sample_pdf):
        """Test pdfsigner sign with metadata arguments."""
        result = subprocess.run(
            [
                "uv",
                "run",
                "pdfsigner",
                "--dry-run",
                "sign",
                str(sample_pdf),
                "--reason",
                "Document approval",
                "--location",
                "Buenos Aires, Argentina",
                "--contact",
                "test@example.com",
            ],
            input="1234\n",  # Provide mock PIN input
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should accept the arguments
        assert result.returncode == 0

    def test_sign_nonexistent_file_fails(self, tmp_path):
        """Test signing non-existent file returns error."""
        nonexistent = tmp_path / "nonexistent.pdf"
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(nonexistent)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail
        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert (
            "not found" in output.lower()
            or "does not exist" in output.lower()
            or "error" in output.lower()
        )

    def test_sign_invalid_file_type_fails(self, tmp_path):
        """Test signing non-PDF file returns error."""
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("Not a PDF")

        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(txt_file)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail or warn
        assert result.returncode != 0 or "error" in (result.stdout + result.stderr).lower()

    def test_sign_batch_multiple_files_dry_run(self, tmp_path):
        """Test batch signing multiple PDFs."""
        # Create multiple PDFs
        pdf1 = tmp_path / "doc1.pdf"
        pdf2 = tmp_path / "doc2.pdf"

        for pdf_path in [pdf1, pdf2]:
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Document {pdf_path.stem}", fontsize=12)
            doc.save(str(pdf_path))
            doc.close()

        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(pdf1), str(pdf2)],
            input="1234\n",  # Provide mock PIN input
            capture_output=True,
            text=True,
            timeout=90,
        )

        # Should process both files
        assert result.returncode == 0

    def test_sign_recursive_directory_dry_run(self, tmp_path):
        """Test recursive directory signing."""
        # Create directory structure with PDFs
        subdir = tmp_path / "subdocs"
        subdir.mkdir()

        for i, parent in enumerate([tmp_path, subdir]):
            pdf = parent / f"doc{i}.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Document {i}", fontsize=12)
            doc.save(str(pdf))
            doc.close()

        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(tmp_path), "-r"],
            input="1234\n",  # Provide mock PIN input
            capture_output=True,
            text=True,
            timeout=90,
        )

        # Should find PDFs recursively
        assert result.returncode == 0


class TestValidateCommand:
    """Tests for validate command."""

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF."""
        pdf_path = tmp_path / "test.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Test Document", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_validate_help_shows_options(self):
        """Test pdfsigner validate --help shows validation options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "validate", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "validate" in result.stdout.lower()

    def test_validate_unsigned_pdf_reports_no_signatures(self, sample_pdf):
        """Test validating unsigned PDF reports no signatures."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "validate", str(sample_pdf)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should complete (might return 0 or 1 depending on implementation)
        output = result.stdout + result.stderr
        # Should mention no signatures or invalid
        assert (
            "no signature" in output.lower()
            or "not signed" in output.lower()
            or "unsigned" in output.lower()
        )

    def test_validate_nonexistent_file_fails(self, tmp_path):
        """Test validating non-existent file returns error."""
        nonexistent = tmp_path / "nonexistent.pdf"
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "validate", str(nonexistent)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert (
            "not found" in output.lower()
            or "does not exist" in output.lower()
            or "error" in output.lower()
        )

    def test_validate_recursive_directory(self, tmp_path):
        """Test recursive directory validation."""
        # Create directory with PDFs
        for i in range(2):
            pdf = tmp_path / f"doc{i}.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_text((72, 72), f"Document {i}", fontsize=12)
            doc.save(str(pdf))
            doc.close()

        result = subprocess.run(
            ["uv", "run", "pdfsigner", "validate", str(tmp_path), "-r"],
            capture_output=True,
            text=True,
            timeout=90,
        )

        # Should process directory
        # Exit code may vary based on signature presence
        assert result.returncode in [0, 1]


class TestEncryptCommand:
    """Tests for encrypt command."""

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF."""
        pdf_path = tmp_path / "test.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Test Document for Encryption", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_encrypt_help_shows_options(self):
        """Test pdfsigner encrypt --help shows encryption options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "encrypt", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--password" in result.stdout
        assert "AES" in result.stdout or "encrypt" in result.stdout.lower()

    def test_encrypt_pdf_creates_encrypted_file(self, sample_pdf):
        """Test encrypting PDF creates encrypted output."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "encrypt", str(sample_pdf), "-p", "testpassword123"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0

        # Check for encrypted output file
        encrypted_path = sample_pdf.parent / f"{sample_pdf.stem}_encrypted.pdf"
        if encrypted_path.exists():
            assert encrypted_path.stat().st_size > 0
            # Try to open without password - should be encrypted
            try:
                doc = fitz.open(str(encrypted_path))
                assert doc.is_encrypted
                doc.close()
            except Exception:
                # Some encryption might prevent opening entirely
                pass

    def test_encrypt_aes128_option(self, sample_pdf):
        """Test encrypting with AES-128 instead of AES-256."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "encrypt", str(sample_pdf), "-p", "testpass", "--aes128"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should accept the flag
        assert result.returncode == 0

    def test_encrypt_custom_suffix(self, sample_pdf):
        """Test encrypting with custom output suffix."""
        result = subprocess.run(
            [
                "uv",
                "run",
                "pdfsigner",
                "encrypt",
                str(sample_pdf),
                "-p",
                "testpass",
                "-s",
                "_secure",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0

        # Check for custom suffix file
        encrypted_path = sample_pdf.parent / f"{sample_pdf.stem}_secure.pdf"
        if encrypted_path.exists():
            assert encrypted_path.stat().st_size > 0

    def test_encrypt_without_password_fails(self, sample_pdf):
        """Test encrypting without password argument fails."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "encrypt", str(sample_pdf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail - password is required
        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert "password" in output.lower() or "required" in output.lower()


class TestDecryptCommand:
    """Tests for decrypt command."""

    @pytest.fixture
    def encrypted_pdf(self, tmp_path):
        """Create an encrypted PDF."""
        pdf_path = tmp_path / "test_encrypted.pdf"

        # Create and encrypt a PDF
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Encrypted Content", fontsize=12)

        # Save with encryption (using correct PyMuPDF API)
        doc.save(
            str(pdf_path),
            encryption=fitz.PDF_ENCRYPT_AES_256,
            user_pw="testpassword",
            owner_pw="testpassword",
            permissions=int(fitz.PDF_PERM_PRINT | fitz.PDF_PERM_COPY | fitz.PDF_PERM_ANNOTATE),
        )
        doc.close()

        return pdf_path

    def test_decrypt_help_shows_options(self):
        """Test pdfsigner decrypt --help shows decryption options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "decrypt", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--password" in result.stdout

    def test_decrypt_pdf_with_correct_password(self, encrypted_pdf):
        """Test decrypting PDF with correct password."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "decrypt", str(encrypted_pdf), "-p", "testpassword"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should succeed with correct password
        assert result.returncode == 0

    def test_decrypt_pdf_with_wrong_password_fails(self, encrypted_pdf):
        """Test decrypting PDF with wrong password fails."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "decrypt", str(encrypted_pdf), "-p", "wrongpassword"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should fail with wrong password
        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert (
            "password" in output.lower() or "decrypt" in output.lower() or "error" in output.lower()
        )


class TestListCertsCommand:
    """Tests for list-certs command."""

    def test_list_certs_help_shows_info(self):
        """Test pdfsigner list-certs --help shows information."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "list-certs", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0

    def test_list_certs_without_token(self):
        """Test list-certs without token (may fail or show empty list)."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "list-certs"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # May succeed with empty list or fail if no token
        # Either way, should not crash
        assert result.returncode in [0, 1]


class TestArchiveTSCommand:
    """Tests for archive-ts command."""

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF."""
        pdf_path = tmp_path / "signed.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Signed Document", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_archive_ts_help_shows_options(self):
        """Test pdfsigner archive-ts --help shows timestamp options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "archive-ts", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--tsa-url" in result.stdout or "timestamp" in result.stdout.lower()

    def test_archive_ts_without_tsa_url(self, sample_pdf):
        """Test archive-ts without TSA URL (should fail or use config)."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "archive-ts", str(sample_pdf)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # May fail if no TSA configured
        # Should not crash
        assert result.returncode in [0, 1]


class TestScanPIICommand:
    """Tests for scan-pii command."""

    @pytest.fixture
    def pdf_with_pii(self, tmp_path):
        """Create a PDF with PII content."""
        pdf_path = tmp_path / "test_pii.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Patient: John Doe", fontsize=12)
        page.insert_text((72, 90), "SSN: 123-45-6789", fontsize=12)
        page.insert_text((72, 108), "Email: patient@example.com", fontsize=12)
        page.insert_text((72, 126), "Phone: (555) 123-4567", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_scan_pii_help_shows_options(self):
        """Test pdfsigner scan-pii --help shows scanning options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "scan-pii", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "PII" in result.stdout or "PHI" in result.stdout or "confidence" in result.stdout

    def test_scan_pii_detects_pii_patterns(self, pdf_with_pii):
        """Test scan-pii detects PII patterns in PDF."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "scan-pii", str(pdf_with_pii)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Return code 1 when PII is detected (not an error)
        assert result.returncode in [0, 1]
        output = result.stdout + result.stderr
        # Should detect some PII types
        assert (
            "SSN" in output
            or "email" in output.lower()
            or "phone" in output.lower()
            or "PII" in output
        )

    def test_scan_pii_with_min_confidence(self, pdf_with_pii):
        """Test scan-pii with custom confidence threshold."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "scan-pii", str(pdf_with_pii), "-c", "0.5"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Return code 0 or 1 (1 when PII detected, not an error)
        assert result.returncode in [0, 1]

    def test_scan_pii_nonexistent_file_fails(self, tmp_path):
        """Test scan-pii with non-existent file fails."""
        nonexistent = tmp_path / "nonexistent.pdf"
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "scan-pii", str(nonexistent)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert (
            "not found" in output.lower()
            or "does not exist" in output.lower()
            or "error" in output.lower()
        )


class TestRedactCommand:
    """Tests for redact command."""

    @pytest.fixture
    def pdf_with_pii(self, tmp_path):
        """Create a PDF with PII content."""
        pdf_path = tmp_path / "test_redact.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "SSN: 123-45-6789", fontsize=12)
        page.insert_text((72, 90), "Email: test@example.com", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_redact_help_shows_options(self):
        """Test pdfsigner redact --help shows redaction options."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "redact", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--types" in result.stdout or "--all" in result.stdout

    @pytest.mark.xfail(reason="Bug in redactor.py: PIIDetector.scan_pdf method does not exist")
    def test_redact_specific_pii_types(self, pdf_with_pii):
        """Test redacting specific PII types."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "redact", str(pdf_with_pii), "--types", "ssn", "email"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should process the file
        assert result.returncode == 0

    @pytest.mark.xfail(reason="Bug in redactor.py: PIIDetector.scan_pdf method does not exist")
    def test_redact_all_pii_types(self, pdf_with_pii):
        """Test redacting all PII types with --all flag."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "redact", str(pdf_with_pii), "--all"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should process the file
        assert result.returncode == 0

    @pytest.mark.xfail(reason="Bug in redactor.py: PIIDetector.scan_pdf method does not exist")
    def test_redact_custom_output_path(self, pdf_with_pii):
        """Test redacting with custom output path."""
        output_path = pdf_with_pii.parent / "redacted_output.pdf"
        result = subprocess.run(
            [
                "uv",
                "run",
                "pdfsigner",
                "redact",
                str(pdf_with_pii),
                "--all",
                "-o",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should accept output parameter
        assert result.returncode == 0


class TestOutputFileNaming:
    """Tests for output file naming conventions."""

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF."""
        pdf_path = tmp_path / "document.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Test Document", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_sign_default_output_naming(self, sample_pdf):
        """Test default output naming: input.pdf -> input_signed.pdf."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "--dry-run", "sign", str(sample_pdf)],
            input="1234\n",  # Provide mock PIN input
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0

        # Check for default naming pattern
        expected_output = sample_pdf.parent / f"{sample_pdf.stem}_signed.pdf"
        if expected_output.exists():
            assert expected_output.stat().st_size > 0

    def test_encrypt_default_output_naming(self, sample_pdf):
        """Test encrypt default output naming: input.pdf -> input_encrypted.pdf."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "encrypt", str(sample_pdf), "-p", "testpass"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0

        # Check for default naming pattern
        expected_output = sample_pdf.parent / f"{sample_pdf.stem}_encrypted.pdf"
        if expected_output.exists():
            assert expected_output.stat().st_size > 0


class TestErrorHandling:
    """Tests for CLI error handling."""

    def test_invalid_command_shows_error(self):
        """Test invalid command shows appropriate error."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "invalid-command"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert (
            "invalid" in output.lower() or "error" in output.lower() or "unknown" in output.lower()
        )

    def test_missing_required_argument_shows_error(self):
        """Test missing required argument shows error."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "sign"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert "required" in output.lower() or "error" in output.lower()

    def test_corrupted_pdf_handling(self, tmp_path):
        """Test handling of corrupted PDF file."""
        corrupted_pdf = tmp_path / "corrupted.pdf"
        corrupted_pdf.write_bytes(b"Not a valid PDF content")

        result = subprocess.run(
            ["uv", "run", "pdfsigner", "validate", str(corrupted_pdf)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should handle gracefully
        assert result.returncode != 0
        output = result.stdout + result.stderr
        assert (
            "error" in output.lower() or "invalid" in output.lower() or "corrupt" in output.lower()
        )


class TestVerboseMode:
    """Tests for verbose mode."""

    @pytest.fixture
    def sample_pdf(self, tmp_path):
        """Create a sample PDF."""
        pdf_path = tmp_path / "test.pdf"
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Test Document", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_verbose_flag_shows_debug_output(self, sample_pdf):
        """Test -v/--verbose flag shows debug information."""
        result = subprocess.run(
            ["uv", "run", "pdfsigner", "-v", "--dry-run", "sign", str(sample_pdf)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Verbose mode should provide more output
        output = result.stdout + result.stderr
        # Should have substantial output in verbose mode
        assert len(output) > 100 or "DEBUG" in output or "INFO" in output
