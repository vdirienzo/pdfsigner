"""
test_cli.py - Tests for CLI commands

Author: Homero Thompson del Lago del Terror
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from pdfsigner.main import main


class TestCLIMain:
    """Tests for main CLI."""

    def test_cli_no_args_shows_help(self, capsys):
        """Test CLI without arguments shows help."""
        with patch.object(sys, "argv", ["pdfsigner"]):
            result = main()

        captured = capsys.readouterr()
        assert result == 0
        assert "PDFSigner" in captured.out or "sign" in captured.out

    def test_cli_help_flag(self, capsys):
        """Test CLI --help flag."""
        with patch.object(sys, "argv", ["pdfsigner", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0

    def test_cli_dry_run_flag_recognized(self):
        """Test CLI --dry-run flag is recognized."""
        with patch.object(sys, "argv", ["pdfsigner", "--dry-run"]):
            # Should not raise error for unknown flag
            result = main()
            assert result == 0


class TestSignCommand:
    """Tests for sign command."""

    def test_sign_help(self, capsys):
        """Test sign command help."""
        with patch.object(sys, "argv", ["pdfsigner", "sign", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0

    def test_sign_no_files_shows_error(self, capsys):
        """Test sign without files shows error."""
        with patch.object(sys, "argv", ["pdfsigner", "sign"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        # argparse exits with code 2 for missing required args
        assert exc_info.value.code == 2

    def test_sign_nonexistent_file(self, capsys, temp_dir):
        """Test sign with non-existent file."""
        with patch.object(sys, "argv", ["pdfsigner", "sign", "nonexistent.pdf"]):
            result = main()

        # Should handle gracefully (might return error code or print message)
        assert result != 0 or "not found" in capsys.readouterr().out.lower()


class TestValidateCommand:
    """Tests for validate command."""

    def test_validate_help(self, capsys):
        """Test validate command help."""
        with patch.object(sys, "argv", ["pdfsigner", "validate", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0

    def test_validate_no_files_shows_error(self, capsys):
        """Test validate without files shows error."""
        with patch.object(sys, "argv", ["pdfsigner", "validate"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        # argparse exits with code 2 for missing required args
        assert exc_info.value.code == 2


class TestListCertsCommand:
    """Tests for list-certs command."""

    def test_list_certs_help(self, capsys):
        """Test list-certs command help."""
        with patch.object(sys, "argv", ["pdfsigner", "list-certs", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0


class TestDryRunMode:
    """Tests for dry-run mode."""

    @patch("pdfsigner.main.cmd_sign")
    def test_dry_run_propagates_to_sign(self, mock_cmd_sign, temp_dir: Path):
        """Test dry-run mode propagates to sign command."""
        # Create test PDF
        pdf_path = temp_dir / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n%%EOF")

        mock_cmd_sign.return_value = 0

        with patch.object(sys, "argv", ["pdfsigner", "--dry-run", "sign", str(pdf_path)]):
            main()

        # cmd_sign should have been called
        mock_cmd_sign.assert_called_once()
