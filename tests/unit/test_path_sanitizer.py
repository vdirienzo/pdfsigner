"""
Tests for path_sanitizer.py - Path traversal prevention

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path

import pytest

from pdfsigner.core.security.path_sanitizer import (
    PathTraversalError,
    sanitize_filename,
    sanitize_output_suffix,
    sanitize_path,
    validate_path_within_base,
)


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_valid_filename_passes(self):
        """Valid filename should pass unchanged."""
        assert sanitize_filename("my_template") == "my_template"
        assert sanitize_filename("template-name") == "template-name"
        assert sanitize_filename("Template123") == "Template123"

    def test_empty_filename_raises(self):
        """Empty filename should raise error."""
        with pytest.raises(PathTraversalError, match="Empty filename"):
            sanitize_filename("")

    def test_null_byte_raises(self):
        """Filename with null byte should raise error."""
        with pytest.raises(PathTraversalError, match="Null bytes"):
            sanitize_filename("file\x00name")

    def test_parent_directory_raises(self):
        """Filename with .. should raise error."""
        with pytest.raises(PathTraversalError, match="Parent directory"):
            sanitize_filename("../evil")
        with pytest.raises(PathTraversalError, match="Parent directory"):
            sanitize_filename("foo/../bar")

    def test_absolute_path_raises(self):
        """Absolute path should raise error."""
        with pytest.raises(PathTraversalError, match="Absolute paths"):
            sanitize_filename("/etc/passwd")
        with pytest.raises(PathTraversalError, match="Absolute paths"):
            sanitize_filename("C:\\Windows\\System32")

    def test_backslash_raises(self):
        """Backslash in filename should raise error."""
        with pytest.raises(PathTraversalError, match="Backslashes"):
            sanitize_filename("foo\\bar")

    def test_path_separator_without_subdirs_raises(self):
        """Path separator should raise error when subdirs not allowed."""
        with pytest.raises(PathTraversalError, match="Path separators"):
            sanitize_filename("subdir/file")

    def test_path_separator_with_subdirs_allowed(self):
        """Path separator should pass when subdirs allowed."""
        assert sanitize_filename("images/logo.png", allow_subdirs=True) == "images/logo.png"


class TestValidatePathWithinBase:
    """Tests for validate_path_within_base function."""

    def test_valid_path_within_base(self, tmp_path: Path):
        """Path within base directory should pass."""
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_file.touch()

        result = validate_path_within_base(
            Path("test.txt"),
            tmp_path,
            "test path",
        )
        assert result == test_file

    def test_path_traversal_blocked(self, tmp_path: Path):
        """Path attempting to escape base should be blocked."""
        with pytest.raises(PathTraversalError, match="escapes base directory"):
            validate_path_within_base(
                Path("../escape.txt"),
                tmp_path,
                "malicious path",
            )

    def test_absolute_path_outside_base_blocked(self, tmp_path: Path):
        """Absolute path outside base should be blocked."""
        with pytest.raises(PathTraversalError, match="escapes base directory"):
            validate_path_within_base(
                Path("/etc/passwd"),
                tmp_path,
                "system file",
            )

    def test_nested_traversal_blocked(self, tmp_path: Path):
        """Nested traversal attempts should be blocked."""
        (tmp_path / "subdir").mkdir()
        with pytest.raises(PathTraversalError, match="escapes base directory"):
            validate_path_within_base(
                Path("subdir/../../escape.txt"),
                tmp_path,
                "nested traversal",
            )


class TestSanitizePath:
    """Tests for sanitize_path function."""

    def test_valid_relative_path(self, tmp_path: Path):
        """Valid relative path should be sanitized and resolved."""
        test_file = tmp_path / "image.png"
        test_file.touch()

        result = sanitize_path(
            "image.png",
            base_dir=tmp_path,
            must_exist=True,
            path_description="image",
        )
        assert result == test_file

    def test_must_exist_raises_when_missing(self, tmp_path: Path):
        """must_exist=True should raise error for non-existent path."""
        with pytest.raises(FileNotFoundError, match="not found"):
            sanitize_path(
                "missing.png",
                base_dir=tmp_path,
                must_exist=True,
                path_description="image",
            )

    def test_must_exist_false_allows_missing(self, tmp_path: Path):
        """must_exist=False should allow non-existent path."""
        result = sanitize_path(
            "future.png",
            base_dir=tmp_path,
            must_exist=False,
            path_description="image",
        )
        assert result == tmp_path / "future.png"

    def test_empty_path_raises(self, tmp_path: Path):
        """Empty path should raise error."""
        with pytest.raises(PathTraversalError, match="Empty"):
            sanitize_path("", base_dir=tmp_path)

    def test_null_byte_raises(self, tmp_path: Path):
        """Path with null byte should raise error."""
        with pytest.raises(PathTraversalError, match="Null bytes"):
            sanitize_path("file\x00.png", base_dir=tmp_path)

    def test_absolute_path_raises(self, tmp_path: Path):
        """Absolute path should raise error."""
        with pytest.raises(PathTraversalError, match="Absolute paths"):
            sanitize_path("/etc/passwd", base_dir=tmp_path)


class TestSanitizeOutputSuffix:
    """Tests for sanitize_output_suffix function."""

    def test_valid_suffix_passes(self):
        """Valid suffix should pass unchanged."""
        assert sanitize_output_suffix("_signed") == "_signed"
        assert sanitize_output_suffix("-firmado") == "-firmado"
        assert sanitize_output_suffix("_v2") == "_v2"

    def test_empty_suffix_passes(self):
        """Empty suffix is valid."""
        assert sanitize_output_suffix("") == ""

    def test_path_separator_raises(self):
        """Path separator in suffix should raise error."""
        with pytest.raises(PathTraversalError, match="Path separators"):
            sanitize_output_suffix("_signed/evil")

    def test_parent_reference_raises(self):
        """Parent reference in suffix should raise error."""
        with pytest.raises(PathTraversalError, match="Parent directory"):
            sanitize_output_suffix("_..")

    def test_null_byte_raises(self):
        """Null byte in suffix should raise error."""
        with pytest.raises(PathTraversalError, match="Null bytes"):
            sanitize_output_suffix("_sig\x00ned")

    def test_invalid_start_character_raises(self):
        """Suffix starting with invalid character should raise error."""
        with pytest.raises(PathTraversalError, match="must start with"):
            sanitize_output_suffix(".hidden")
        with pytest.raises(PathTraversalError, match="must start with"):
            sanitize_output_suffix("$special")


class TestPathTraversalAttackVectors:
    """Test common path traversal attack vectors."""

    def test_dot_dot_slash_attack(self, tmp_path: Path):
        """Classic ../ attack should be blocked."""
        with pytest.raises(PathTraversalError):
            sanitize_path("../../../etc/passwd", base_dir=tmp_path)

    def test_encoded_traversal_in_filename(self):
        """Encoded traversal in filename should be blocked."""
        # Even if decoded, .. is still blocked
        with pytest.raises(PathTraversalError):
            sanitize_filename("..%2F..%2Fetc%2Fpasswd")

    def test_mixed_slash_attack(self, tmp_path: Path):
        """Mixed slashes should be handled."""
        with pytest.raises(PathTraversalError):
            sanitize_path("..\\..\\Windows\\System32", base_dir=tmp_path)

    def test_null_byte_injection(self):
        """Null byte injection should be blocked."""
        with pytest.raises(PathTraversalError):
            sanitize_filename("valid.png\x00.exe")

    def test_double_dot_variations(self):
        """Various .. patterns should be blocked."""
        attack_patterns = [
            "..",
            "...",
            "....//",
            "..//",
            "..\\/",
        ]
        for pattern in attack_patterns:
            # Either PathTraversalError or it gets sanitized
            try:
                result = sanitize_filename(pattern, allow_subdirs=True)
                # If no error, result should not contain ..
                assert ".." not in result
            except PathTraversalError:
                pass  # Expected for most patterns
