"""Tests for encryption configuration dataclasses."""

import pytest

from pdfsigner.core.encryption import (
    EncryptionConfig,
    EncryptionMethod,
    EncryptionResult,
    EncryptionStrength,
    PDFPermissions,
)


class TestEncryptionMethod:
    """Tests for EncryptionMethod enum."""

    def test_password_method_value(self):
        """Test PASSWORD method has correct value."""
        assert EncryptionMethod.PASSWORD.value == "password"

    def test_certificate_method_value(self):
        """Test CERTIFICATE method has correct value."""
        assert EncryptionMethod.CERTIFICATE.value == "certificate"


class TestEncryptionStrength:
    """Tests for EncryptionStrength enum."""

    def test_aes128_value(self):
        """Test AES-128 has correct value."""
        assert EncryptionStrength.AES_128.value == "aes128"

    def test_aes256_value(self):
        """Test AES-256 has correct value."""
        assert EncryptionStrength.AES_256.value == "aes256"


class TestPDFPermissions:
    """Tests for PDFPermissions dataclass."""

    def test_default_permissions_deny_all(self):
        """Test default permissions deny most actions."""
        perms = PDFPermissions()
        assert perms.allow_print_low_quality is False
        assert perms.allow_copy_content is False
        assert perms.allow_modify_content is False
        assert perms.allow_accessibility is True  # Required for HIPAA

    def test_hipaa_compliant_default(self):
        """Test HIPAA-compliant default only allows accessibility."""
        perms = PDFPermissions.hipaa_compliant_default()
        assert perms.allow_accessibility is True
        assert perms.allow_print_low_quality is False
        assert perms.allow_copy_content is False

    def test_allow_printing_only(self):
        """Test allow_printing_only preset."""
        perms = PDFPermissions.allow_printing_only()
        assert perms.allow_print_low_quality is True
        assert perms.allow_print_high_quality is True
        assert perms.allow_copy_content is False

    def test_no_restrictions(self):
        """Test no_restrictions enables all permissions."""
        perms = PDFPermissions.no_restrictions()
        assert perms.allow_print_low_quality is True
        assert perms.allow_print_high_quality is True
        assert perms.allow_copy_content is True
        assert perms.allow_modify_content is True
        assert perms.allow_accessibility is True

    def test_to_pymupdf_flags_empty(self):
        """Test PyMuPDF flags with no permissions."""
        perms = PDFPermissions(allow_accessibility=False)
        # Should be minimal flags
        flags = perms.to_pymupdf_flags()
        assert isinstance(flags, int)


class TestEncryptionConfig:
    """Tests for EncryptionConfig dataclass."""

    def test_password_config_valid(self):
        """Test valid password configuration."""
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
            user_password="test123",
        )
        config.validate()  # Should not raise

    def test_password_config_with_owner(self):
        """Test password config with both user and owner."""
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
            user_password="user",
            owner_password="owner",
        )
        config.validate()  # Should not raise

    def test_password_config_missing_password_raises(self):
        """Test missing password raises ValueError."""
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
        )
        with pytest.raises(ValueError, match="password.*required"):
            config.validate()

    def test_certificate_config_missing_certs_raises(self):
        """Test missing certificates raises ValueError."""
        config = EncryptionConfig(
            method=EncryptionMethod.CERTIFICATE,
        )
        with pytest.raises(ValueError, match="certificate.*required"):
            config.validate()

    def test_default_strength_is_aes256(self):
        """Test default encryption strength is AES-256."""
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
            user_password="test",
        )
        assert config.strength == EncryptionStrength.AES_256

    def test_default_permissions_hipaa_compliant(self):
        """Test default permissions are HIPAA-compliant."""
        config = EncryptionConfig(
            method=EncryptionMethod.PASSWORD,
            user_password="test",
        )
        assert config.permissions.allow_accessibility is True
        assert config.permissions.allow_copy_content is False


class TestEncryptionResult:
    """Tests for EncryptionResult dataclass."""

    def test_success_result_str(self, tmp_path):
        """Test string representation of successful result."""
        result = EncryptionResult(
            success=True,
            input_path=tmp_path / "input.pdf",
            output_path=tmp_path / "output.pdf",
        )
        assert "✓" in str(result)
        assert "input.pdf" in str(result)

    def test_failure_result_str(self, tmp_path):
        """Test string representation of failed result."""
        result = EncryptionResult(
            success=False,
            input_path=tmp_path / "input.pdf",
            error="Something went wrong",
        )
        assert "✗" in str(result)
        assert "Something went wrong" in str(result)
