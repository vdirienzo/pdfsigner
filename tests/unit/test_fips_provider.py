"""Tests for FIPS 140-2 crypto provider."""

import hashlib
import warnings

import pytest

from pdfsigner.core.crypto import (
    AlgorithmCategory,
    FIPSCryptoProvider,
    FIPSModeError,
    get_fips_provider,
    reset_fips_provider,
)


class TestAlgorithmCategory:
    """Tests for AlgorithmCategory enum."""

    def test_hash_category_value(self):
        """Test HASH category has correct value."""
        assert AlgorithmCategory.HASH.value == "hash"

    def test_encryption_category_value(self):
        """Test ENCRYPTION category has correct value."""
        assert AlgorithmCategory.ENCRYPTION.value == "encryption"

    def test_signature_category_value(self):
        """Test SIGNATURE category has correct value."""
        assert AlgorithmCategory.SIGNATURE.value == "signature"

    def test_mac_category_value(self):
        """Test MAC category has correct value."""
        assert AlgorithmCategory.MAC.value == "mac"


class TestFIPSCryptoProviderInit:
    """Tests for FIPSCryptoProvider initialization."""

    def test_default_init_no_fips_mode(self):
        """Test default initialization has FIPS mode disabled."""
        provider = FIPSCryptoProvider()
        assert provider.fips_mode is False
        assert provider.strict_mode is True

    def test_init_with_fips_mode_enabled(self):
        """Test initialization with FIPS mode enabled."""
        provider = FIPSCryptoProvider(fips_mode=True)
        assert provider.fips_mode is True
        assert provider.strict_mode is True

    def test_init_with_non_strict_mode(self):
        """Test initialization with non-strict mode."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=False)
        assert provider.fips_mode is True
        assert provider.strict_mode is False

    def test_fips_mode_property(self):
        """Test fips_mode property returns correct value."""
        provider = FIPSCryptoProvider(fips_mode=True)
        assert provider.fips_mode is True

    def test_strict_mode_property(self):
        """Test strict_mode property returns correct value."""
        provider = FIPSCryptoProvider(strict_mode=False)
        assert provider.strict_mode is False


class TestFIPSAlgorithmValidation:
    """Tests for algorithm validation."""

    def test_validate_allowed_hash_in_fips_mode(self):
        """Test SHA-256 is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_algorithm("SHA-256", AlgorithmCategory.HASH)
        assert result is True

    def test_validate_allowed_encryption_in_fips_mode(self):
        """Test AES-256 is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_algorithm("AES-256", AlgorithmCategory.ENCRYPTION)
        assert result is True

    def test_validate_allowed_signature_in_fips_mode(self):
        """Test RSA-2048 is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_algorithm("RSA-2048", AlgorithmCategory.SIGNATURE)
        assert result is True

    def test_validate_allowed_mac_in_fips_mode(self):
        """Test HMAC-SHA-256 is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_algorithm("HMAC-SHA-256", AlgorithmCategory.MAC)
        assert result is True

    def test_validate_blocked_hash_strict_mode_raises(self):
        """Test MD5 raises exception in strict FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=True)
        with pytest.raises(FIPSModeError, match="MD5.*not allowed"):
            provider.validate_algorithm("MD5", AlgorithmCategory.HASH)

    def test_validate_blocked_hash_non_strict_mode_warns(self):
        """Test MD5 warns but doesn't raise in non-strict FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=False)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = provider.validate_algorithm("MD5", AlgorithmCategory.HASH)
            assert result is False
            assert len(w) == 1
            assert "MD5" in str(w[0].message)

    def test_validate_blocked_encryption_strict_mode_raises(self):
        """Test DES raises exception in strict FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=True)
        with pytest.raises(FIPSModeError, match="DES.*not allowed"):
            provider.validate_algorithm("DES", AlgorithmCategory.ENCRYPTION)

    def test_validate_blocked_signature_strict_mode_raises(self):
        """Test RSA-1024 raises exception in strict FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=True)
        with pytest.raises(FIPSModeError, match="RSA-1024.*not allowed"):
            provider.validate_algorithm("RSA-1024", AlgorithmCategory.SIGNATURE)

    def test_validate_all_algorithms_allowed_no_fips_mode(self):
        """Test all algorithms allowed when FIPS mode disabled."""
        provider = FIPSCryptoProvider(fips_mode=False)
        # Even MD5 should be allowed
        result = provider.validate_algorithm("MD5", AlgorithmCategory.HASH)
        assert result is True

    def test_validate_case_insensitive(self):
        """Test algorithm validation is case-insensitive."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result1 = provider.validate_algorithm("sha-256", AlgorithmCategory.HASH)
        result2 = provider.validate_algorithm("SHA-256", AlgorithmCategory.HASH)
        result3 = provider.validate_algorithm("ShA-256", AlgorithmCategory.HASH)
        assert result1 is True
        assert result2 is True
        assert result3 is True


class TestFIPSHashAlgorithm:
    """Tests for hash algorithm retrieval."""

    def test_get_hash_algorithm_sha256(self):
        """Test getting SHA-256 hash algorithm."""
        provider = FIPSCryptoProvider()
        algo = provider.get_hash_algorithm("SHA-256")
        assert algo == hashlib.sha256

    def test_get_hash_algorithm_sha384(self):
        """Test getting SHA-384 hash algorithm."""
        provider = FIPSCryptoProvider()
        algo = provider.get_hash_algorithm("SHA-384")
        assert algo == hashlib.sha384

    def test_get_hash_algorithm_sha512(self):
        """Test getting SHA-512 hash algorithm."""
        provider = FIPSCryptoProvider()
        algo = provider.get_hash_algorithm("SHA-512")
        assert algo == hashlib.sha512

    def test_get_hash_algorithm_unknown_raises(self):
        """Test getting unknown hash algorithm raises ValueError."""
        provider = FIPSCryptoProvider()
        with pytest.raises(ValueError, match="Unknown hash algorithm"):
            provider.get_hash_algorithm("SHA-999")

    def test_get_hash_algorithm_blocked_in_fips_mode_raises(self):
        """Test getting blocked hash in FIPS mode raises."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=True)
        with pytest.raises(FIPSModeError, match="MD5.*not allowed"):
            provider.get_hash_algorithm("MD5")

    def test_get_hash_algorithm_works_with_returned_algo(self):
        """Test returned hash algorithm actually works."""
        provider = FIPSCryptoProvider()
        algo = provider.get_hash_algorithm("SHA-256")
        # Should be able to create a hash
        h = algo(b"test data")
        digest = h.hexdigest()
        assert len(digest) == 64  # SHA-256 produces 64 hex chars


class TestFIPSCipher:
    """Tests for cipher retrieval."""

    def test_get_cipher_aes128(self):
        """Test getting AES-128 cipher identifier."""
        provider = FIPSCryptoProvider()
        cipher = provider.get_cipher("AES-128")
        assert cipher == "AES-128"

    def test_get_cipher_aes256(self):
        """Test getting AES-256 cipher identifier."""
        provider = FIPSCryptoProvider()
        cipher = provider.get_cipher("AES-256")
        assert cipher == "AES-256"

    def test_get_cipher_blocked_in_fips_mode_raises(self):
        """Test getting blocked cipher in FIPS mode raises."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=True)
        with pytest.raises(FIPSModeError, match="DES.*not allowed"):
            provider.get_cipher("DES")

    def test_get_cipher_normalizes_case(self):
        """Test cipher identifier is normalized to uppercase."""
        provider = FIPSCryptoProvider()
        cipher = provider.get_cipher("aes-256")
        assert cipher == "AES-256"


class TestFIPSSignatureValidation:
    """Tests for signature algorithm validation."""

    def test_validate_rsa_2048_signature(self):
        """Test RSA-2048 signature is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_signature_algorithm("RSA", 2048)
        assert result is True

    def test_validate_rsa_4096_signature(self):
        """Test RSA-4096 signature is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_signature_algorithm("RSA", 4096)
        assert result is True

    def test_validate_ecdsa_p256_signature(self):
        """Test ECDSA-P256 signature is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_signature_algorithm("ECDSA", 256)
        assert result is True

    def test_validate_ecdsa_p384_signature(self):
        """Test ECDSA-P384 signature is allowed in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True)
        result = provider.validate_signature_algorithm("ECDSA", 384)
        assert result is True

    def test_validate_rsa_1024_blocked_in_fips_mode(self):
        """Test RSA-1024 is blocked in FIPS mode."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=True)
        with pytest.raises(FIPSModeError, match="RSA-1024.*not allowed"):
            provider.validate_signature_algorithm("RSA", 1024)

    def test_validate_signature_without_key_size(self):
        """Test signature validation without key size."""
        provider = FIPSCryptoProvider(fips_mode=False)
        # Should use algorithm name only
        result = provider.validate_signature_algorithm("RSA", None)
        assert result is True


class TestFIPSProviderInfo:
    """Tests for provider information."""

    def test_get_provider_info_structure(self):
        """Test provider info has correct structure."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=False)
        info = provider.get_provider_info()
        assert "fips_mode" in info
        assert "strict_mode" in info
        assert "fips_available" in info
        assert "allowed_algorithms" in info

    def test_get_provider_info_values(self):
        """Test provider info has correct values."""
        provider = FIPSCryptoProvider(fips_mode=True, strict_mode=False)
        info = provider.get_provider_info()
        assert info["fips_mode"] is True
        assert info["strict_mode"] is False
        assert isinstance(info["fips_available"], bool)

    def test_get_provider_info_allowed_algorithms(self):
        """Test provider info includes all algorithm categories."""
        provider = FIPSCryptoProvider()
        info = provider.get_provider_info()
        algos = info["allowed_algorithms"]
        assert "hash" in algos
        assert "encryption" in algos
        assert "signature" in algos
        assert "mac" in algos

    def test_get_provider_info_hash_algorithms(self):
        """Test provider info includes correct hash algorithms."""
        provider = FIPSCryptoProvider()
        info = provider.get_provider_info()
        hash_algos = info["allowed_algorithms"]["hash"]
        assert "SHA-256" in hash_algos
        assert "SHA-384" in hash_algos
        assert "SHA-512" in hash_algos
        assert len(hash_algos) == 3

    def test_get_provider_info_encryption_algorithms(self):
        """Test provider info includes correct encryption algorithms."""
        provider = FIPSCryptoProvider()
        info = provider.get_provider_info()
        enc_algos = info["allowed_algorithms"]["encryption"]
        assert "AES-128" in enc_algos
        assert "AES-256" in enc_algos
        assert len(enc_algos) == 2


class TestFIPSAvailability:
    """Tests for FIPS availability checking."""

    def test_is_fips_available_returns_bool(self):
        """Test is_fips_available returns boolean."""
        provider = FIPSCryptoProvider()
        result = provider.is_fips_available()
        assert isinstance(result, bool)

    def test_is_fips_available_consistent(self):
        """Test is_fips_available returns consistent result."""
        provider = FIPSCryptoProvider()
        result1 = provider.is_fips_available()
        result2 = provider.is_fips_available()
        assert result1 == result2


class TestFIPSSingletonProvider:
    """Tests for singleton provider access."""

    def test_get_fips_provider_returns_instance(self):
        """Test get_fips_provider returns FIPSCryptoProvider instance."""
        reset_fips_provider()  # Ensure clean slate
        provider = get_fips_provider()
        assert isinstance(provider, FIPSCryptoProvider)

    def test_get_fips_provider_returns_singleton(self):
        """Test get_fips_provider returns same instance."""
        reset_fips_provider()
        provider1 = get_fips_provider()
        provider2 = get_fips_provider()
        assert provider1 is provider2

    def test_reset_fips_provider_creates_new_instance(self):
        """Test reset_fips_provider allows new instance."""
        reset_fips_provider()
        provider1 = get_fips_provider()
        reset_fips_provider()
        provider2 = get_fips_provider()
        assert provider1 is not provider2

    def test_get_fips_provider_loads_from_settings(self, monkeypatch):
        """Test get_fips_provider initializes from settings."""
        # Mock settings
        from pdfsigner.config.settings import Settings

        mock_settings = Settings(fips_mode_enabled=True, fips_strict_mode=False)

        def mock_get_settings():
            return mock_settings

        import pdfsigner.config.settings

        monkeypatch.setattr(pdfsigner.config.settings, "get_settings", mock_get_settings)

        reset_fips_provider()
        provider = get_fips_provider()
        assert provider.fips_mode is True
        assert provider.strict_mode is False


class TestFIPSModeError:
    """Tests for FIPSModeError exception."""

    def test_fips_mode_error_is_exception(self):
        """Test FIPSModeError is an Exception."""
        assert issubclass(FIPSModeError, Exception)

    def test_fips_mode_error_message(self):
        """Test FIPSModeError can be raised with message."""
        with pytest.raises(FIPSModeError, match="test error"):
            raise FIPSModeError("test error")
