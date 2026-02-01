"""
test_mfa_encryption.py - Tests for MFA secret encryption

Tests AES-256-GCM encryption of TOTP secrets via KeyManager integration.
"""

import base64

import pytest

from pdfsigner.core.crypto.key_manager import (
    KeyManager,
    KeyType,
    init_key_manager,
)


@pytest.fixture
def key_manager(tmp_path):
    """Create a test KeyManager."""
    db_path = tmp_path / "test_keys.db"
    master_password = "test-master-password-12345"
    return KeyManager(db_path, master_password)


@pytest.fixture
def initialized_key_manager(tmp_path, monkeypatch):
    """Create and initialize KeyManager singleton."""
    db_path = tmp_path / "test_keys.db"
    master_password = "test-master-password-12345"

    # Initialize the singleton
    km = init_key_manager(db_path, master_password)

    # Patch the module to use our test instance
    import pdfsigner.core.crypto.key_manager as km_module

    monkeypatch.setattr(km_module, "_key_manager", km)

    return km


class TestKeyManagerEncryption:
    """Test KeyManager encrypt/decrypt methods."""

    def test_encrypt_decrypt_roundtrip(self, key_manager):
        """Encrypted data should decrypt correctly."""
        # Generate a key
        key_id = key_manager.generate_key(
            key_type=KeyType.SYMMETRIC,
            algorithm="AES-256",
            key_size=256,
        )

        # Test data
        plaintext = b"my-secret-totp-key-ABCDEFGH123456"

        # Encrypt
        ciphertext = key_manager.encrypt_data(key_id, plaintext)
        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)  # Ciphertext includes overhead

        # Decrypt
        decrypted = key_manager.decrypt_data(key_id, ciphertext)
        assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertext(self, key_manager):
        """Different keys should produce different ciphertext."""
        # Generate two keys
        key1 = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", 256)
        key2 = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", 256)

        plaintext = b"same-plaintext"

        ct1 = key_manager.encrypt_data(key1, plaintext)
        ct2 = key_manager.encrypt_data(key2, plaintext)

        assert ct1 != ct2

    def test_same_plaintext_produces_different_ciphertext(self, key_manager):
        """Same plaintext encrypted twice should produce different ciphertext (IV)."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", 256)
        plaintext = b"same-plaintext"

        ct1 = key_manager.encrypt_data(key_id, plaintext)
        ct2 = key_manager.encrypt_data(key_id, plaintext)

        # Fernet uses random IV, so ciphertexts should differ
        assert ct1 != ct2

        # Both should decrypt correctly
        assert key_manager.decrypt_data(key_id, ct1) == plaintext
        assert key_manager.decrypt_data(key_id, ct2) == plaintext

    def test_wrong_key_fails_decryption(self, key_manager):
        """Decryption with wrong key should fail."""
        key1 = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", 256)
        key2 = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", 256)

        plaintext = b"secret-data"
        ciphertext = key_manager.encrypt_data(key1, plaintext)

        with pytest.raises(ValueError, match="Decryption failed"):
            key_manager.decrypt_data(key2, ciphertext)

    def test_corrupted_ciphertext_fails(self, key_manager):
        """Corrupted ciphertext should fail decryption."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", 256)
        plaintext = b"secret-data"

        ciphertext = key_manager.encrypt_data(key_id, plaintext)

        # Corrupt the ciphertext
        corrupted = bytes([b ^ 0xFF for b in ciphertext[:10]]) + ciphertext[10:]

        with pytest.raises(ValueError, match="Decryption failed"):
            key_manager.decrypt_data(key_id, corrupted)


class TestMFAKeyManagement:
    """Test MFA-specific key management."""

    def test_get_or_create_mfa_key_creates_new(self, key_manager):
        """Should create new MFA key if none exists."""
        key_id = key_manager.get_or_create_mfa_key()

        assert key_id is not None
        assert len(key_id) > 0

        # Key should be active and have correct metadata
        keys = key_manager.list_keys(key_type=KeyType.SYMMETRIC)
        mfa_keys = [k for k in keys if k.metadata.get("purpose") == "mfa_encryption"]

        assert len(mfa_keys) == 1
        assert mfa_keys[0].key_id == key_id
        assert mfa_keys[0].algorithm == "AES-256-GCM"

    def test_get_or_create_mfa_key_reuses_existing(self, key_manager):
        """Should reuse existing MFA key."""
        key_id1 = key_manager.get_or_create_mfa_key()
        key_id2 = key_manager.get_or_create_mfa_key()

        assert key_id1 == key_id2


class TestMFAManagerEncryption:
    """Test MFAManager integration with KeyManager."""

    @pytest.fixture
    def mfa_manager(self, tmp_path, initialized_key_manager):
        """Create MFA manager with test database."""
        from pdfsigner.core.auth.mfa.mfa_manager import MFAManager

        mfa_db = tmp_path / "mfa.db"
        return MFAManager(db_path=mfa_db)

    def test_secret_stored_encrypted(self, mfa_manager, tmp_path, initialized_key_manager):
        """TOTP secret should be stored encrypted."""
        import sqlite3

        # Enroll user
        enrollment = mfa_manager.begin_enrollment("test_user")
        secret = enrollment.secret

        # Check database directly
        mfa_db = tmp_path / "mfa.db"
        conn = sqlite3.connect(mfa_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT encrypted_secret, key_id FROM mfa_secrets WHERE user_id = ?",
            ("test_user",),
        )
        row = cursor.fetchone()
        conn.close()

        encrypted_secret = row[0]
        key_id = row[1]

        # Should NOT be base64 (legacy)
        assert key_id != "base64"

        # Encrypted value should be different from original
        decoded = base64.b64decode(encrypted_secret)
        assert decoded != secret.encode()

    def test_secret_retrieved_correctly(self, mfa_manager, initialized_key_manager):
        """Stored secret should decrypt correctly."""
        # Enroll user
        enrollment = mfa_manager.begin_enrollment("retrieve_user")
        original_secret = enrollment.secret

        # Retrieve via internal method
        retrieved = mfa_manager._get_secret("retrieve_user")

        assert retrieved == original_secret

    def test_verification_works_with_encrypted_secret(self, mfa_manager, initialized_key_manager):
        """TOTP verification should work with encrypted secrets."""
        import pyotp

        # Enroll and enable
        enrollment = mfa_manager.begin_enrollment("verify_user")
        secret = enrollment.secret

        # Generate valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Complete enrollment with valid code
        result = mfa_manager.complete_enrollment("verify_user", code)
        assert result is True

        # Verify with new code
        new_code = totp.now()
        is_valid = mfa_manager.verify_code("verify_user", new_code)
        assert is_valid is True


class TestLegacyBase64Secrets:
    """Test backward compatibility with legacy base64 secrets."""

    def test_legacy_secret_readable(self, tmp_path):
        """Legacy base64 secrets should still be readable."""
        import sqlite3

        from pdfsigner.core.auth.mfa.mfa_manager import MFAManager

        # Create MFA database with legacy format
        mfa_db = tmp_path / "legacy_mfa.db"
        conn = sqlite3.connect(mfa_db)
        cursor = conn.cursor()

        # Create schema
        cursor.execute(
            """
            CREATE TABLE mfa_secrets (
                user_id TEXT PRIMARY KEY,
                encrypted_secret TEXT NOT NULL,
                key_id TEXT NOT NULL,
                enabled INTEGER DEFAULT 0,
                enrolled_at TEXT,
                last_used_at TEXT
            )
        """
        )

        # Insert legacy base64 encoded secret
        legacy_secret = "JBSWY3DPEHPK3PXP"
        encoded = base64.b64encode(legacy_secret.encode()).decode()
        cursor.execute(
            "INSERT INTO mfa_secrets (user_id, encrypted_secret, key_id, enabled) VALUES (?, ?, ?, ?)",
            ("legacy_user", encoded, "base64", 1),
        )
        conn.commit()
        conn.close()

        # Create MFAManager and read secret
        manager = MFAManager(db_path=mfa_db)
        retrieved = manager._get_secret("legacy_user")

        assert retrieved == legacy_secret
