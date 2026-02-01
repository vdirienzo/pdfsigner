"""
test_key_manager.py - Tests for KeyManager

Tests secure key storage, rotation, revocation, and expiration.
"""

import json
import secrets
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from pdfsigner.core.crypto.key_manager import (
    KeyExpiredError,
    KeyInfo,
    KeyManager,
    KeyNotFoundError,
    KeyRevokedError,
    KeyStatus,
    KeyType,
    get_key_manager,
    init_key_manager,
)


@pytest.fixture
def temp_db() -> Path:
    """Create temporary database path."""
    import tempfile

    # Create temp directory
    temp_dir = tempfile.gettempdir()
    path = Path(temp_dir) / f"test_keymanager_{secrets.token_hex(8)}.db"

    yield path
    # Cleanup
    if path.exists():
        path.unlink()


@pytest.fixture
def key_manager(temp_db: Path) -> KeyManager:
    """Create KeyManager instance with test database."""
    return KeyManager(temp_db, "test-master-password-123")


@pytest.fixture
def initialized_singleton(temp_db: Path) -> KeyManager:
    """Initialize singleton KeyManager for testing."""
    return init_key_manager(temp_db, "test-master-password-456")


class TestKeyManagerInit:
    """Test KeyManager initialization."""

    def test_init_creates_database(self, temp_db: Path):
        """Test that initialization creates database file."""
        assert not temp_db.exists()
        KeyManager(temp_db, "test-password")
        assert temp_db.exists()

    def test_init_creates_tables(self, key_manager: KeyManager):
        """Test that initialization creates required tables."""
        import sqlite3

        conn = sqlite3.connect(key_manager.db_path)
        cursor = conn.cursor()

        # Check metadata table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
        assert cursor.fetchone() is not None

        # Check keys table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
        assert cursor.fetchone() is not None

        conn.close()

    def test_init_stores_master_salt(self, key_manager: KeyManager):
        """Test that master salt is stored in metadata."""
        import sqlite3

        conn = sqlite3.connect(key_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = 'master_salt'")
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert len(bytes.fromhex(row[0])) == KeyManager.SALT_LENGTH

    def test_init_empty_password_fails(self, temp_db: Path):
        """Test that empty master password raises ValueError."""
        with pytest.raises(ValueError, match="Master password cannot be empty"):
            KeyManager(temp_db, "")


class TestKeyGeneration:
    """Test key generation functionality."""

    def test_generate_symmetric_key(self, key_manager: KeyManager):
        """Test generating symmetric key."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)

        assert key_id is not None
        assert len(key_id) > 0

        # Verify key can be retrieved
        key_bytes = key_manager.get_key(key_id)
        assert len(key_bytes) == 32  # 256 bits = 32 bytes

    def test_generate_hmac_key(self, key_manager: KeyManager):
        """Test generating HMAC key."""
        key_id = key_manager.generate_key(KeyType.HMAC, "HMAC-SHA256", key_size=256)

        key_bytes = key_manager.get_key(key_id)
        assert len(key_bytes) == 32

    def test_generate_key_with_expiration(self, key_manager: KeyManager):
        """Test generating key with expiration."""
        key_id = key_manager.generate_key(
            KeyType.SYMMETRIC, "AES-256", key_size=256, expires_days=30
        )

        info = key_manager._get_key_info_from_db(key_id)
        assert info.expires_at is not None
        assert info.expires_at > datetime.now()
        assert info.expires_at < datetime.now() + timedelta(days=31)

    def test_generate_key_with_metadata(self, key_manager: KeyManager):
        """Test generating key with custom metadata."""
        metadata = {"purpose": "test", "owner": "admin"}
        key_id = key_manager.generate_key(
            KeyType.SYMMETRIC, "AES-256", key_size=256, metadata=metadata
        )

        info = key_manager._get_key_info_from_db(key_id)
        assert info.metadata == metadata

    def test_generate_key_invalid_size_fails(self, key_manager: KeyManager):
        """Test that invalid key size raises ValueError."""
        with pytest.raises(ValueError, match="Key size must be at least 128 bits"):
            key_manager.generate_key(KeyType.SYMMETRIC, "AES", key_size=64)


class TestKeyRetrieval:
    """Test key retrieval functionality."""

    def test_get_key_returns_correct_bytes(self, key_manager: KeyManager):
        """Test that retrieved key matches generated key."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_bytes = key_manager.get_key(key_id)

        # Retrieve again
        key_bytes2 = key_manager.get_key(key_id)

        # Should be identical
        assert key_bytes == key_bytes2

    def test_get_key_nonexistent_fails(self, key_manager: KeyManager):
        """Test that retrieving nonexistent key raises KeyNotFoundError."""
        with pytest.raises(KeyNotFoundError, match="not found"):
            key_manager.get_key("nonexistent-key-id")

    def test_get_revoked_key_fails(self, key_manager: KeyManager):
        """Test that retrieving revoked key raises KeyRevokedError."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_manager.revoke_key(key_id)

        with pytest.raises(KeyRevokedError, match="revoked"):
            key_manager.get_key(key_id)

    def test_get_expired_key_fails(self, key_manager: KeyManager):
        """Test that retrieving expired key raises KeyExpiredError."""
        import sqlite3
        from datetime import datetime, timedelta

        # Generate key with normal expiration
        key_id = key_manager.generate_key(
            KeyType.SYMMETRIC, "AES-256", key_size=256, expires_days=30
        )

        # Manually set expiration to past
        conn = sqlite3.connect(key_manager.db_path)
        cursor = conn.cursor()
        past_date = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute("UPDATE keys SET expires_at = ? WHERE key_id = ?", (past_date, key_id))
        conn.commit()
        conn.close()

        # Should be expired
        with pytest.raises(KeyExpiredError, match="expired"):
            key_manager.get_key(key_id)


class TestKeyRotation:
    """Test key rotation functionality."""

    def test_rotate_key_creates_new_key(self, key_manager: KeyManager):
        """Test that key rotation creates new key."""
        old_key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        new_key_id = key_manager.rotate_key(old_key_id)

        assert new_key_id != old_key_id

        # Both keys should exist
        old_key = key_manager.get_key(old_key_id)
        new_key = key_manager.get_key(new_key_id)

        # Keys should be different
        assert old_key != new_key

    def test_rotate_key_marks_old_as_rotated(self, key_manager: KeyManager):
        """Test that old key is marked as rotated."""
        old_key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_manager.rotate_key(old_key_id)

        old_info = key_manager._get_key_info_from_db(old_key_id)
        assert old_info.status == KeyStatus.ROTATED

    def test_rotate_key_preserves_algorithm(self, key_manager: KeyManager):
        """Test that rotated key has same algorithm."""
        old_key_id = key_manager.generate_key(KeyType.HMAC, "HMAC-SHA512", key_size=512)
        new_key_id = key_manager.rotate_key(old_key_id)

        new_info = key_manager._get_key_info_from_db(new_key_id)
        old_info = key_manager._get_key_info_from_db(old_key_id)

        assert new_info.algorithm == old_info.algorithm
        assert new_info.key_type == old_info.key_type

    def test_rotate_key_nonexistent_fails(self, key_manager: KeyManager):
        """Test that rotating nonexistent key raises KeyNotFoundError."""
        with pytest.raises(KeyNotFoundError):
            key_manager.rotate_key("nonexistent-key-id")


class TestKeyRevocation:
    """Test key revocation functionality."""

    def test_revoke_key_marks_as_revoked(self, key_manager: KeyManager):
        """Test that revocation marks key as revoked."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        result = key_manager.revoke_key(key_id)

        assert result is True

        info = key_manager._get_key_info_from_db(key_id)
        assert info.status == KeyStatus.REVOKED

    def test_revoke_key_idempotent(self, key_manager: KeyManager):
        """Test that revoking already revoked key succeeds."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_manager.revoke_key(key_id)
        result = key_manager.revoke_key(key_id)

        assert result is True

    def test_revoke_key_prevents_retrieval(self, key_manager: KeyManager):
        """Test that revoked key cannot be retrieved."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_manager.revoke_key(key_id)

        with pytest.raises(KeyRevokedError):
            key_manager.get_key(key_id)


class TestKeyListing:
    """Test key listing functionality."""

    def test_list_keys_returns_all(self, key_manager: KeyManager):
        """Test listing all keys."""
        key_id1 = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_id2 = key_manager.generate_key(KeyType.HMAC, "HMAC-SHA256", key_size=256)

        keys = key_manager.list_keys()

        assert len(keys) == 2
        key_ids = [k.key_id for k in keys]
        assert key_id1 in key_ids
        assert key_id2 in key_ids

    def test_list_keys_filter_by_type(self, key_manager: KeyManager):
        """Test filtering keys by type."""
        key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        hmac_id = key_manager.generate_key(KeyType.HMAC, "HMAC-SHA256", key_size=256)

        keys = key_manager.list_keys(key_type=KeyType.HMAC)

        assert len(keys) == 1
        assert keys[0].key_id == hmac_id

    def test_list_keys_filter_by_status(self, key_manager: KeyManager):
        """Test filtering keys by status."""
        active_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        revoked_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        key_manager.revoke_key(revoked_id)

        active_keys = key_manager.list_keys(status=KeyStatus.ACTIVE)
        revoked_keys = key_manager.list_keys(status=KeyStatus.REVOKED)

        assert len(active_keys) == 1
        assert active_keys[0].key_id == active_id

        assert len(revoked_keys) == 1
        assert revoked_keys[0].key_id == revoked_id


class TestKeyExportImport:
    """Test key export and import functionality."""

    def test_export_key_returns_encrypted_data(self, key_manager: KeyManager):
        """Test that export returns encrypted data."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        export_data = key_manager.export_key(key_id, "export-password-123")

        assert isinstance(export_data, bytes)
        assert len(export_data) > 0

        # Should be JSON
        package = json.loads(export_data.decode())
        assert "salt" in package
        assert "data" in package

    def test_export_import_roundtrip(self, key_manager: KeyManager):
        """Test exporting and importing key."""
        original_key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        original_key_bytes = key_manager.get_key(original_key_id)

        # Export
        export_data = key_manager.export_key(original_key_id, "export-password-123")

        # Import to new manager
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            new_db_path = Path(f.name)

        try:
            new_manager = KeyManager(new_db_path, "different-master-password")
            imported_key_id = new_manager.import_key(
                export_data, "export-password-123", KeyType.SYMMETRIC, "AES-256"
            )

            imported_key_bytes = new_manager.get_key(imported_key_id)

            # Key material should be identical
            assert imported_key_bytes == original_key_bytes
        finally:
            if new_db_path.exists():
                new_db_path.unlink()

    def test_import_wrong_password_fails(self, key_manager: KeyManager):
        """Test that import with wrong password fails."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        export_data = key_manager.export_key(key_id, "correct-password")

        with pytest.raises(ValueError, match="Failed to import key"):
            key_manager.import_key(export_data, "wrong-password", KeyType.SYMMETRIC, "AES-256")

    def test_import_type_mismatch_fails(self, key_manager: KeyManager):
        """Test that import with wrong type fails."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)
        export_data = key_manager.export_key(key_id, "password")

        with pytest.raises(ValueError, match="Key type mismatch"):
            key_manager.import_key(export_data, "password", KeyType.HMAC, "AES-256")

    def test_export_empty_password_fails(self, key_manager: KeyManager):
        """Test that export with empty password fails."""
        key_id = key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256)

        with pytest.raises(ValueError, match="Export password cannot be empty"):
            key_manager.export_key(key_id, "")


class TestKeyCleanup:
    """Test key cleanup functionality."""

    def test_cleanup_expired_marks_keys(self, key_manager: KeyManager):
        """Test that cleanup marks expired keys."""
        import sqlite3
        from datetime import datetime, timedelta

        # Generate key
        expired_key_id = key_manager.generate_key(
            KeyType.SYMMETRIC, "AES-256", key_size=256, expires_days=30
        )

        # Manually expire it
        conn = sqlite3.connect(key_manager.db_path)
        cursor = conn.cursor()
        past_date = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute(
            "UPDATE keys SET expires_at = ? WHERE key_id = ?", (past_date, expired_key_id)
        )
        conn.commit()
        conn.close()

        # Generate active key
        key_manager.generate_key(KeyType.SYMMETRIC, "AES-256", key_size=256, expires_days=365)

        count = key_manager.cleanup_expired()

        # Should have marked 1 key as expired
        assert count >= 1

    def test_cleanup_expired_returns_count(self, key_manager: KeyManager):
        """Test that cleanup returns correct count."""
        import sqlite3
        from datetime import datetime, timedelta

        # Generate multiple keys and manually expire them
        expired_keys = []
        for _ in range(3):
            key_id = key_manager.generate_key(
                KeyType.SYMMETRIC, "AES-256", key_size=256, expires_days=30
            )
            expired_keys.append(key_id)

        # Manually expire all of them
        conn = sqlite3.connect(key_manager.db_path)
        cursor = conn.cursor()
        past_date = (datetime.now() - timedelta(days=1)).isoformat()
        for key_id in expired_keys:
            cursor.execute("UPDATE keys SET expires_at = ? WHERE key_id = ?", (past_date, key_id))
        conn.commit()
        conn.close()

        count = key_manager.cleanup_expired()
        assert count >= 3


class TestSingletonPattern:
    """Test singleton functionality."""

    def test_get_key_manager_before_init_fails(self):
        """Test that get_key_manager fails before initialization."""
        # Reset singleton
        import pdfsigner.core.crypto.key_manager as km_module

        km_module._key_manager = None

        with pytest.raises(RuntimeError, match="not initialized"):
            get_key_manager()

    def test_init_key_manager_returns_instance(self, temp_db: Path):
        """Test that init_key_manager returns KeyManager instance."""
        manager = init_key_manager(temp_db, "test-password")
        assert isinstance(manager, KeyManager)

    def test_get_key_manager_returns_singleton(self, initialized_singleton: KeyManager):
        """Test that get_key_manager returns same instance."""
        manager1 = get_key_manager()
        manager2 = get_key_manager()

        assert manager1 is manager2
        assert manager1 is initialized_singleton


class TestKeyInfo:
    """Test KeyInfo dataclass."""

    def test_key_info_to_dict(self):
        """Test KeyInfo serialization to dict."""
        info = KeyInfo(
            key_id="test-id",
            key_type=KeyType.SYMMETRIC,
            algorithm="AES-256",
            status=KeyStatus.ACTIVE,
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            expires_at=datetime(2025, 1, 1, 12, 0, 0),
            rotated_from=None,
            metadata={"test": "value"},
        )

        data = info.to_dict()

        assert data["key_id"] == "test-id"
        assert data["key_type"] == "symmetric"
        assert data["algorithm"] == "AES-256"
        assert data["status"] == "active"
        assert data["created_at"] == "2024-01-01T12:00:00"
        assert data["expires_at"] == "2025-01-01T12:00:00"
        assert data["metadata"] == {"test": "value"}

    def test_key_info_from_dict(self):
        """Test KeyInfo deserialization from dict."""
        data = {
            "key_id": "test-id",
            "key_type": "hmac",
            "algorithm": "HMAC-SHA256",
            "status": "rotated",
            "created_at": "2024-01-01T12:00:00",
            "expires_at": "2025-01-01T12:00:00",
            "rotated_from": "old-key-id",
            "metadata": {"test": "value"},
        }

        info = KeyInfo.from_dict(data)

        assert info.key_id == "test-id"
        assert info.key_type == KeyType.HMAC
        assert info.algorithm == "HMAC-SHA256"
        assert info.status == KeyStatus.ROTATED
        assert info.metadata == {"test": "value"}


class TestPBKDF2Security:
    """Test PBKDF2 security parameters."""

    def test_pbkdf2_high_iterations(self, key_manager: KeyManager):
        """Test that PBKDF2 uses secure iteration count."""
        assert key_manager.PBKDF2_ITERATIONS >= 480000

    def test_pbkdf2_salt_length(self, key_manager: KeyManager):
        """Test that salt length is secure."""
        assert key_manager.SALT_LENGTH == 32
