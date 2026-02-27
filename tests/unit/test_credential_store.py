"""
test_credential_store.py - Tests for encryption credential storage

Tests password storage, retrieval, deletion, and security features.
"""

import hashlib
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.encryption.credential_store import (
    EncryptionCredentialStore,
    get_encryption_credential_store,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_pdf_path(tmp_path):
    """Create temporary PDF path."""
    pdf_path = tmp_path / "test_document.pdf"
    pdf_path.write_text("dummy PDF content")
    return pdf_path


@pytest.fixture
def mock_credential_manager():
    """Mock credential manager for testing."""
    mock_manager = MagicMock()
    mock_manager.store_password.return_value = True
    mock_manager.get_password.return_value = None
    mock_manager.delete_password.return_value = True
    return mock_manager


@pytest.fixture
def credential_store(mock_credential_manager):
    """Create credential store with mocked manager."""
    store = EncryptionCredentialStore()
    store._credential_manager = mock_credential_manager
    return store


@pytest.fixture
def special_chars_path(tmp_path):
    """Path with special characters for security testing."""
    # Create nested directory with special chars
    special_dir = tmp_path / "docs (2024)" / "user@company.com"
    special_dir.mkdir(parents=True)
    pdf_path = special_dir / "report #123 [final].pdf"
    pdf_path.write_text("dummy content")
    return pdf_path


# ============================================================================
# store_password_for_file Tests
# ============================================================================


def test_store_password_for_file_user_password_success(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test storing user password succeeds."""
    result = credential_store.store_password_for_file(temp_pdf_path, "secret123")

    assert result is True
    mock_credential_manager.store_password.assert_called_once()
    call_args = mock_credential_manager.store_password.call_args
    key, password = call_args[0]
    assert password == "secret123"
    assert "_user" in key
    assert "test_document" in key


def test_store_password_for_file_owner_password_success(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test storing owner password succeeds."""
    result = credential_store.store_password_for_file(temp_pdf_path, "owner_secret", is_owner=True)

    assert result is True
    mock_credential_manager.store_password.assert_called_once()
    call_args = mock_credential_manager.store_password.call_args
    key, password = call_args[0]
    assert password == "owner_secret"
    assert "_owner" in key


def test_store_password_for_file_keyring_failure_returns_false(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test store returns False when keyring fails."""
    mock_credential_manager.store_password.return_value = False

    result = credential_store.store_password_for_file(temp_pdf_path, "password")

    assert result is False


def test_store_password_for_file_exception_propagates(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test store propagates exceptions to caller for visibility."""
    mock_credential_manager.store_password.side_effect = RuntimeError("Keyring error")

    with pytest.raises(RuntimeError, match="Keyring error"):
        credential_store.store_password_for_file(temp_pdf_path, "password")


@pytest.mark.parametrize(
    "password",
    [
        "simple",
        "with spaces",
        "special!@#$%^&*()",
        "unicode-密码-🔒",
        "very_long_" * 50,
        "",
    ],
)
def test_store_password_for_file_various_passwords(
    credential_store, mock_credential_manager, temp_pdf_path, password
):
    """Test storing various password formats."""
    result = credential_store.store_password_for_file(temp_pdf_path, password)

    assert result is True
    call_args = mock_credential_manager.store_password.call_args
    _, stored_password = call_args[0]
    assert stored_password == password


# ============================================================================
# get_password_for_file Tests
# ============================================================================


def test_get_password_for_file_found_returns_password(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test retrieving existing password succeeds."""
    mock_credential_manager.get_password.return_value = "stored_password"

    result = credential_store.get_password_for_file(temp_pdf_path)

    assert result == "stored_password"
    mock_credential_manager.get_password.assert_called_once()


def test_get_password_for_file_not_found_returns_none(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test retrieving non-existent password returns None."""
    mock_credential_manager.get_password.return_value = None

    result = credential_store.get_password_for_file(temp_pdf_path)

    assert result is None


def test_get_password_for_file_owner_uses_correct_key(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test getting owner password uses owner key."""
    mock_credential_manager.get_password.return_value = "owner_pass"

    result = credential_store.get_password_for_file(temp_pdf_path, is_owner=True)

    assert result == "owner_pass"
    call_args = mock_credential_manager.get_password.call_args
    key = call_args[0][0]
    assert "_owner" in key


def test_get_password_for_file_exception_returns_none(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test get returns None on exception."""
    mock_credential_manager.get_password.side_effect = RuntimeError("Keyring error")

    result = credential_store.get_password_for_file(temp_pdf_path)

    assert result is None


# ============================================================================
# delete_password_for_file Tests
# ============================================================================


def test_delete_password_for_file_success(credential_store, mock_credential_manager, temp_pdf_path):
    """Test deleting password succeeds."""
    result = credential_store.delete_password_for_file(temp_pdf_path)

    assert result is True
    mock_credential_manager.delete_password.assert_called_once()


def test_delete_password_for_file_owner_uses_correct_key(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test deleting owner password uses owner key."""
    result = credential_store.delete_password_for_file(temp_pdf_path, is_owner=True)

    assert result is True
    call_args = mock_credential_manager.delete_password.call_args
    key = call_args[0][0]
    assert "_owner" in key


def test_delete_password_for_file_keyring_failure_returns_false(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test delete returns False when keyring fails."""
    mock_credential_manager.delete_password.return_value = False

    result = credential_store.delete_password_for_file(temp_pdf_path)

    assert result is False


def test_delete_password_for_file_exception_returns_false(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test delete returns False on exception."""
    mock_credential_manager.delete_password.side_effect = RuntimeError("Keyring error")

    result = credential_store.delete_password_for_file(temp_pdf_path)

    assert result is False


# ============================================================================
# get_any_password_for_file Tests
# ============================================================================


def test_get_any_password_for_file_returns_owner_first(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test get_any returns owner password when available."""

    def mock_get(key):
        if "_owner" in key:
            return "owner_pass"
        return "user_pass"

    mock_credential_manager.get_password.side_effect = mock_get

    result = credential_store.get_any_password_for_file(temp_pdf_path)

    assert result == "owner_pass"


def test_get_any_password_for_file_falls_back_to_user(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test get_any falls back to user password."""

    def mock_get(key):
        if "_owner" in key:
            return None
        return "user_pass"

    mock_credential_manager.get_password.side_effect = mock_get

    result = credential_store.get_any_password_for_file(temp_pdf_path)

    assert result == "user_pass"
    # Should have tried both
    assert mock_credential_manager.get_password.call_count == 2


def test_get_any_password_for_file_none_found_returns_none(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test get_any returns None when no passwords found."""
    mock_credential_manager.get_password.return_value = None

    result = credential_store.get_any_password_for_file(temp_pdf_path)

    assert result is None
    # Should have tried both
    assert mock_credential_manager.get_password.call_count == 2


# ============================================================================
# _generate_key_for_file Tests
# ============================================================================


def test_generate_key_for_file_includes_filename(credential_store, temp_pdf_path):
    """Test generated key includes filename stem."""
    key = credential_store._generate_key_for_file(temp_pdf_path, is_owner=False)

    assert "test_document" in key
    assert key.startswith("pdfsigner_encrypt_")


def test_generate_key_for_file_includes_hash(credential_store, temp_pdf_path):
    """Test generated key includes path hash."""
    key = credential_store._generate_key_for_file(temp_pdf_path, is_owner=False)

    # Key format: pdfsigner_encrypt_{filename}_{hash}_{type}
    # Hash should be 16 hex chars before the final _user or _owner
    assert key.startswith("pdfsigner_encrypt_")
    assert key.endswith("_user")

    # Extract the hash (16 hex chars before _user/_owner)
    # Find last occurrence of 16 hex chars

    hash_pattern = r"([0-9a-f]{16})_(user|owner)$"
    match = re.search(hash_pattern, key)
    assert match is not None
    assert len(match.group(1)) == 16


def test_generate_key_for_file_different_for_owner_and_user(credential_store, temp_pdf_path):
    """Test owner and user keys are different."""
    user_key = credential_store._generate_key_for_file(temp_pdf_path, is_owner=False)
    owner_key = credential_store._generate_key_for_file(temp_pdf_path, is_owner=True)

    assert user_key != owner_key
    assert "_user" in user_key
    assert "_owner" in owner_key


def test_generate_key_for_file_collision_different_paths(credential_store, tmp_path):
    """Test different paths generate different keys (no hash collision)."""
    path1 = tmp_path / "doc1.pdf"
    path2 = tmp_path / "doc2.pdf"
    path1.write_text("content1")
    path2.write_text("content2")

    key1 = credential_store._generate_key_for_file(path1, is_owner=False)
    key2 = credential_store._generate_key_for_file(path2, is_owner=False)

    assert key1 != key2


def test_generate_key_for_file_same_filename_different_dirs(credential_store, tmp_path):
    """Test same filename in different directories generates different keys."""
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()

    path1 = dir1 / "document.pdf"
    path2 = dir2 / "document.pdf"
    path1.write_text("content")
    path2.write_text("content")

    key1 = credential_store._generate_key_for_file(path1, is_owner=False)
    key2 = credential_store._generate_key_for_file(path2, is_owner=False)

    assert key1 != key2
    # Both should have 'document' in them but different hashes
    assert "document" in key1
    assert "document" in key2


def test_generate_key_for_file_deterministic(credential_store, temp_pdf_path):
    """Test key generation is deterministic."""
    key1 = credential_store._generate_key_for_file(temp_pdf_path, is_owner=False)
    key2 = credential_store._generate_key_for_file(temp_pdf_path, is_owner=False)

    assert key1 == key2


# ============================================================================
# Security Tests
# ============================================================================


@pytest.mark.security
def test_security_password_not_in_key(credential_store, temp_pdf_path):
    """Test password is not embedded in generated key."""
    password = "super_secret_password_123"
    credential_store.store_password_for_file(temp_pdf_path, password)

    key = credential_store._generate_key_for_file(temp_pdf_path, is_owner=False)

    assert password not in key
    assert "secret" not in key.lower()


@pytest.mark.security
def test_security_special_chars_in_path(credential_store, special_chars_path):
    """Test handling paths with special characters."""
    result = credential_store.store_password_for_file(special_chars_path, "test_password")

    assert result is True
    key = credential_store._generate_key_for_file(special_chars_path, is_owner=False)
    # Should have sanitized filename but maintain uniqueness
    assert "pdfsigner_encrypt_" in key


@pytest.mark.security
def test_security_absolute_path_used_for_hash(credential_store, tmp_path):
    """Test absolute path is used for hash generation (prevents collision)."""
    # Create file and get key
    pdf_path = tmp_path / "document.pdf"
    pdf_path.write_text("content")

    # Generate key using relative path (should resolve to absolute)
    relative_path = Path("document.pdf")
    key1 = credential_store._generate_key_for_file(pdf_path, is_owner=False)

    # Verify hash is based on absolute path
    path_str = str(pdf_path.absolute())
    expected_hash = hashlib.sha256(path_str.encode()).hexdigest()[:16]

    assert expected_hash in key1


@pytest.mark.security
def test_security_unicode_in_password(credential_store, mock_credential_manager, temp_pdf_path):
    """Test handling Unicode characters in password."""
    unicode_password = "密码🔒key"

    result = credential_store.store_password_for_file(temp_pdf_path, unicode_password)

    assert result is True
    call_args = mock_credential_manager.store_password.call_args
    _, stored = call_args[0]
    assert stored == unicode_password


# ============================================================================
# Singleton Tests
# ============================================================================


def test_get_encryption_credential_store_returns_singleton():
    """Test singleton returns same instance."""
    store1 = get_encryption_credential_store()
    store2 = get_encryption_credential_store()

    assert store1 is store2


def test_get_encryption_credential_store_creates_instance():
    """Test singleton creates instance on first call."""
    # Reset singleton
    import pdfsigner.core.encryption.credential_store as module

    module._credential_store = None

    store = get_encryption_credential_store()

    assert store is not None
    assert isinstance(store, EncryptionCredentialStore)


# ============================================================================
# Integration-style Tests
# ============================================================================


def test_integration_full_lifecycle(credential_store, mock_credential_manager, temp_pdf_path):
    """Test complete store-retrieve-delete lifecycle."""
    # Store
    store_result = credential_store.store_password_for_file(temp_pdf_path, "my_password")
    assert store_result is True

    # Retrieve
    mock_credential_manager.get_password.return_value = "my_password"
    retrieved = credential_store.get_password_for_file(temp_pdf_path)
    assert retrieved == "my_password"

    # Delete
    delete_result = credential_store.delete_password_for_file(temp_pdf_path)
    assert delete_result is True


def test_integration_owner_and_user_separate(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test owner and user passwords are stored separately."""
    # Store both
    credential_store.store_password_for_file(temp_pdf_path, "user_pass", is_owner=False)
    credential_store.store_password_for_file(temp_pdf_path, "owner_pass", is_owner=True)

    # Both should be called with different keys
    assert mock_credential_manager.store_password.call_count == 2

    calls = mock_credential_manager.store_password.call_args_list
    keys = [call[0][0] for call in calls]

    assert len(set(keys)) == 2  # Two different keys
    assert any("_user" in k for k in keys)
    assert any("_owner" in k for k in keys)


# ============================================================================
# Error Propagation Tests
# ============================================================================


def test_store_password_propagates_os_error(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test store_password_for_file propagates OSError from keyring."""
    mock_credential_manager.store_password.side_effect = OSError("Keyring backend unavailable")

    with pytest.raises(OSError, match="Keyring backend unavailable"):
        credential_store.store_password_for_file(temp_pdf_path, "password")


def test_get_password_swallows_exception_returns_none(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test get_password_for_file returns None on exception (fallback to asking user)."""
    mock_credential_manager.get_password.side_effect = OSError("Keyring backend unavailable")

    result = credential_store.get_password_for_file(temp_pdf_path)

    assert result is None


def test_delete_password_swallows_exception_returns_false(
    credential_store, mock_credential_manager, temp_pdf_path
):
    """Test delete_password_for_file returns False on exception (best effort)."""
    mock_credential_manager.delete_password.side_effect = OSError("Keyring backend unavailable")

    result = credential_store.delete_password_for_file(temp_pdf_path)

    assert result is False


# ============================================================================
# Lazy Loading Tests
# ============================================================================


def test_lazy_loading_credential_manager(temp_pdf_path):
    """Test credential manager is lazy-loaded."""
    store = EncryptionCredentialStore()
    assert store._credential_manager is None

    # Access property triggers lazy load
    with patch("pdfsigner.core.encryption.credential_store.get_credential_manager") as mock_get:
        mock_manager = MagicMock()
        mock_get.return_value = mock_manager

        manager = store.credential_manager

        assert manager is mock_manager
        mock_get.assert_called_once()
        assert store._credential_manager is mock_manager
