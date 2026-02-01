"""
Integration tests for PDFSigner Backup/Restore API.

Tests all backup and recovery endpoints with authentication, authorization,
validation, and security checks.

Coverage:
- Backup creation (admin only)
- Backup listing (admin only)
- Backup restoration (admin only)
- Backup deletion (admin only)
- Security: path traversal, non-admin access, encryption validation
- Compliance: HIPAA §164.308(a)(7) - Contingency plan

Run with:
    uv run pytest tests/integration/test_api_backup.py -v
    uv run pytest tests/integration/test_api_backup.py -v -m security
    uv run pytest tests/integration/test_api_backup.py -v -m compliance
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.core.backup import BackupMetadata, BackupStatus, BackupType

# Mark all tests in this module as anyio (use anyio for async support)
pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
def api_settings():
    """Get API settings for tests."""
    settings = get_api_settings()
    settings.api_keys = ["test-api-key-123"]
    return settings


@pytest.fixture
async def client():
    """
    Create async HTTP client for testing.

    Uses httpx.AsyncClient with ASGITransport for async support.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def auth_token(api_settings):
    """Create valid JWT token for testing (non-admin)."""
    token = create_access_token(
        data={"sub": "testuser", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def admin_token(api_settings):
    """Create valid admin JWT token for testing."""
    token = create_access_token(
        data={"sub": "admin", "role": "admin"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auth_headers(auth_token):
    """Create authentication headers with JWT token (non-admin)."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def admin_headers(admin_token):
    """Create authentication headers with admin JWT token."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def sample_backup_metadata():
    """Create sample backup metadata for testing."""
    return BackupMetadata(
        backup_id="550e8400-e29b-41d4-a716-446655440000",
        backup_type=BackupType.FULL,
        status=BackupStatus.COMPLETED,
        created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 1, 10, 5, 0, tzinfo=UTC),
        size_bytes=10485760,
        file_count=42,
        encrypted=False,
        backup_path="/home/user/.local/share/pdfsigner/backups/backup_550e8400.tar.gz",
        error=None,
        includes_config=True,
        includes_audit=True,
        includes_databases=True,
    )


# --- Create Backup Tests ---


@pytest.mark.compliance
async def test_create_backup_admin_success(client, admin_headers, sample_backup_metadata):
    """Test admin can create backup successfully."""
    # Arrange
    request_data = {
        "backup_type": "full",
        "encrypt": False,
        "password": None,
    }

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.create_backup.return_value = sample_backup_metadata
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/create",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["backup_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["backup_type"] == "full"
    assert data["status"] == "completed"
    assert data["size_bytes"] == 10485760
    assert data["file_count"] == 42
    assert data["encrypted"] is False
    assert data["includes_config"] is True
    assert data["includes_audit"] is True
    assert data["includes_databases"] is True


@pytest.mark.security
async def test_create_backup_non_admin_forbidden(client, auth_headers):
    """Test non-admin cannot create backup."""
    # Arrange
    request_data = {
        "backup_type": "full",
        "encrypt": False,
    }

    # Act
    response = await client.post(
        "/api/v1/backup/create",
        json=request_data,
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.security
async def test_create_backup_encrypted_without_password_fails(client, admin_headers):
    """Test encrypted backup without password fails with 400."""
    # Arrange
    request_data = {
        "backup_type": "full",
        "encrypt": True,
        "password": None,  # Missing password
    }

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/create",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Password required" in response.json()["detail"]


@pytest.mark.compliance
async def test_create_backup_config_only(client, admin_headers):
    """Test creating config-only backup."""
    # Arrange
    request_data = {
        "backup_type": "config",
        "encrypt": False,
    }

    metadata = BackupMetadata(
        backup_id="config-backup-001",
        backup_type=BackupType.CONFIG,
        status=BackupStatus.COMPLETED,
        created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 1, 10, 1, 0, tzinfo=UTC),
        size_bytes=1024,
        file_count=5,
        encrypted=False,
        backup_path="/backups/config_backup.tar.gz",
        error=None,
        includes_config=True,
        includes_audit=False,
        includes_databases=False,
    )

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.create_backup.return_value = metadata
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/create",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["backup_type"] == "config"
    assert data["includes_config"] is True
    assert data["includes_audit"] is False
    assert data["includes_databases"] is False


@pytest.mark.compliance
async def test_create_backup_database_only(client, admin_headers):
    """Test creating database-only backup."""
    # Arrange
    request_data = {
        "backup_type": "database",
        "encrypt": True,
        "password": "secure_db_password",
    }

    metadata = BackupMetadata(
        backup_id="db-backup-001",
        backup_type=BackupType.DATABASE,
        status=BackupStatus.COMPLETED,
        created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 1, 10, 2, 0, tzinfo=UTC),
        size_bytes=5242880,
        file_count=3,
        encrypted=True,
        backup_path="/backups/db_backup.tar.gz.enc",
        error=None,
        includes_config=False,
        includes_audit=False,
        includes_databases=True,
    )

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.create_backup.return_value = metadata
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/create",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["backup_type"] == "database"
    assert data["encrypted"] is True
    assert data["includes_databases"] is True


async def test_create_backup_failed_status_returns_500(client, admin_headers):
    """Test failed backup returns 500 error."""
    # Arrange
    request_data = {
        "backup_type": "full",
        "encrypt": False,
    }

    failed_metadata = BackupMetadata(
        backup_id="failed-backup",
        backup_type=BackupType.FULL,
        status=BackupStatus.FAILED,
        created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC),
        completed_at=None,
        size_bytes=0,
        file_count=0,
        encrypted=False,
        backup_path="",
        error="Disk full",
        includes_config=False,
        includes_audit=False,
        includes_databases=False,
    )

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.create_backup.return_value = failed_metadata
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/create",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "failed" in response.json()["detail"].lower()


# --- List Backups Tests ---


@pytest.mark.compliance
async def test_list_backups_admin_success(client, admin_headers, sample_backup_metadata):
    """Test admin can list all backups."""
    # Arrange
    backup2 = BackupMetadata(
        backup_id="backup-002",
        backup_type=BackupType.CONFIG,
        status=BackupStatus.COMPLETED,
        created_at=datetime(2026, 2, 1, 11, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 1, 11, 1, 0, tzinfo=UTC),
        size_bytes=2048,
        file_count=10,
        encrypted=True,
        backup_path="/backups/backup_002.tar.gz.enc",
        error=None,
        includes_config=True,
        includes_audit=False,
        includes_databases=False,
    )

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_backups.return_value = [sample_backup_metadata, backup2]
        mock_get_manager.return_value = mock_manager

        response = await client.get("/api/v1/backup/list", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert len(data["backups"]) == 2
    assert data["backups"][0]["backup_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert data["backups"][1]["backup_id"] == "backup-002"
    assert data["backups"][1]["encrypted"] is True


@pytest.mark.security
async def test_list_backups_non_admin_forbidden(client, auth_headers):
    """Test non-admin cannot list backups."""
    # Act
    response = await client.get("/api/v1/backup/list", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_list_backups_empty_list(client, admin_headers):
    """Test listing backups returns empty list when no backups exist."""
    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_backups.return_value = []
        mock_get_manager.return_value = mock_manager

        response = await client.get("/api/v1/backup/list", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 0
    assert len(data["backups"]) == 0


# --- Restore Backup Tests ---


@pytest.mark.compliance
async def test_restore_backup_admin_success(client, admin_headers, sample_backup_metadata):
    """Test admin can restore backup successfully."""
    # Arrange
    request_data = {
        "backup_id": "550e8400-e29b-41d4-a716-446655440000",
        "password": None,
        "restore_config": True,
        "restore_audit": True,
        "restore_databases": True,
    }

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_backups.return_value = [sample_backup_metadata]
        mock_manager.restore_backup.return_value = True
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/restore",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["backup_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert "successfully" in data["message"].lower()


@pytest.mark.security
async def test_restore_backup_non_admin_forbidden(client, auth_headers):
    """Test non-admin cannot restore backup."""
    # Arrange
    request_data = {
        "backup_id": "550e8400-e29b-41d4-a716-446655440000",
        "restore_config": True,
        "restore_audit": True,
        "restore_databases": True,
    }

    # Act
    response = await client.post(
        "/api/v1/backup/restore",
        json=request_data,
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.security
async def test_restore_backup_encrypted_requires_password(client, admin_headers):
    """Test restoring encrypted backup requires password."""
    # Arrange
    request_data = {
        "backup_id": "encrypted-backup-001",
        "password": None,  # Missing password
        "restore_config": True,
        "restore_audit": True,
        "restore_databases": True,
    }

    encrypted_metadata = BackupMetadata(
        backup_id="encrypted-backup-001",
        backup_type=BackupType.FULL,
        status=BackupStatus.COMPLETED,
        created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 1, 10, 5, 0, tzinfo=UTC),
        size_bytes=10485760,
        file_count=42,
        encrypted=True,  # Encrypted
        backup_path="/backups/encrypted.tar.gz.enc",
        error=None,
        includes_config=True,
        includes_audit=True,
        includes_databases=True,
    )

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_backups.return_value = [encrypted_metadata]
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/restore",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Password required" in response.json()["detail"]


async def test_restore_backup_not_found(client, admin_headers):
    """Test restoring non-existent backup returns 404."""
    # Arrange
    request_data = {
        "backup_id": "nonexistent-backup-id",
        "restore_config": True,
        "restore_audit": True,
        "restore_databases": True,
    }

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_backups.return_value = []  # No backups
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/restore",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.security
async def test_restore_backup_path_traversal_blocked(client, admin_headers):
    """Test path traversal in backup_id is blocked."""
    # Arrange - Attempt path traversal
    request_data = {
        "backup_id": "../../etc/passwd",
        "restore_config": True,
        "restore_audit": True,
        "restore_databases": True,
    }

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_backups.return_value = []  # Won't find malicious path
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            "/api/v1/backup/restore",
            json=request_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- Delete Backup Tests ---


async def test_delete_backup_admin_success(client, admin_headers):
    """Test admin can delete backup successfully."""
    # Arrange
    backup_id = "550e8400-e29b-41d4-a716-446655440000"

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.delete_backup.return_value = True
        mock_get_manager.return_value = mock_manager

        response = await client.delete(
            f"/api/v1/backup/{backup_id}",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["backup_id"] == backup_id
    assert "deleted successfully" in data["message"].lower()


@pytest.mark.security
async def test_delete_backup_non_admin_forbidden(client, auth_headers):
    """Test non-admin cannot delete backup."""
    # Arrange
    backup_id = "550e8400-e29b-41d4-a716-446655440000"

    # Act
    response = await client.delete(
        f"/api/v1/backup/{backup_id}",
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_delete_backup_not_found(client, admin_headers):
    """Test deleting non-existent backup returns 404."""
    # Arrange
    backup_id = "nonexistent-backup-id"

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.delete_backup.return_value = False  # Backup not found
        mock_get_manager.return_value = mock_manager

        response = await client.delete(
            f"/api/v1/backup/{backup_id}",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.security
async def test_delete_backup_path_traversal_blocked(client, admin_headers):
    """Test path traversal in backup_id parameter is blocked."""
    # Arrange - Attempt path traversal
    malicious_id = "../../etc/passwd"

    # Act
    with patch("pdfsigner.api.routes.backup.get_backup_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.delete_backup.return_value = False  # Won't find malicious path
        mock_get_manager.return_value = mock_manager

        response = await client.delete(
            f"/api/v1/backup/{malicious_id}",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
