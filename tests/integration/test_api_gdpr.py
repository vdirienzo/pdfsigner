"""
Integration tests for GDPR API.

Tests GDPR data rights endpoints (Article 17, Article 20).

Run with:
    uv run pytest tests/integration/test_api_gdpr.py -v
    uv run pytest tests/integration/test_api_gdpr.py -v --cov=src/pdfsigner/api/routes/gdpr
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token

# Mark all tests as anyio and compliance
pytestmark = [pytest.mark.anyio, pytest.mark.compliance]


# --- Fixtures ---


@pytest.fixture
def enable_healthcare_mode():
    """Enable healthcare mode for RBAC testing."""
    from pdfsigner.config.settings import get_settings

    settings = get_settings()
    original_mode = settings.healthcare_mode
    settings.healthcare_mode = True
    yield
    settings.healthcare_mode = original_mode


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def user_token():
    """Create valid JWT token with user role."""
    token = create_access_token(
        data={"sub": "testuser", "user_id": "user-123", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def user_headers(user_token):
    """Create authentication headers with user JWT token."""
    return {"Authorization": f"Bearer {user_token}"}


@pytest.fixture
def admin_token():
    """Create valid JWT token with admin role."""
    token = create_access_token(
        data={"sub": "admin", "user_id": "admin-123", "role": "admin"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def admin_headers(admin_token):
    """Create authentication headers with admin JWT token."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def mock_user():
    """Create mock regular user for testing with healthcare_mode."""
    from pdfsigner.core.users import User, UserRole, UserStatus

    return User(
        id="user-123",
        username="testuser",
        display_name="Test User",
        email="testuser@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
        created_at=datetime.now(UTC),
        certificate_serial="TEST123",
        certificate_issuer="CN=TestCA",
    )


@pytest.fixture
def mock_admin():
    """Create mock admin user for testing with healthcare_mode."""
    from pdfsigner.core.users import User, UserRole, UserStatus

    return User(
        id="admin-123",
        username="admin",
        display_name="Admin User",
        email="admin@example.com",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
        created_at=datetime.now(UTC),
        certificate_serial="ADMIN456",
        certificate_issuer="CN=TestCA",
    )


# --- Data Export Tests (GDPR Article 20) ---


async def test_export_user_data_own_data(client, user_headers):
    """Test user can export their own data."""
    # Arrange
    user_id = "user-123"

    # Act - Mock data exporter
    with patch("pdfsigner.api.services.gdpr_service.get_user_data_exporter") as mock_exporter:
        mock_instance = Mock()
        mock_export = Mock()
        mock_export.format = "json"
        mock_export.generated_at = datetime.now(UTC)
        mock_export.user_info = {"id": user_id, "username": "testuser"}
        mock_export.certificates = []
        mock_export.audit_events = []
        mock_export.sessions = []
        mock_export.metadata = {}
        mock_instance.export_user_data.return_value = mock_export
        mock_exporter.return_value = mock_instance

        response = await client.get(f"/api/v1/gdpr/export/{user_id}", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["user_id"] == user_id
    assert data["format"] == "json"
    assert "data" in data


async def test_export_user_data_forbidden(client, user_headers):
    """Test user cannot export another user's data."""
    # Arrange
    other_user_id = "other-user-456"

    # Act
    response = await client.get(f"/api/v1/gdpr/export/{other_user_id}", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_export_user_data_admin(client, admin_headers):
    """Test admin can export any user's data."""
    # Arrange
    user_id = "user-123"

    # Act - Mock data exporter
    with patch("pdfsigner.api.services.gdpr_service.get_user_data_exporter") as mock_exporter:
        mock_instance = Mock()
        mock_export = Mock()
        mock_export.format = "json"
        mock_export.generated_at = datetime.now(UTC)
        mock_export.user_info = {"id": user_id}
        mock_export.certificates = []
        mock_export.audit_events = []
        mock_export.sessions = []
        mock_export.metadata = {}
        mock_instance.export_user_data.return_value = mock_export
        mock_exporter.return_value = mock_instance

        response = await client.get(f"/api/v1/gdpr/export/{user_id}", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK


async def test_export_user_data_not_found(client, admin_headers):
    """Test exporting non-existent user returns 404."""
    # Arrange
    user_id = "nonexistent"

    # Act - Mock data exporter to return None
    with patch("pdfsigner.api.services.gdpr_service.get_user_data_exporter") as mock_exporter:
        mock_instance = Mock()
        mock_instance.export_user_data.return_value = None
        mock_exporter.return_value = mock_instance

        response = await client.get(f"/api/v1/gdpr/export/{user_id}", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- User Anonymization Tests (GDPR Article 17) ---


async def test_anonymize_user_success(client, admin_headers):
    """Test successful user anonymization."""
    # Arrange
    request_data = {"user_id": "user-123"}

    # Act - Mock retention service
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.user_id = "user-123"
        mock_result.fields_anonymized = ["username", "email", "display_name"]
        mock_result.audit_records_anonymized = 42
        mock_result.error_message = None
        mock_instance.anonymize_user.return_value = mock_result
        mock_service.return_value = mock_instance

        response = await client.post(
            "/api/v1/gdpr/anonymize", json=request_data, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert len(data["fields_anonymized"]) == 3
    assert data["audit_records_anonymized"] == 42


async def test_anonymize_user_unauthorized(client, user_headers, enable_healthcare_mode, mock_user):
    """Test anonymization fails without admin permission."""
    # Arrange
    request_data = {"user_id": "user-123"}

    # Act - Mock auth to return regular user (non-admin)
    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_user):
        response = await client.post(
            "/api/v1/gdpr/anonymize", json=request_data, headers=user_headers
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_anonymize_user_not_found(client, admin_headers):
    """Test anonymization fails for non-existent user."""
    # Arrange
    request_data = {"user_id": "nonexistent"}

    # Act - Mock service to return failure with "not found" message
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.error_message = "User not found: nonexistent"
        mock_instance.anonymize_user.return_value = mock_result
        mock_service.return_value = mock_instance

        response = await client.post(
            "/api/v1/gdpr/anonymize", json=request_data, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- Scheduled Deletion Tests ---


async def test_schedule_user_deletion_own_account(client, user_headers):
    """Test user can schedule deletion of their own account."""
    # Arrange
    user_id = "user-123"
    request_data = {"grace_days": 30}

    # Act - Mock retention service
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_instance.schedule_deletion.return_value = True
        mock_status = Mock()
        mock_status.deletion_date = datetime.now(UTC) + timedelta(days=30)
        mock_instance.get_retention_status.return_value = mock_status
        mock_service.return_value = mock_instance

        response = await client.post(
            f"/api/v1/gdpr/delete/{user_id}", json=request_data, headers=user_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["grace_days"] == 30


async def test_schedule_user_deletion_forbidden(client, user_headers):
    """Test user cannot schedule deletion of another user's account."""
    # Arrange
    other_user_id = "other-user-456"
    request_data = {"grace_days": 30}

    # Act
    response = await client.post(
        f"/api/v1/gdpr/delete/{other_user_id}", json=request_data, headers=user_headers
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_cancel_user_deletion_success(client, user_headers):
    """Test user can cancel their own scheduled deletion."""
    # Arrange
    user_id = "user-123"

    # Act - Mock retention service
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_instance.cancel_scheduled_deletion.return_value = True
        mock_service.return_value = mock_instance

        response = await client.delete(f"/api/v1/gdpr/delete/{user_id}", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True


async def test_cancel_user_deletion_not_scheduled(client, user_headers):
    """Test cancellation fails when no deletion is scheduled."""
    # Arrange
    user_id = "user-123"

    # Act - Mock service to return False
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_instance.cancel_scheduled_deletion.return_value = False
        mock_service.return_value = mock_instance

        response = await client.delete(f"/api/v1/gdpr/delete/{user_id}", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


# --- Retention Status Tests ---


async def test_get_retention_status_own_account(client, user_headers):
    """Test user can check their own retention status."""
    # Arrange
    user_id = "user-123"

    # Act - Mock retention service
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_status = Mock()
        mock_status.user_id = user_id
        mock_status.is_anonymized = False
        mock_status.deletion_scheduled = True
        mock_status.deletion_scheduled_at = datetime.now(UTC)
        mock_status.deletion_date = datetime.now(UTC) + timedelta(days=30)
        mock_status.days_until_deletion = 30
        mock_instance.get_retention_status.return_value = mock_status
        mock_service.return_value = mock_instance

        response = await client.get(f"/api/v1/gdpr/status/{user_id}", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["user_id"] == user_id
    assert data["deletion_scheduled"] is True
    assert data["days_until_deletion"] == 30


async def test_get_retention_status_forbidden(client, user_headers):
    """Test user cannot check another user's retention status."""
    # Arrange
    other_user_id = "other-user-456"

    # Act
    response = await client.get(f"/api/v1/gdpr/status/{other_user_id}", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


# --- Purge Expired Data Tests (Admin Only) ---


async def test_purge_expired_data_success(client, admin_headers):
    """Test successful data purge operation."""
    # Act - Mock retention service
    with patch("pdfsigner.api.services.gdpr_service.get_data_retention_service") as mock_service:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.users_deleted = 3
        mock_result.audit_records_purged = 127
        mock_result.documents_deleted = 0
        mock_result.error_message = None
        mock_instance.purge_expired_data.return_value = mock_result
        mock_service.return_value = mock_instance

        response = await client.post("/api/v1/gdpr/purge", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["users_deleted"] == 3
    assert data["audit_records_purged"] == 127


async def test_purge_expired_data_unauthorized(
    client, user_headers, enable_healthcare_mode, mock_user
):
    """Test data purge fails without admin permission."""
    # Act - Mock auth to return regular user (non-admin)
    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_user):
        response = await client.post("/api/v1/gdpr/purge", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_purge_expired_data_no_auth(client):
    """Test data purge fails without authentication."""
    # Act
    response = await client.post("/api/v1/gdpr/purge")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
