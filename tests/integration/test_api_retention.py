"""
Integration tests for Data Retention API.

Tests retention policy management endpoints:
- Policy CRUD operations
- Cleanup execution
- History tracking

Run with:
    uv run pytest tests/integration/test_api_retention.py -v
    uv run pytest tests/integration/test_api_retention.py -v -m compliance
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
from pdfsigner.core.retention import RetentionAction, RetentionPolicy, RetentionTarget

# Mark all tests in this module as anyio and compliance
pytestmark = [pytest.mark.anyio, pytest.mark.compliance]


# --- Fixtures ---


@pytest.fixture
def api_settings():
    """Get API settings for tests."""
    settings = get_api_settings()
    settings.api_keys = ["test-api-key-123"]
    return settings


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def auth_token(api_settings):
    """Create valid JWT token for testing."""
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
    """Create authentication headers with JWT token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def admin_headers(admin_token):
    """Create authentication headers with admin JWT token."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def sample_retention_policy():
    """Create sample retention policy for testing."""
    return RetentionPolicy(
        id="550e8400-e29b-41d4-a716-446655440000",
        name="Test Policy",
        description="Test retention policy",
        target=RetentionTarget.AUDIT_LOGS,
        retention_days=365,
        action=RetentionAction.ARCHIVE,
        enabled=True,
        hipaa_reference="§164.530(j)",
        created_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )


@pytest.fixture
def sample_retention_result():
    """Create sample retention cleanup result."""
    from pdfsigner.core.retention import RetentionResult

    return RetentionResult(
        policy_id="550e8400-e29b-41d4-a716-446655440000",
        policy_name="Test Policy",
        target=RetentionTarget.AUDIT_LOGS,
        action=RetentionAction.ARCHIVE,
        items_processed=100,
        items_deleted=0,
        items_archived=100,
        items_failed=0,
        started_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 2, 1, 10, 0, 5, tzinfo=UTC),
        errors=[],
    )


# --- Policy Listing Tests ---


async def test_list_retention_policies_success(client, auth_headers, sample_retention_policy):
    """Test listing all retention policies returns policies."""
    # Arrange - Mock RetentionManager
    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_policies.return_value = [sample_retention_policy]
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.get("/api/v1/retention/policies", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["id"] == sample_retention_policy.id
    assert data[0]["name"] == sample_retention_policy.name
    assert data[0]["target"] == sample_retention_policy.target.value
    assert data[0]["retention_days"] == sample_retention_policy.retention_days
    mock_manager.list_policies.assert_called_once_with(enabled_only=False)


async def test_list_retention_policies_enabled_only(client, auth_headers, sample_retention_policy):
    """Test listing only enabled retention policies."""
    # Arrange - Mock RetentionManager
    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.list_policies.return_value = [sample_retention_policy]
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.get(
            "/api/v1/retention/policies",
            params={"enabled_only": True},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    mock_manager.list_policies.assert_called_once_with(enabled_only=True)


# --- Get Policy Tests ---


async def test_get_retention_policy_success(client, auth_headers, sample_retention_policy):
    """Test getting specific retention policy returns policy details."""
    # Arrange - Mock RetentionManager
    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_policy.return_value = sample_retention_policy
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.get(
            f"/api/v1/retention/policies/{sample_retention_policy.id}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == sample_retention_policy.id
    assert data["name"] == sample_retention_policy.name
    assert data["target"] == sample_retention_policy.target.value
    assert data["hipaa_reference"] == sample_retention_policy.hipaa_reference


async def test_get_retention_policy_not_found(client, auth_headers):
    """Test getting non-existent retention policy returns 404."""
    # Arrange - Mock RetentionManager
    fake_policy_id = "00000000-0000-0000-0000-000000000000"

    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_policy.return_value = None
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.get(
            f"/api/v1/retention/policies/{fake_policy_id}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


# --- Create Policy Tests ---


async def test_create_retention_policy_success(client, auth_headers, sample_retention_policy):
    """Test creating new retention policy returns created policy."""
    # Arrange - Mock RetentionManager
    policy_data = {
        "name": "New Test Policy",
        "description": "New test policy description",
        "target": "session_data",
        "retention_days": 90,
        "action": "delete",
        "enabled": True,
        "hipaa_reference": "",
    }

    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.add_policy.return_value = sample_retention_policy
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.post(
            "/api/v1/retention/policies",
            json=policy_data,
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "id" in data
    assert "name" in data
    assert "created_at" in data
    mock_manager.add_policy.assert_called_once()


async def test_create_retention_policy_validation_error(client, auth_headers):
    """Test creating retention policy with invalid data fails validation."""
    # Arrange - Invalid retention_days (must be >= 1)
    policy_data = {
        "name": "Invalid Policy",
        "description": "Invalid policy",
        "target": "audit_logs",
        "retention_days": 0,  # Invalid: must be >= 1
        "action": "delete",
        "enabled": True,
    }

    # Act
    response = await client.post(
        "/api/v1/retention/policies",
        json=policy_data,
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# --- Update Policy Tests ---


async def test_update_retention_policy_success(client, auth_headers, sample_retention_policy):
    """Test updating retention policy returns updated policy."""
    # Arrange - Mock RetentionManager
    update_data = {
        "retention_days": 730,
        "enabled": False,
    }

    # Create updated policy
    updated_policy = RetentionPolicy(
        id=sample_retention_policy.id,
        name=sample_retention_policy.name,
        description=sample_retention_policy.description,
        target=sample_retention_policy.target,
        retention_days=730,
        action=sample_retention_policy.action,
        enabled=False,
        hipaa_reference=sample_retention_policy.hipaa_reference,
        created_at=sample_retention_policy.created_at,
    )

    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_policy.return_value = sample_retention_policy
        mock_manager.update_policy.return_value = updated_policy
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.patch(
            f"/api/v1/retention/policies/{sample_retention_policy.id}",
            json=update_data,
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == sample_retention_policy.id
    assert data["retention_days"] == 730
    assert data["enabled"] is False
    mock_manager.update_policy.assert_called_once()


async def test_update_retention_policy_not_found(client, auth_headers):
    """Test updating non-existent retention policy returns 404."""
    # Arrange - Mock RetentionManager
    fake_policy_id = "00000000-0000-0000-0000-000000000000"
    update_data = {"enabled": False}

    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_policy.return_value = None
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.patch(
            f"/api/v1/retention/policies/{fake_policy_id}",
            json=update_data,
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- Delete Policy Tests ---


async def test_delete_retention_policy_success(client, auth_headers):
    """Test deleting retention policy returns 204 no content."""
    # Arrange - Mock RetentionManager with non-HIPAA policy
    policy_id = "550e8400-e29b-41d4-a716-446655440000"
    policy = RetentionPolicy(
        id=policy_id,
        name="Deletable Policy",
        description="Can be deleted",
        target=RetentionTarget.REPORTS,
        retention_days=30,
        action=RetentionAction.DELETE,
        enabled=True,
        hipaa_reference="",  # No HIPAA reference
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_policy.return_value = policy
        mock_manager.delete_policy.return_value = True
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.delete(
            f"/api/v1/retention/policies/{policy_id}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_204_NO_CONTENT
    mock_manager.delete_policy.assert_called_once_with(policy_id)


async def test_delete_retention_policy_hipaa_protected(
    client, auth_headers, sample_retention_policy
):
    """Test deleting HIPAA-required policy returns 400 error."""
    # Arrange - Mock RetentionManager with HIPAA policy
    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_policy.return_value = sample_retention_policy  # Has hipaa_reference
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.delete(
            f"/api/v1/retention/policies/{sample_retention_policy.id}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "HIPAA" in response.json()["detail"]
    mock_manager.delete_policy.assert_not_called()


# --- Run Cleanup Tests ---


async def test_run_retention_cleanup_all_policies(client, auth_headers, sample_retention_result):
    """Test running retention cleanup for all policies."""
    # Arrange - Mock RetentionManager
    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.run_cleanup.return_value = [sample_retention_result]
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.post(
            "/api/v1/retention/run",
            json={"policy_id": None},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["policy_id"] == sample_retention_result.policy_id
    assert data[0]["items_processed"] == sample_retention_result.items_processed
    assert data[0]["items_archived"] == sample_retention_result.items_archived
    mock_manager.run_cleanup.assert_called_once_with(policy_id=None)


# --- History Tests ---


async def test_get_retention_history_success(client, auth_headers):
    """Test getting retention cleanup history returns records."""
    # Arrange - Mock RetentionManager
    history_records = [
        {
            "id": 1,
            "policy_id": "550e8400-e29b-41d4-a716-446655440000",
            "items_processed": 100,
            "items_deleted": 0,
            "items_archived": 100,
            "items_failed": 0,
            "started_at": "2026-02-01T10:00:00",
            "completed_at": "2026-02-01T10:00:05",
            "errors": None,
        },
        {
            "id": 2,
            "policy_id": "550e8400-e29b-41d4-a716-446655440001",
            "items_processed": 50,
            "items_deleted": 50,
            "items_archived": 0,
            "items_failed": 0,
            "started_at": "2026-02-01T11:00:00",
            "completed_at": "2026-02-01T11:00:02",
            "errors": None,
        },
    ]

    with patch("pdfsigner.api.routes.retention.get_retention_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_history.return_value = history_records
        mock_get_manager.return_value = mock_manager

        # Act
        response = await client.get("/api/v1/retention/history", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == 1
    assert data[0]["items_processed"] == 100
    assert data[1]["id"] == 2
    assert data[1]["items_deleted"] == 50
    mock_manager.get_history.assert_called_once_with(policy_id=None, limit=100)


# --- Public Exports ---

__all__ = [
    "test_list_retention_policies_success",
    "test_list_retention_policies_enabled_only",
    "test_get_retention_policy_success",
    "test_get_retention_policy_not_found",
    "test_create_retention_policy_success",
    "test_create_retention_policy_validation_error",
    "test_update_retention_policy_success",
    "test_update_retention_policy_not_found",
    "test_delete_retention_policy_success",
    "test_delete_retention_policy_hipaa_protected",
    "test_run_retention_cleanup_all_policies",
    "test_get_retention_history_success",
]
