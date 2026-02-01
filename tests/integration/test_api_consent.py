"""
Integration tests for Consent Management API.

Tests GDPR Article 7 consent endpoints:
- Grant consent
- Get active consents
- Withdraw consent
- Audit trail
- Summary
- IDOR prevention (users can only access their own data)

Run with:
    uv run pytest tests/integration/test_api_consent.py -v
    uv run pytest tests/integration/test_api_consent.py -v --cov=src/pdfsigner/api/routes/consent
"""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from fastapi import status

from pdfsigner.core.gdpr import ConsentType

# Mark all tests in this module as anyio and compliance
pytestmark = [pytest.mark.anyio, pytest.mark.compliance]


# --- Helper Functions ---


def _create_mock_consent(
    user_id: str,
    consent_type: ConsentType,
    granted: bool = True,
    withdrawn_at: datetime | None = None,
    policy_version: str | None = "1.0.0",
):
    """Create mock consent record for testing."""
    mock = Mock()
    mock.id = "550e8400-e29b-41d4-a716-446655440000"
    mock.user_id = user_id
    mock.consent_type = consent_type
    mock.granted = granted
    mock.granted_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
    mock.withdrawn_at = withdrawn_at
    mock.ip_address = "192.168.1.100"
    mock.policy_version = policy_version
    return mock


# --- Test Grant Consent (POST /api/v1/consent/{user_id}) ---


async def test_grant_consent_success(client, auth_headers):
    """Test user can grant their own consent."""
    # Arrange
    user_id = "testuser"
    consent_data = {
        "consent_type": "analytics",
        "policy_version": "1.0.0",
    }

    mock_consent = _create_mock_consent(user_id, ConsentType.ANALYTICS)

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.grant_consent.return_value = mock_consent
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            f"/api/v1/consent/{user_id}",
            json=consent_data,
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["user_id"] == user_id
    assert data["consent_type"] == "analytics"
    assert data["granted"] is True
    assert data["policy_version"] == "1.0.0"
    assert "id" in data
    assert "granted_at" in data


async def test_grant_consent_idor_prevention(client, auth_headers):
    """Test user cannot grant consent for another user (IDOR prevention)."""
    # Arrange
    other_user_id = "otheruser"
    consent_data = {
        "consent_type": "analytics",
        "policy_version": "1.0.0",
    }

    # Act
    response = await client.post(
        f"/api/v1/consent/{other_user_id}",
        json=consent_data,
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "own consent" in response.json()["detail"]


async def test_grant_consent_admin_can_grant_for_others(client, admin_headers):
    """Test admin can grant consent on behalf of other users."""
    # Arrange
    user_id = "someuser"
    consent_data = {
        "consent_type": "processing",
        "policy_version": "2.0.0",
    }

    mock_consent = _create_mock_consent(user_id, ConsentType.PROCESSING, policy_version="2.0.0")

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.grant_consent.return_value = mock_consent
        mock_get_manager.return_value = mock_manager

        response = await client.post(
            f"/api/v1/consent/{user_id}",
            json=consent_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["user_id"] == user_id
    assert data["consent_type"] == "processing"


async def test_grant_consent_invalid_type(client, auth_headers):
    """Test granting consent fails with invalid consent type."""
    # Arrange
    user_id = "testuser"
    consent_data = {
        "consent_type": "invalid_type",
        "policy_version": "1.0.0",
    }

    # Act
    response = await client.post(
        f"/api/v1/consent/{user_id}",
        json=consent_data,
        headers=auth_headers,
    )

    # Assert - Pydantic validation fails first (pattern mismatch)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# --- Test Get Consents (GET /api/v1/consent/{user_id}) ---


async def test_get_consents_success(client, auth_headers):
    """Test user can retrieve their own active consents."""
    # Arrange
    user_id = "testuser"
    mock_consents = [
        _create_mock_consent(user_id, ConsentType.ANALYTICS),
        _create_mock_consent(user_id, ConsentType.PROCESSING),
    ]

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_active_consents.return_value = mock_consents
        mock_get_manager.return_value = mock_manager

        response = await client.get(
            f"/api/v1/consent/{user_id}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert all(c["granted"] is True for c in data)


async def test_get_consents_idor_prevention(client, auth_headers):
    """Test user cannot view another user's consents (IDOR prevention)."""
    # Arrange
    other_user_id = "otheruser"

    # Act
    response = await client.get(
        f"/api/v1/consent/{other_user_id}",
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "own consents" in response.json()["detail"]


async def test_get_consents_admin_can_view_others(client, admin_headers):
    """Test admin can view any user's consents."""
    # Arrange
    user_id = "someuser"
    mock_consents = [_create_mock_consent(user_id, ConsentType.MARKETING)]

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_active_consents.return_value = mock_consents
        mock_get_manager.return_value = mock_manager

        response = await client.get(
            f"/api/v1/consent/{user_id}",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1


# --- Test Withdraw Consent (DELETE /api/v1/consent/{user_id}/{consent_type}) ---


async def test_withdraw_consent_success(client, auth_headers):
    """Test user can withdraw their own consent."""
    # Arrange
    user_id = "testuser"
    consent_type = "analytics"

    withdrawn_at = datetime(2024, 1, 15, 11, 0, 0, tzinfo=UTC)
    mock_withdrawal = _create_mock_consent(
        user_id,
        ConsentType.ANALYTICS,
        granted=False,
        withdrawn_at=withdrawn_at,
    )

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.withdraw_consent.return_value = mock_withdrawal
        mock_get_manager.return_value = mock_manager

        response = await client.delete(
            f"/api/v1/consent/{user_id}/{consent_type}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["user_id"] == user_id
    assert data["consent_type"] == "analytics"
    assert data["granted"] is False
    assert data["withdrawn_at"] is not None


async def test_withdraw_consent_not_found(client, auth_headers):
    """Test withdrawing non-existent consent returns 404."""
    # Arrange
    user_id = "testuser"
    consent_type = "marketing"

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.withdraw_consent.side_effect = ValueError("No active consent found")
        mock_get_manager.return_value = mock_manager

        response = await client.delete(
            f"/api/v1/consent/{user_id}/{consent_type}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_withdraw_consent_idor_prevention(client, auth_headers):
    """Test user cannot withdraw another user's consent (IDOR prevention)."""
    # Arrange
    other_user_id = "otheruser"
    consent_type = "analytics"

    # Act
    response = await client.delete(
        f"/api/v1/consent/{other_user_id}/{consent_type}",
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "own consent" in response.json()["detail"]


# --- Test Audit Trail (GET /api/v1/consent/audit/{user_id}) ---


async def test_get_audit_trail_success(client, admin_headers):
    """Test admin can view complete consent audit trail."""
    # Arrange
    user_id = "testuser"
    mock_consents = [
        _create_mock_consent(user_id, ConsentType.ANALYTICS, granted=True),
        _create_mock_consent(
            user_id,
            ConsentType.MARKETING,
            granted=False,
            withdrawn_at=datetime(2024, 1, 14, 9, 0, 0, tzinfo=UTC),
        ),
    ]

    # Act
    with (
        patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager,
        patch("pdfsigner.api.routes.consent.check_permission") as mock_check,
    ):
        # Mock permission check
        mock_check.return_value = lambda: None

        mock_manager = Mock()
        mock_manager.get_consent_audit_trail.return_value = mock_consents
        mock_get_manager.return_value = mock_manager

        response = await client.get(
            f"/api/v1/consent/audit/{user_id}",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "consents" in data
    assert "total_records" in data
    assert data["total_records"] == 2
    assert len(data["consents"]) == 2


# --- Test Summary (GET /api/v1/consent/summary/{user_id}) ---


async def test_get_summary_success(client, auth_headers):
    """Test user can view their consent summary."""
    # Arrange
    user_id = "testuser"
    mock_summary = {
        ConsentType.PROCESSING: True,
        ConsentType.ANALYTICS: True,
        ConsentType.MARKETING: False,
    }
    mock_trail = [_create_mock_consent(user_id, ConsentType.ANALYTICS)]

    # Act
    with patch("pdfsigner.api.routes.consent.get_consent_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_consent_summary.return_value = mock_summary
        mock_manager.get_consent_audit_trail.return_value = mock_trail
        mock_get_manager.return_value = mock_manager

        response = await client.get(
            f"/api/v1/consent/summary/{user_id}",
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["user_id"] == user_id
    assert "consents" in data
    assert "last_updated" in data
    assert data["consents"]["processing"] is True
    assert data["consents"]["analytics"] is True
    assert data["consents"]["marketing"] is False


async def test_get_summary_idor_prevention(client, auth_headers):
    """Test user cannot view another user's consent summary (IDOR prevention)."""
    # Arrange
    other_user_id = "otheruser"

    # Act
    response = await client.get(
        f"/api/v1/consent/summary/{other_user_id}",
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "own consent summary" in response.json()["detail"]
