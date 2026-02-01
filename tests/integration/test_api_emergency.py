"""
Integration tests for Emergency Access (Break-Glass) API.

Tests HIPAA §164.312(a)(2)(ii) emergency access procedures including:
- Request creation with justification
- Admin approval/denial workflows
- Access revocation
- Status checking
- Expiration handling
- Audit trail compliance

Run with:
    uv run pytest tests/integration/test_api_emergency.py -v
    uv run pytest tests/integration/test_api_emergency.py -v -m security
    uv run pytest tests/integration/test_api_emergency.py -v -m compliance
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.core.emergency import EmergencyAccessStatus

# Mark all tests in this module as anyio (async support)
pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def temp_emergency_repo(tmp_path: Path):
    """Create temporary emergency access repository."""
    from pdfsigner.core.emergency import EmergencyAccessRepository

    db_path = tmp_path / "test_emergency.db"
    repo = EmergencyAccessRepository(db_path=db_path)
    return repo


@pytest.fixture
def user_token():
    """Create valid JWT token for regular user."""
    token = create_access_token(
        data={"sub": "testuser", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def admin_token():
    """Create valid admin JWT token."""
    token = create_access_token(
        data={"sub": "admin", "role": "admin"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def user_headers(user_token):
    """Create authentication headers for regular user."""
    return {"Authorization": f"Bearer {user_token}"}


@pytest.fixture
def admin_headers(admin_token):
    """Create authentication headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def mock_settings():
    """Mock settings with healthcare_mode enabled."""
    settings = MagicMock()
    settings.healthcare_mode = True
    settings.healthcare_emergency_duration_hours = 4
    settings.healthcare_emergency_require_approval = True
    return settings


# --- Request Emergency Access Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_request_emergency_access_success(client, user_headers, mock_settings):
    """Test requesting emergency access with valid justification."""
    # Arrange
    request_data = {"reason": "Patient in critical condition requiring immediate care"}

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "id" in data
    assert data["requester_id"] == "testuser"
    assert data["reason"] == request_data["reason"]
    assert data["status"] == EmergencyAccessStatus.PENDING.value
    assert data["requested_at"] is not None
    assert data["approved_by"] is None


@pytest.mark.security
async def test_request_emergency_access_empty_reason(client, user_headers, mock_settings):
    """Test requesting emergency access fails with empty reason."""
    # Arrange
    request_data = {"reason": ""}

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

    # Assert - Pydantic validation should fail (min_length=10)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.security
async def test_request_emergency_access_short_reason(client, user_headers, mock_settings):
    """Test requesting emergency access fails with too short reason."""
    # Arrange
    request_data = {"reason": "short"}  # Less than 10 chars

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.security
async def test_request_emergency_access_auto_approve(client, user_headers):
    """Test emergency access is auto-approved when require_approval is False."""
    # Arrange
    settings = MagicMock()
    settings.healthcare_mode = True
    settings.healthcare_emergency_duration_hours = 4
    settings.healthcare_emergency_require_approval = False  # Auto-approve

    request_data = {"reason": "Emergency access needed for patient care"}

    # Act
    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
    ):
        # Create fresh service instance with mocked settings
        from pdfsigner.core.emergency import BreakGlassService, get_emergency_repository

        service = BreakGlassService(repository=get_emergency_repository())
        service.settings = settings
        mock_get_service.return_value = service

        response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["status"] == EmergencyAccessStatus.APPROVED.value
    assert data["approved_by"] == "system"
    assert data["expires_at"] is not None


@pytest.mark.security
async def test_request_emergency_access_healthcare_disabled(client, user_headers):
    """Test emergency access fails when healthcare_mode is disabled."""
    # Arrange
    settings = MagicMock()
    settings.healthcare_mode = False  # Disabled

    request_data = {"reason": "Emergency access needed"}

    # Act
    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
    ):
        # Create fresh service instance with mocked settings
        from pdfsigner.core.emergency import BreakGlassService, get_emergency_repository

        service = BreakGlassService(repository=get_emergency_repository())
        service.settings = settings
        mock_get_service.return_value = service

        response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "healthcare_mode" in response.json()["detail"]


@pytest.mark.security
async def test_request_emergency_access_without_auth(client, mock_settings):
    """Test requesting emergency access fails without authentication."""
    # Arrange
    request_data = {"reason": "Emergency access needed"}

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post("/api/v1/emergency/request", json=request_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- List Pending Requests Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_list_pending_requests_admin(client, admin_headers, user_headers, mock_settings):
    """Test admin can list pending emergency access requests."""
    # Arrange - Create a pending request
    request_data = {"reason": "Patient emergency requiring immediate attention"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

        # Act
        response = await client.get("/api/v1/emergency/pending", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["status"] == EmergencyAccessStatus.PENDING.value


@pytest.mark.security
async def test_list_pending_requests_non_admin(client, user_headers, mock_settings):
    """Test non-admin cannot list pending requests."""
    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.get("/api/v1/emergency/pending", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Admin access required" in response.json()["detail"]


@pytest.mark.security
async def test_list_pending_requests_without_auth(client, mock_settings):
    """Test listing pending requests fails without authentication."""
    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.get("/api/v1/emergency/pending")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Approve Request Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_approve_request_admin(client, admin_headers, user_headers, mock_settings):
    """Test admin can approve pending emergency access request."""
    # Arrange - Create a pending request
    request_data = {"reason": "Patient critical care access required"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Act
        approve_response = await client.post(
            f"/api/v1/emergency/{request_id}/approve",
            headers=admin_headers,
        )

    # Assert
    assert approve_response.status_code == status.HTTP_200_OK
    data = approve_response.json()
    assert data["id"] == request_id
    assert data["status"] == EmergencyAccessStatus.APPROVED.value
    assert data["approved_by"] == "admin"
    assert data["approved_at"] is not None
    assert data["expires_at"] is not None


@pytest.mark.security
async def test_approve_request_non_admin(client, user_headers, mock_settings):
    """Test non-admin cannot approve requests."""
    # Arrange
    fake_request_id = "a1b2c3d4-e5f6-4789-a012-b34c56d78e90"

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/approve",
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.security
async def test_approve_request_not_found(client, admin_headers, mock_settings):
    """Test approving non-existent request returns 404."""
    # Arrange
    fake_request_id = "00000000-0000-0000-0000-000000000000"

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/approve",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"]


@pytest.mark.security
async def test_approve_already_approved_request(client, admin_headers, user_headers, mock_settings):
    """Test cannot approve already approved request."""
    # Arrange - Create and approve a request
    request_data = {"reason": "Patient emergency requiring care"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Approve once
        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Act - Try to approve again
        second_approve = await client.post(
            f"/api/v1/emergency/{request_id}/approve",
            headers=admin_headers,
        )

    # Assert
    assert second_approve.status_code == status.HTTP_400_BAD_REQUEST
    assert "cannot be approved" in second_approve.json()["detail"]


# --- Deny Request Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_deny_request_admin(client, admin_headers, user_headers, mock_settings):
    """Test admin can deny pending emergency access request."""
    # Arrange - Create a pending request
    request_data = {"reason": "Emergency access request"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Act
        deny_data = {"reason": "Insufficient justification"}
        deny_response = await client.post(
            f"/api/v1/emergency/{request_id}/deny",
            json=deny_data,
            headers=admin_headers,
        )

    # Assert
    assert deny_response.status_code == status.HTTP_200_OK
    data = deny_response.json()
    assert data["id"] == request_id
    assert data["status"] == EmergencyAccessStatus.DENIED.value
    assert data["approved_by"] == "admin"  # Tracks who made the decision


@pytest.mark.security
async def test_deny_request_non_admin(client, user_headers, mock_settings):
    """Test non-admin cannot deny requests."""
    # Arrange
    fake_request_id = "a1b2c3d4-e5f6-4789-a012-b34c56d78e90"
    deny_data = {"reason": "Test denial"}

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/deny",
            json=deny_data,
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.security
async def test_deny_request_not_found(client, admin_headers, mock_settings):
    """Test denying non-existent request returns 404."""
    # Arrange
    fake_request_id = "00000000-0000-0000-0000-000000000000"
    deny_data = {"reason": "Test denial"}

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/deny",
            json=deny_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.security
async def test_deny_already_approved_request(client, admin_headers, user_headers, mock_settings):
    """Test cannot deny already approved request."""
    # Arrange - Create and approve a request
    request_data = {"reason": "Patient emergency requiring care"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Approve first
        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Act - Try to deny
        deny_data = {"reason": "Trying to deny"}
        deny_response = await client.post(
            f"/api/v1/emergency/{request_id}/deny",
            json=deny_data,
            headers=admin_headers,
        )

    # Assert
    assert deny_response.status_code == status.HTTP_400_BAD_REQUEST
    assert "cannot be denied" in deny_response.json()["detail"]


# --- Revoke Access Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_revoke_access_admin(client, admin_headers, user_headers, mock_settings):
    """Test admin can revoke active emergency access."""
    # Arrange - Create and approve a request
    request_data = {"reason": "Patient emergency requiring immediate care"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Approve
        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Act - Revoke
        revoke_response = await client.post(
            f"/api/v1/emergency/{request_id}/revoke",
            headers=admin_headers,
        )

    # Assert
    assert revoke_response.status_code == status.HTTP_200_OK
    data = revoke_response.json()
    assert data["id"] == request_id
    assert data["status"] == EmergencyAccessStatus.REVOKED.value
    assert data["revoked_by"] == "admin"
    assert data["revoked_at"] is not None


@pytest.mark.security
async def test_revoke_access_non_admin(client, user_headers, mock_settings):
    """Test non-admin cannot revoke access."""
    # Arrange
    fake_request_id = "a1b2c3d4-e5f6-4789-a012-b34c56d78e90"

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/revoke",
            headers=user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.security
async def test_revoke_access_not_found(client, admin_headers, mock_settings):
    """Test revoking non-existent request returns 404."""
    # Arrange
    fake_request_id = "00000000-0000-0000-0000-000000000000"

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/revoke",
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.security
async def test_revoke_pending_request(client, admin_headers, user_headers, mock_settings):
    """Test cannot revoke pending (not approved) request."""
    # Arrange - Create a pending request (don't approve it)
    request_data = {"reason": "Patient emergency requiring care"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Act - Try to revoke without approval
        revoke_response = await client.post(
            f"/api/v1/emergency/{request_id}/revoke",
            headers=admin_headers,
        )

    # Assert
    assert revoke_response.status_code == status.HTTP_400_BAD_REQUEST
    assert "cannot be revoked" in revoke_response.json()["detail"]


# --- Check Status Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_check_status_no_access(client, user_headers, mock_settings, temp_emergency_repo):
    """Test status check returns false when user has no emergency access."""
    # Act
    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
    ):
        # Create fresh service instance with clean temporary repo
        from pdfsigner.core.emergency import BreakGlassService

        service = BreakGlassService(repository=temp_emergency_repo)
        service.settings = mock_settings
        mock_get_service.return_value = service

        response = await client.get("/api/v1/emergency/status", headers=user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["has_active_access"] is False
    assert data["active_request_id"] is None
    assert data["expires_at"] is None


@pytest.mark.security
@pytest.mark.compliance
async def test_check_status_with_active_access(client, admin_headers, user_headers, mock_settings):
    """Test status check returns true when user has active emergency access."""
    # Arrange - Create and approve a request
    request_data = {"reason": "Patient emergency requiring immediate care"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Approve
        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Act
        status_response = await client.get("/api/v1/emergency/status", headers=user_headers)

    # Assert
    assert status_response.status_code == status.HTTP_200_OK
    data = status_response.json()
    assert data["has_active_access"] is True
    assert data["active_request_id"] == request_id
    assert data["expires_at"] is not None


@pytest.mark.security
async def test_check_status_with_revoked_access(
    client, admin_headers, user_headers, mock_settings, temp_emergency_repo
):
    """Test status check returns false after access is revoked."""
    # Arrange - Create, approve, then revoke a request
    request_data = {"reason": "Patient emergency requiring immediate care"}

    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
    ):
        # Create fresh service instance with clean temporary repo
        from pdfsigner.core.emergency import BreakGlassService

        service = BreakGlassService(repository=temp_emergency_repo)
        service.settings = mock_settings
        mock_get_service.return_value = service

        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Approve
        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Revoke
        await client.post(f"/api/v1/emergency/{request_id}/revoke", headers=admin_headers)

        # Act
        status_response = await client.get("/api/v1/emergency/status", headers=user_headers)

    # Assert
    assert status_response.status_code == status.HTTP_200_OK
    data = status_response.json()
    assert data["has_active_access"] is False


@pytest.mark.security
async def test_check_status_without_auth(client, mock_settings):
    """Test status check fails without authentication."""
    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.get("/api/v1/emergency/status")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Expiration Tests ---


@pytest.mark.security
@pytest.mark.compliance
async def test_expired_access_not_active(client, admin_headers, user_headers, temp_emergency_repo):
    """Test that expired emergency access is not considered active."""
    # Arrange - Create with very short expiration
    settings = MagicMock()
    settings.healthcare_mode = True
    settings.healthcare_emergency_duration_hours = 0.0001  # Very short duration
    settings.healthcare_emergency_require_approval = True

    request_data = {"reason": "Patient emergency requiring immediate care"}

    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
    ):
        # Create fresh service instance with clean temporary repo
        from pdfsigner.core.emergency import BreakGlassService

        service = BreakGlassService(repository=temp_emergency_repo)
        service.settings = settings
        mock_get_service.return_value = service

        # Create and approve request
        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Wait for expiration (small delay)
        import asyncio

        await asyncio.sleep(0.5)

        # Act - Check status after expiration
        status_response = await client.get("/api/v1/emergency/status", headers=user_headers)

    # Assert
    assert status_response.status_code == status.HTTP_200_OK
    data = status_response.json()
    # Should be false since access expired
    assert data["has_active_access"] is False


# --- Audit Trail Tests ---


@pytest.mark.compliance
async def test_emergency_request_creates_audit_trail(client, user_headers, mock_settings):
    """Test that emergency access request creates audit log entry."""
    # Arrange
    request_data = {"reason": "Patient critical care access required"}
    mock_audit_instance = MagicMock()

    # Act
    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
        patch("pdfsigner.core.emergency.break_glass.AuditLogger") as mock_audit,
    ):
        mock_audit.get_instance.return_value = mock_audit_instance

        # Create fresh service instance with mocked audit logger
        from pdfsigner.core.emergency import BreakGlassService, get_emergency_repository

        service = BreakGlassService(
            repository=get_emergency_repository(),
            audit_logger=mock_audit_instance,
        )
        service.settings = mock_settings
        mock_get_service.return_value = service

        await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )

        # Assert - Verify audit log was called
        assert mock_audit_instance.log_event.called


@pytest.mark.compliance
async def test_emergency_approval_creates_audit_trail(
    client, admin_headers, user_headers, mock_settings
):
    """Test that emergency access approval creates audit log entry."""
    # Arrange
    request_data = {"reason": "Patient emergency requiring care"}
    mock_audit_instance = MagicMock()

    with (
        patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings),
        patch("pdfsigner.api.routes.emergency.get_break_glass_service") as mock_get_service,
        patch("pdfsigner.core.emergency.break_glass.AuditLogger") as mock_audit,
    ):
        mock_audit.get_instance.return_value = mock_audit_instance

        # Create fresh service instance with mocked audit logger
        from pdfsigner.core.emergency import BreakGlassService, get_emergency_repository

        service = BreakGlassService(
            repository=get_emergency_repository(),
            audit_logger=mock_audit_instance,
        )
        service.settings = mock_settings
        mock_get_service.return_value = service

        create_response = await client.post(
            "/api/v1/emergency/request",
            json=request_data,
            headers=user_headers,
        )
        request_id = create_response.json()["id"]

        # Clear the mock to only check approval call
        mock_audit_instance.log_event.reset_mock()

        # Act
        await client.post(f"/api/v1/emergency/{request_id}/approve", headers=admin_headers)

        # Assert
        assert mock_audit_instance.log_event.called


# --- Additional Edge Cases ---


@pytest.mark.security
async def test_approve_request_with_expired_token(client, mock_settings):
    """Test approving request with expired token fails."""
    # Arrange - Create expired token
    expired_token = create_access_token(
        data={"sub": "admin", "role": "admin"},
        expires_delta=timedelta(seconds=-1),
    )
    expired_headers = {"Authorization": f"Bearer {expired_token}"}
    fake_request_id = "a1b2c3d4-e5f6-4789-a012-b34c56d78e90"

    # Act
    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        response = await client.post(
            f"/api/v1/emergency/{fake_request_id}/approve",
            headers=expired_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.security
async def test_list_pending_excludes_non_pending(
    client, admin_headers, user_headers, mock_settings
):
    """Test list pending only returns pending requests, not approved/denied."""
    # Arrange - Create multiple requests with different statuses
    request_data1 = {"reason": "Emergency 1 - will be approved"}
    request_data2 = {"reason": "Emergency 2 - will stay pending"}
    request_data3 = {"reason": "Emergency 3 - will be denied"}

    with patch("pdfsigner.core.emergency.break_glass.get_settings", return_value=mock_settings):
        # Create request 1 and approve it
        r1 = await client.post(
            "/api/v1/emergency/request", json=request_data1, headers=user_headers
        )
        await client.post(f"/api/v1/emergency/{r1.json()['id']}/approve", headers=admin_headers)

        # Create request 2 (leave pending)
        await client.post("/api/v1/emergency/request", json=request_data2, headers=user_headers)

        # Create request 3 and deny it
        r3 = await client.post(
            "/api/v1/emergency/request", json=request_data3, headers=user_headers
        )
        deny_data = {"reason": "Denied"}
        await client.post(
            f"/api/v1/emergency/{r3.json()['id']}/deny", json=deny_data, headers=admin_headers
        )

        # Act - List pending
        response = await client.get("/api/v1/emergency/pending", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    # Should only have the pending request
    pending_count = sum(1 for req in data if req["status"] == EmergencyAccessStatus.PENDING.value)
    assert pending_count >= 1
    # Should not have approved or denied in the list
    for req in data:
        assert req["status"] == EmergencyAccessStatus.PENDING.value
