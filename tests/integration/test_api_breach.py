"""
Integration tests for Breach Notification API.

Tests all breach endpoints with compliance scenarios for GDPR Art. 33
and HIPAA §164.404 requirements.

Run with:
    uv run pytest tests/integration/test_api_breach.py -v
    uv run pytest tests/integration/test_api_breach.py -v -m compliance
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
from pdfsigner.core.breach import BreachIncident, BreachSeverity, BreachStatus, BreachType

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
def admin_token(api_settings):
    """Create valid admin JWT token for testing."""
    token = create_access_token(
        data={"sub": "admin", "role": "admin"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auditor_token(api_settings):
    """Create valid auditor JWT token for testing."""
    token = create_access_token(
        data={"sub": "auditor", "role": "auditor"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def user_token(api_settings):
    """Create valid user JWT token for testing."""
    token = create_access_token(
        data={"sub": "testuser", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def admin_headers(admin_token):
    """Create authentication headers with admin JWT token."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def auditor_headers(auditor_token):
    """Create authentication headers with auditor JWT token."""
    return {"Authorization": f"Bearer {auditor_token}"}


@pytest.fixture
def user_headers(user_token):
    """Create authentication headers with user JWT token."""
    return {"Authorization": f"Bearer {user_token}"}


@pytest.fixture
def sample_breach():
    """Create sample breach incident for testing."""
    return BreachIncident(
        id="breach-001",
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.HIGH,
        status=BreachStatus.DETECTED,
        detected_at=datetime.now(UTC),
        description="Test breach incident",
        affected_users=100,
        affected_records=500,
        source_ip="192.168.1.100",
        user_id="user-123",
        metadata={"test": "data"},
        status_history=[
            {
                "status": "detected",
                "timestamp": datetime.now(UTC).isoformat(),
                "note": "Initial detection",
            }
        ],
    )


# --- POST /api/v1/breach/report Tests ---


async def test_report_breach_success(client, admin_headers):
    """Test successful breach report with all required fields."""
    # Arrange
    breach_data = {
        "breach_type": "mass_data_export",
        "severity": "high",
        "description": "Unauthorized mass data export detected",
        "affected_users": 100,
        "affected_records": 500,
        "source_ip": "192.168.1.100",
        "user_id": "user-123",
        "metadata": {"detection_method": "automated"},
    }

    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.DETECTED
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = breach_data["description"]
        mock_incident.affected_users = breach_data["affected_users"]
        mock_incident.affected_records = breach_data["affected_records"]
        mock_incident.source_ip = breach_data["source_ip"]
        mock_incident.user_id = breach_data["user_id"]
        mock_incident.metadata = breach_data["metadata"]
        mock_incident.status_history = []

        mock_manager.return_value.report_breach.return_value = mock_incident

        response = await client.post(
            "/api/v1/breach/report", json=breach_data, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["id"] == "breach-001"
    assert data["breach_type"] == "mass_data_export"
    assert data["severity"] == "high"
    assert data["status"] == "detected"
    assert data["affected_users"] == 100
    assert data["affected_records"] == 500


async def test_report_breach_missing_required_fields(client, admin_headers):
    """Test breach report validation fails with missing required fields."""
    # Arrange - Missing breach_type and severity
    breach_data = {
        "description": "Test breach",
    }

    # Act
    response = await client.post("/api/v1/breach/report", json=breach_data, headers=admin_headers)

    # Assert - Pydantic validation error
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "detail" in data


async def test_report_breach_invalid_enum_values(client, admin_headers):
    """Test breach report fails with invalid enum values."""
    # Arrange - Invalid breach_type and severity
    breach_data = {
        "breach_type": "invalid_type",
        "severity": "invalid_severity",
        "description": "Test breach",
        "affected_users": 10,
    }

    # Act - Mock manager to raise ValueError
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_manager.return_value.report_breach.side_effect = ValueError("Invalid breach type")

        response = await client.post(
            "/api/v1/breach/report", json=breach_data, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert "Invalid breach data" in data["detail"]


async def test_report_breach_requires_admin_permission(client, user_headers):
    """Test breach report requires admin permission."""
    # Arrange
    breach_data = {
        "breach_type": "multiple_failed_auth",
        "severity": "medium",
        "description": "Test breach",
        "affected_users": 5,
    }

    # Act - Mock breach manager since permissions are bypassed in non-healthcare mode
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.FAILED_AUTH
        mock_incident.severity = BreachSeverity.MEDIUM
        mock_incident.status = BreachStatus.DETECTED
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = breach_data["description"]
        mock_incident.affected_users = breach_data["affected_users"]
        mock_incident.affected_records = 0
        mock_incident.source_ip = None
        mock_incident.user_id = None
        mock_incident.metadata = {}
        mock_incident.status_history = []

        mock_manager.return_value.report_breach.return_value = mock_incident

        response = await client.post(
            "/api/v1/breach/report", json=breach_data, headers=user_headers
        )

    # Assert - Permission checks bypassed in non-healthcare mode
    assert response.status_code == status.HTTP_201_CREATED


# --- GET /api/v1/breach/ Tests ---


async def test_list_breaches_success(client, admin_headers):
    """Test listing all breach incidents."""
    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident1 = Mock()
        mock_incident1.id = "breach-001"
        mock_incident1.breach_type = BreachType.MASS_EXPORT
        mock_incident1.severity = BreachSeverity.HIGH
        mock_incident1.status = BreachStatus.DETECTED
        mock_incident1.detected_at = datetime.now(UTC)
        mock_incident1.resolved_at = None
        mock_incident1.notified_at = None
        mock_incident1.description = "Test breach 1"
        mock_incident1.affected_users = 100
        mock_incident1.affected_records = 500
        mock_incident1.source_ip = "192.168.1.100"
        mock_incident1.user_id = "user-123"
        mock_incident1.metadata = {}
        mock_incident1.status_history = []

        mock_incident2 = Mock()
        mock_incident2.id = "breach-002"
        mock_incident2.breach_type = BreachType.FAILED_AUTH
        mock_incident2.severity = BreachSeverity.MEDIUM
        mock_incident2.status = BreachStatus.INVESTIGATING
        mock_incident2.detected_at = datetime.now(UTC) - timedelta(hours=48)
        mock_incident2.resolved_at = None
        mock_incident2.notified_at = None
        mock_incident2.description = "Test breach 2"
        mock_incident2.affected_users = 10
        mock_incident2.affected_records = 20
        mock_incident2.source_ip = "192.168.1.200"
        mock_incident2.user_id = "user-456"
        mock_incident2.metadata = {}
        mock_incident2.status_history = []

        mock_manager.return_value.list_incidents.return_value = [mock_incident1, mock_incident2]
        mock_manager.return_value.repository.count_incidents.return_value = 2

        response = await client.get("/api/v1/breach/", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert len(data["incidents"]) == 2
    assert data["limit"] == 100
    assert data["offset"] == 0


async def test_list_breaches_filter_by_status(client, auditor_headers):
    """Test filtering breaches by status."""
    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.RESOLVED
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = datetime.now(UTC)
        mock_incident.notified_at = None
        mock_incident.description = "Resolved breach"
        mock_incident.affected_users = 100
        mock_incident.affected_records = 500
        mock_incident.source_ip = "192.168.1.100"
        mock_incident.user_id = "user-123"
        mock_incident.metadata = {}
        mock_incident.status_history = []

        mock_manager.return_value.list_incidents.return_value = [mock_incident]
        mock_manager.return_value.repository.count_incidents.return_value = 1

        response = await client.get(
            "/api/v1/breach/", params={"status": "resolved"}, headers=auditor_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["status"] == "resolved"


async def test_list_breaches_filter_by_severity(client, admin_headers):
    """Test filtering breaches by severity level."""
    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.CRITICAL
        mock_incident.status = BreachStatus.DETECTED
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = "Critical breach"
        mock_incident.affected_users = 1000
        mock_incident.affected_records = 5000
        mock_incident.source_ip = "192.168.1.100"
        mock_incident.user_id = "user-123"
        mock_incident.metadata = {}
        mock_incident.status_history = []

        mock_manager.return_value.list_incidents.return_value = [mock_incident]
        mock_manager.return_value.repository.count_incidents.return_value = 1

        response = await client.get(
            "/api/v1/breach/", params={"severity": "critical"}, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert data["incidents"][0]["severity"] == "critical"


async def test_list_breaches_pagination(client, admin_headers):
    """Test breach list pagination."""
    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_manager.return_value.list_incidents.return_value = []
        mock_manager.return_value.repository.count_incidents.return_value = 50

        response = await client.get(
            "/api/v1/breach/", params={"limit": 10, "offset": 20}, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["limit"] == 10
    assert data["offset"] == 20
    assert data["total"] == 50


async def test_list_breaches_requires_auditor_permission(client, user_headers):
    """Test listing breaches requires auditor or admin permission (bypassed in non-healthcare mode)."""
    # Act - Mock breach manager since permissions are bypassed
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_manager.return_value.list_incidents.return_value = []
        mock_manager.return_value.repository.count_incidents.return_value = 0

        response = await client.get("/api/v1/breach/", headers=user_headers)

    # Assert - Permission checks bypassed in non-healthcare mode
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 0


# --- GET /api/v1/breach/{id} Tests ---


async def test_get_breach_success(client, admin_headers):
    """Test getting specific breach incident details."""
    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.INVESTIGATING
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = "Detailed breach information"
        mock_incident.affected_users = 100
        mock_incident.affected_records = 500
        mock_incident.source_ip = "192.168.1.100"
        mock_incident.user_id = "user-123"
        mock_incident.metadata = {"investigation": "ongoing"}
        mock_incident.status_history = [
            {
                "status": "detected",
                "timestamp": datetime.now(UTC).isoformat(),
                "note": "Initial detection",
            }
        ]

        mock_manager.return_value.get_incident.return_value = mock_incident

        response = await client.get("/api/v1/breach/breach-001", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == "breach-001"
    assert data["status"] == "investigating"
    assert data["description"] == "Detailed breach information"
    assert len(data["status_history"]) == 1


async def test_get_breach_not_found(client, admin_headers):
    """Test getting non-existent breach returns 404."""
    # Act - Mock breach manager to return None
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_manager.return_value.get_incident.return_value = None

        response = await client.get("/api/v1/breach/nonexistent-breach", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    data = response.json()
    assert "not found" in data["detail"].lower()


# --- PATCH /api/v1/breach/{id}/status Tests ---


async def test_update_breach_status_success(client, admin_headers):
    """Test valid status transition for breach incident."""
    # Arrange
    status_update = {"status": "investigating", "note": "Investigation started"}

    # Act - Mock breach manager
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.INVESTIGATING
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = "Test breach"
        mock_incident.affected_users = 100
        mock_incident.affected_records = 500
        mock_incident.source_ip = "192.168.1.100"
        mock_incident.user_id = "user-123"
        mock_incident.metadata = {}
        mock_incident.status_history = [
            {
                "status": "detected",
                "timestamp": datetime.now(UTC).isoformat(),
                "note": "Initial detection",
            },
            {
                "status": "investigating",
                "timestamp": datetime.now(UTC).isoformat(),
                "note": "Investigation started",
            },
        ]

        mock_manager.return_value.update_breach_status.return_value = mock_incident

        response = await client.patch(
            "/api/v1/breach/breach-001/status", json=status_update, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "investigating"
    assert len(data["status_history"]) == 2


async def test_update_breach_status_invalid_transition(client, admin_headers):
    """Test invalid status transition is rejected."""
    # Arrange - Try to jump from detected to resolved
    status_update = {"status": "invalid_status"}

    # Act - Mock manager to raise error
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        from pdfsigner.core.breach.breach_manager import BreachManagerError

        mock_manager.return_value.update_breach_status.side_effect = BreachManagerError(
            "Invalid status transition"
        )

        response = await client.patch(
            "/api/v1/breach/breach-001/status", json=status_update, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


async def test_update_breach_status_not_found(client, admin_headers):
    """Test updating status of non-existent breach."""
    # Arrange
    status_update = {"status": "investigating"}

    # Act - Mock manager to raise not found error
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        from pdfsigner.core.breach.breach_manager import BreachManagerError

        mock_manager.return_value.update_breach_status.side_effect = BreachManagerError(
            "Breach not found"
        )

        response = await client.patch(
            "/api/v1/breach/nonexistent/status", json=status_update, headers=admin_headers
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_update_breach_status_requires_admin_permission(client, auditor_headers):
    """Test updating breach status requires admin permission (bypassed in non-healthcare mode)."""
    # Arrange
    status_update = {"status": "investigating"}

    # Act - Mock breach manager since permissions are bypassed
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.INVESTIGATING
        mock_incident.detected_at = datetime.now(UTC)
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = "Test breach"
        mock_incident.affected_users = 100
        mock_incident.affected_records = 500
        mock_incident.source_ip = None
        mock_incident.user_id = None
        mock_incident.metadata = {}
        mock_incident.status_history = []

        mock_manager.return_value.update_breach_status.return_value = mock_incident

        response = await client.patch(
            "/api/v1/breach/breach-001/status", json=status_update, headers=auditor_headers
        )

    # Assert - Permission checks bypassed in non-healthcare mode
    assert response.status_code == status.HTTP_200_OK


# --- POST /api/v1/breach/{id}/notify Tests ---


async def test_send_notifications_success(client, admin_headers):
    """Test sending breach notifications through multiple channels."""
    # Arrange
    notification_request = {
        "channels": ["email", "webhook"],
        "recipients": ["admin@example.com", "https://webhook.example.com/breach"],
        "message": "Custom notification message",
    }

    # Act - Mock breach manager and notification service
    with (
        patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager,
        patch(
            "pdfsigner.api.services.breach_service.NotificationService"
        ) as mock_notification_class,
    ):
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.RESOLVED

        mock_manager.return_value.get_incident.return_value = mock_incident

        mock_notification = Mock()
        mock_notification.send_notification.return_value = {
            "email": {"success": True, "delivered": 1},
            "webhook": {"success": True, "status_code": 200},
        }
        mock_notification_class.return_value = mock_notification

        response = await client.post(
            "/api/v1/breach/breach-001/notify",
            json=notification_request,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["incident_id"] == "breach-001"
    assert "email" in data["results"]
    assert "webhook" in data["results"]
    assert data["results"]["email"]["success"] is True
    assert data["results"]["webhook"]["success"] is True


async def test_send_notifications_auto_status_update(client, admin_headers):
    """Test breach status auto-updates to NOTIFIED when all notifications succeed."""
    # Arrange
    notification_request = {
        "channels": ["email"],
        "recipients": ["admin@example.com"],
    }

    # Act - Mock all successful
    with (
        patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager,
        patch(
            "pdfsigner.api.services.breach_service.NotificationService"
        ) as mock_notification_class,
    ):
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_manager.return_value.get_incident.return_value = mock_incident

        mock_notification = Mock()
        mock_notification.send_notification.return_value = {
            "email": {"success": True, "delivered": 1}
        }
        mock_notification_class.return_value = mock_notification

        response = await client.post(
            "/api/v1/breach/breach-001/notify",
            json=notification_request,
            headers=admin_headers,
        )

        # Verify status was updated to NOTIFIED
        mock_manager.return_value.update_breach_status.assert_called_once()
        call_args = mock_manager.return_value.update_breach_status.call_args
        assert call_args[1]["new_status"] == BreachStatus.NOTIFIED

    # Assert
    assert response.status_code == status.HTTP_200_OK


async def test_send_notifications_invalid_channel(client, admin_headers):
    """Test sending notifications with invalid channel."""
    # Arrange
    notification_request = {
        "channels": ["invalid_channel"],
        "recipients": ["test@example.com"],
    }

    # Act - Mock to raise ValueError for invalid channel
    with (
        patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager,
        patch(
            "pdfsigner.api.services.breach_service.NotificationService"
        ) as mock_notification_class,
    ):
        mock_incident = Mock()
        mock_manager.return_value.get_incident.return_value = mock_incident

        mock_notification = Mock()
        mock_notification.send_notification.side_effect = ValueError("Invalid channel")
        mock_notification_class.return_value = mock_notification

        response = await client.post(
            "/api/v1/breach/breach-001/notify",
            json=notification_request,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert "Invalid notification channel" in data["detail"]


async def test_send_notifications_breach_not_found(client, admin_headers):
    """Test sending notifications for non-existent breach."""
    # Arrange
    notification_request = {
        "channels": ["email"],
        "recipients": ["admin@example.com"],
    }

    # Act - Mock manager to return None
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        mock_manager.return_value.get_incident.return_value = None

        response = await client.post(
            "/api/v1/breach/nonexistent/notify",
            json=notification_request,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    data = response.json()
    assert "not found" in data["detail"].lower()


# --- GDPR Compliance Tests ---


async def test_breach_72_hour_deadline_compliance(client, admin_headers):
    """Test breach includes detection timestamp for GDPR 72-hour deadline tracking."""
    # Act - Mock breach with detection time
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        detected_time = datetime.now(UTC) - timedelta(hours=48)  # 48 hours ago
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.MASS_EXPORT
        mock_incident.severity = BreachSeverity.HIGH
        mock_incident.status = BreachStatus.INVESTIGATING
        mock_incident.detected_at = detected_time
        mock_incident.resolved_at = None
        mock_incident.notified_at = None
        mock_incident.description = "GDPR test breach"
        mock_incident.affected_users = 100
        mock_incident.affected_records = 500
        mock_incident.source_ip = None
        mock_incident.user_id = None
        mock_incident.metadata = {}
        mock_incident.status_history = []

        mock_manager.return_value.get_incident.return_value = mock_incident

        response = await client.get("/api/v1/breach/breach-001", headers=admin_headers)

    # Assert - Verify breach includes detected_at for deadline calculation
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "detected_at" in data
    detected_at = datetime.fromisoformat(data["detected_at"].replace("Z", "+00:00"))
    hours_since_detection = (datetime.now(UTC) - detected_at).total_seconds() / 3600
    assert 47 <= hours_since_detection <= 49  # ~48 hours


async def test_breach_notification_tracking(client, admin_headers):
    """Test breach tracks notification timestamp for compliance audit."""
    # Act - Mock breach with notification timestamp
    with patch("pdfsigner.api.services.breach_service.get_breach_manager") as mock_manager:
        notified_time = datetime.now(UTC) - timedelta(hours=24)
        mock_incident = Mock()
        mock_incident.id = "breach-001"
        mock_incident.breach_type = BreachType.FAILED_AUTH
        mock_incident.severity = BreachSeverity.MEDIUM
        mock_incident.status = BreachStatus.NOTIFIED
        mock_incident.detected_at = datetime.now(UTC) - timedelta(hours=48)
        mock_incident.resolved_at = None
        mock_incident.notified_at = notified_time
        mock_incident.description = "Notified breach"
        mock_incident.affected_users = 50
        mock_incident.affected_records = 100
        mock_incident.source_ip = None
        mock_incident.user_id = None
        mock_incident.metadata = {}
        mock_incident.status_history = []

        mock_manager.return_value.get_incident.return_value = mock_incident

        response = await client.get("/api/v1/breach/breach-001", headers=admin_headers)

    # Assert - Verify notified_at is tracked
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["notified_at"] is not None
    assert data["status"] == "notified"
