"""
Integration tests for Evidence API (SOC 2 compliance).

Tests SOC 2 evidence collection and reporting endpoints.

Run with:
    uv run pytest tests/integration/test_api_evidence.py -v
    uv run pytest tests/integration/test_api_evidence.py -v --cov=src/pdfsigner/api/routes/evidence
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
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def auditor_token():
    """Create valid JWT token with auditor role."""
    token = create_access_token(
        data={"sub": "auditor", "role": "auditor"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auditor_headers(auditor_token):
    """Create authentication headers with auditor JWT token."""
    return {"Authorization": f"Bearer {auditor_token}"}


@pytest.fixture
def signer_token():
    """Create valid JWT token with signer role (no AUDIT_VIEW permission)."""
    token = create_access_token(
        data={"sub": "signer", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def signer_headers(signer_token):
    """Create authentication headers with signer JWT token."""
    return {"Authorization": f"Bearer {signer_token}"}


# --- Evidence Collection Tests ---


async def test_collect_evidence_success(client, auditor_headers):
    """Test successful evidence collection."""
    # Arrange
    request_data = {
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-01-31T23:59:59Z",
    }

    # Act - Mock evidence collector
    with patch("pdfsigner.api.services.evidence_service.get_evidence_collector") as mock_collector:
        mock_instance = Mock()
        mock_collection = Mock()
        mock_collection.evidence_items = []
        mock_collection.summary = {"total_evidence": 0}
        mock_collection.period_start = datetime(2026, 1, 1, tzinfo=UTC)
        mock_collection.period_end = datetime(2026, 1, 31, tzinfo=UTC)
        mock_collection.collected_at = datetime.now(UTC)
        mock_instance.collect_all_evidence.return_value = mock_collection
        mock_collector.return_value = mock_instance

        response = await client.post(
            "/api/v1/compliance/evidence/collect", json=request_data, headers=auditor_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "evidence_items" in data
    assert "summary" in data
    assert "period_start" in data
    assert "period_end" in data


async def test_collect_evidence_invalid_date_range(client, auditor_headers):
    """Test evidence collection fails with invalid date range."""
    # Arrange - End date before start date
    request_data = {
        "period_start": "2026-01-31T00:00:00Z",
        "period_end": "2026-01-01T00:00:00Z",
    }

    # Act
    response = await client.post(
        "/api/v1/compliance/evidence/collect", json=request_data, headers=auditor_headers
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "period_end must be after period_start" in response.json()["detail"]


async def test_collect_evidence_unauthorized(client, signer_headers):
    """Test evidence collection fails without AUDIT_VIEW permission."""
    # Arrange
    request_data = {
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-01-31T23:59:59Z",
    }

    # Act - Mock authorization service to deny permission
    with patch(
        "pdfsigner.core.rbac.authorization.AuthorizationService.has_permission"
    ) as mock_has_permission:
        mock_has_permission.return_value = False

        response = await client.post(
            "/api/v1/compliance/evidence/collect", json=request_data, headers=signer_headers
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_collect_evidence_no_auth(client):
    """Test evidence collection fails without authentication."""
    # Arrange
    request_data = {
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-01-31T23:59:59Z",
    }

    # Act
    response = await client.post("/api/v1/compliance/evidence/collect", json=request_data)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- List Evidence Tests ---


async def test_list_evidence_empty(client, auditor_headers):
    """Test listing evidence returns empty list."""
    # Act
    response = await client.get("/api/v1/compliance/evidence/", headers=auditor_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


async def test_list_evidence_unauthorized(client, signer_headers):
    """Test listing evidence fails without AUDIT_VIEW permission."""
    # Act - Mock authorization service to deny permission
    with patch(
        "pdfsigner.core.rbac.authorization.AuthorizationService.has_permission"
    ) as mock_has_permission:
        mock_has_permission.return_value = False

        response = await client.get("/api/v1/compliance/evidence/", headers=signer_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


# --- Get Evidence Tests ---


async def test_get_evidence_not_found(client, auditor_headers):
    """Test getting non-existent evidence returns 404."""
    # Act
    response = await client.get(
        "/api/v1/compliance/evidence/nonexistent-id", headers=auditor_headers
    )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- SOC 2 Report Tests ---


async def test_generate_soc2_report_success(client, auditor_headers):
    """Test successful SOC 2 report generation."""
    # Arrange
    request_data = {
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-01-31T23:59:59Z",
        "include_evidence": True,
    }

    # Act - Mock collector and report generator
    with (
        patch("pdfsigner.api.services.evidence_service.get_evidence_collector") as mock_collector,
        patch("pdfsigner.api.services.evidence_service.generate_report") as mock_report_gen,
    ):
        # Mock evidence collection
        mock_instance = Mock()
        mock_collection = Mock()
        mock_collection.evidence_items = []
        mock_instance.collect_all_evidence.return_value = mock_collection
        mock_collector.return_value = mock_instance

        # Mock report generation
        mock_report = Mock()
        mock_report.period_start = datetime(2026, 1, 1, tzinfo=UTC)
        mock_report.period_end = datetime(2026, 1, 31, tzinfo=UTC)
        mock_report.generated_at = datetime.now(UTC)
        mock_report.controls = []
        mock_report.summary = {"total_controls": 0}
        mock_report.recommendations = []
        mock_report_gen.return_value = mock_report

        response = await client.post(
            "/api/v1/compliance/evidence/soc2/report",
            json=request_data,
            headers=auditor_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "period_start" in data
    assert "period_end" in data
    assert "controls" in data
    assert "summary" in data


async def test_generate_soc2_report_invalid_dates(client, auditor_headers):
    """Test SOC 2 report generation fails with invalid date range."""
    # Arrange - End date before start date
    request_data = {
        "period_start": "2026-01-31T00:00:00Z",
        "period_end": "2026-01-01T00:00:00Z",
    }

    # Act
    response = await client.post(
        "/api/v1/compliance/evidence/soc2/report", json=request_data, headers=auditor_headers
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


# --- SOC 2 Export Tests ---


async def test_export_soc2_report_success(client, auditor_headers):
    """Test successful SOC 2 export generation."""
    # Arrange
    params = {
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-01-31T23:59:59Z",
    }

    # Act - Mock collector and report generator
    with (
        patch("pdfsigner.api.services.evidence_service.get_evidence_collector") as mock_collector,
        patch("pdfsigner.api.services.evidence_service.generate_report") as mock_report_gen,
    ):
        # Mock evidence collection
        mock_instance = Mock()
        mock_collection = Mock()
        mock_collection.evidence_items = []
        mock_collection.to_dict.return_value = {}
        mock_instance.collect_all_evidence.return_value = mock_collection
        mock_collector.return_value = mock_instance

        # Mock report generation
        mock_report = Mock()
        mock_report.to_dict.return_value = {
            "period_start": "2026-01-01T00:00:00Z",
            "period_end": "2026-01-31T23:59:59Z",
        }
        mock_report.summary = {"total_controls": 0}
        mock_report.export_to_markdown.return_value = "# SOC 2 Report"
        mock_report_gen.return_value = mock_report

        response = await client.get(
            "/api/v1/compliance/evidence/soc2/export", params=params, headers=auditor_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "filename" in data
    assert "size_bytes" in data
    assert "checksum" in data
    assert "download_url" in data


async def test_export_soc2_report_invalid_dates(client, auditor_headers):
    """Test SOC 2 export fails with invalid date format."""
    # Arrange
    params = {
        "period_start": "invalid-date",
        "period_end": "2026-01-31T00:00:00Z",
    }

    # Act
    response = await client.get(
        "/api/v1/compliance/evidence/soc2/export", params=params, headers=auditor_headers
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


async def test_download_export_not_found(client, auditor_headers):
    """Test downloading non-existent export returns 404."""
    # Act
    response = await client.get(
        "/api/v1/compliance/evidence/export/nonexistent.zip", headers=auditor_headers
    )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
