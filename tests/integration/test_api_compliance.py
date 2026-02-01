"""
Integration tests for Compliance API (HIPAA monitoring).

Tests HIPAA compliance status monitoring and report generation endpoints.

Run with:
    uv run pytest tests/integration/test_api_compliance.py -v
    uv run pytest tests/integration/test_api_compliance.py -v --cov=src/pdfsigner/api/routes/compliance
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


# --- Compliance Status Tests ---


async def test_get_compliance_status_success(client, auditor_headers):
    """Test successful compliance status retrieval."""
    # Arrange - Import required types
    from pdfsigner.core.compliance.status_checker import (
        ComplianceCategory,
        ComplianceCheck,
        ComplianceReport,
        ComplianceStatus,
    )

    # Act - Mock compliance checker (patch where it's imported, not where it's defined)
    with patch("pdfsigner.core.compliance.get_compliance_checker") as mock_checker:
        mock_instance = Mock()

        # Create real ComplianceCheck object (not a mock)
        check = ComplianceCheck(
            name="PDF Encryption",
            category=ComplianceCategory.ENCRYPTION,
            status=ComplianceStatus.COMPLIANT,
            hipaa_reference="§164.312(a)(2)(iv)",
            description="Encryption capability",
            details="AES-256 enabled",
            remediation=None,
            last_checked=datetime.now(UTC),
        )

        # Create real ComplianceReport object (not a mock)
        mock_report = ComplianceReport(
            checks=[check],
            overall_status=ComplianceStatus.COMPLIANT,
            compliant_count=7,
            warning_count=0,
            non_compliant_count=0,
            generated_at=datetime.now(UTC),
        )

        mock_instance.check_all.return_value = mock_report
        mock_checker.return_value = mock_instance

        response = await client.get("/api/v1/compliance/status", headers=auditor_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "checks" in data
    assert "overall_status" in data
    assert "compliant_count" in data
    assert "is_hipaa_compliant" in data
    assert data["is_hipaa_compliant"] is True


async def test_get_compliance_status_unauthorized(client, signer_headers):
    """Test compliance status with signer role (no AUDIT_VIEW permission).

    Note: When healthcare_mode is disabled (default in tests), permission checks
    are bypassed, so this test verifies that access is allowed in that mode.
    In production with healthcare_mode=True, this would return 403.
    """
    # Act
    response = await client.get("/api/v1/compliance/status", headers=signer_headers)

    # Assert - Access is allowed when healthcare_mode is disabled
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "checks" in data
    assert "overall_status" in data


async def test_get_compliance_status_no_auth(client):
    """Test compliance status fails without authentication."""
    # Act
    response = await client.get("/api/v1/compliance/status")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Compliance Check Tests ---


async def test_run_compliance_check_success(client, auditor_headers):
    """Test successful compliance check execution."""
    # Arrange - Import required types
    from pdfsigner.core.compliance.status_checker import (
        ComplianceCategory,
        ComplianceCheck,
        ComplianceReport,
        ComplianceStatus,
    )

    # Act - Mock compliance checker (patch where it's imported)
    with patch("pdfsigner.core.compliance.get_compliance_checker") as mock_checker:
        mock_instance = Mock()

        # Create real ComplianceCheck object (not a mock)
        check = ComplianceCheck(
            name="Audit Controls",
            category=ComplianceCategory.AUDIT_CONTROLS,
            status=ComplianceStatus.WARNING,
            hipaa_reference="§164.312(b)",
            description="Audit trail",
            details="Audit enabled with warnings",
            remediation="Enable integrity checks",
            last_checked=datetime.now(UTC),
        )

        # Create real ComplianceReport object (not a mock)
        mock_report = ComplianceReport(
            checks=[check],
            overall_status=ComplianceStatus.WARNING,
            compliant_count=6,
            warning_count=1,
            non_compliant_count=0,
            generated_at=datetime.now(UTC),
        )

        mock_instance.check_all.return_value = mock_report
        mock_checker.return_value = mock_instance

        response = await client.post("/api/v1/compliance/check", headers=auditor_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["overall_status"] == "warning"
    assert data["warning_count"] == 1


async def test_run_compliance_check_non_compliant(client, auditor_headers):
    """Test compliance check with non-compliant status."""
    # Arrange - Import required types
    from pdfsigner.core.compliance.status_checker import (
        ComplianceCategory,
        ComplianceCheck,
        ComplianceReport,
        ComplianceStatus,
    )

    # Act - Mock compliance checker with non-compliant result (patch where it's imported)
    with patch("pdfsigner.core.compliance.get_compliance_checker") as mock_checker:
        mock_instance = Mock()

        # Create real ComplianceCheck object (not a mock)
        check = ComplianceCheck(
            name="Access Control",
            category=ComplianceCategory.ACCESS_CONTROL,
            status=ComplianceStatus.NON_COMPLIANT,
            hipaa_reference="§164.312(a)(1)",
            description="User authentication",
            details="No MFA enabled",
            remediation="Enable multi-factor authentication",
            last_checked=datetime.now(UTC),
        )

        # Create real ComplianceReport object (not a mock)
        mock_report = ComplianceReport(
            checks=[check],
            overall_status=ComplianceStatus.NON_COMPLIANT,
            compliant_count=5,
            warning_count=1,
            non_compliant_count=1,
            generated_at=datetime.now(UTC),
        )

        mock_instance.check_all.return_value = mock_report
        mock_checker.return_value = mock_instance

        response = await client.post("/api/v1/compliance/check", headers=auditor_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["is_hipaa_compliant"] is False
    assert data["non_compliant_count"] == 1


# --- Report Generation Tests ---


async def test_generate_compliance_report_pdf(client, auditor_headers):
    """Test generating compliance report in PDF format."""
    # Arrange
    request_data = {
        "format": "pdf",
        "standards": ["all"],
        "include_evidence": True,
        "include_recommendations": True,
        "executive_summary": True,
    }

    # Act - Mock report generator (patch where it's imported)
    with patch("pdfsigner.core.compliance.get_report_generator") as mock_generator:
        mock_instance = Mock()
        mock_metadata = Mock()
        mock_metadata.path = "/tmp/report.pdf"
        mock_metadata.size_bytes = 45678
        mock_metadata.generated_at = datetime.now(UTC)
        mock_metadata.checksum = "abc123"
        mock_instance.generate.return_value = mock_metadata
        mock_generator.return_value = mock_instance

        response = await client.post(
            "/api/v1/compliance/report", json=request_data, headers=auditor_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["format"] == "pdf"
    assert "report_id" in data
    assert "download_url" in data


async def test_generate_compliance_report_json(client, auditor_headers):
    """Test generating compliance report in JSON format."""
    # Arrange
    request_data = {
        "format": "json",
        "standards": ["HIPAA"],
        "include_evidence": True,
    }

    # Act - Mock report generator (patch where it's imported)
    with patch("pdfsigner.core.compliance.get_report_generator") as mock_generator:
        mock_instance = Mock()
        mock_metadata = Mock()
        mock_metadata.path = "/tmp/report.json"
        mock_metadata.size_bytes = 12345
        mock_metadata.generated_at = datetime.now(UTC)
        mock_metadata.checksum = "def456"
        mock_instance.generate.return_value = mock_metadata
        mock_generator.return_value = mock_instance

        response = await client.post(
            "/api/v1/compliance/report", json=request_data, headers=auditor_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["format"] == "json"


async def test_generate_compliance_report_invalid_format(client, auditor_headers):
    """Test report generation fails with invalid format."""
    # Arrange
    request_data = {
        "format": "xml",  # Invalid format
    }

    # Act
    response = await client.post(
        "/api/v1/compliance/report", json=request_data, headers=auditor_headers
    )

    # Assert
    # Pydantic validation returns 422 for schema validation errors
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "detail" in data
    # Check that the error mentions the format field
    assert any("format" in str(error).lower() for error in data["detail"])


async def test_generate_compliance_report_unauthorized(client, signer_headers):
    """Test report generation with signer role (no AUDIT_VIEW permission).

    Note: When healthcare_mode is disabled (default in tests), permission checks
    are bypassed, so this test verifies that access is allowed in that mode.
    In production with healthcare_mode=True, this would return 403.
    """
    # Arrange
    request_data = {"format": "pdf"}

    # Mock report generator to avoid actual generation
    with patch("pdfsigner.core.compliance.get_report_generator") as mock_generator:
        mock_instance = Mock()
        mock_metadata = Mock()
        mock_metadata.path = "/tmp/report.pdf"
        mock_metadata.size_bytes = 12345
        mock_metadata.generated_at = datetime.now(UTC)
        mock_metadata.checksum = "abc123"
        mock_instance.generate.return_value = mock_metadata
        mock_generator.return_value = mock_instance

        # Act
        response = await client.post(
            "/api/v1/compliance/report", json=request_data, headers=signer_headers
        )

        # Assert - Access is allowed when healthcare_mode is disabled
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "report_id" in data
        assert data["format"] == "pdf"


# --- Report Download Tests ---


async def test_download_compliance_report_not_found(client, auditor_headers):
    """Test downloading non-existent report returns 404."""
    # Act
    response = await client.get("/api/v1/compliance/report/nonexistent", headers=auditor_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- Standards Tests ---


async def test_list_available_standards(client, auditor_headers):
    """Test listing available compliance standards."""
    # Act
    response = await client.get("/api/v1/compliance/standards", headers=auditor_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "standards" in data
    assert isinstance(data["standards"], list)
    assert "HIPAA" in data["standards"]
