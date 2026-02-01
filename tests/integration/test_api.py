"""
Integration tests for PDFSigner REST API.

Tests all API endpoints with authentication, validation, and error handling.
Uses httpx for async testing and mocks for external dependencies.

Run with:
    uv run pytest tests/integration/test_api.py -v
    uv run pytest tests/integration/test_api.py -v --cov=src/pdfsigner/api
"""

import tempfile
from datetime import UTC, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token

# Mark all tests in this module as anyio (use anyio for async support)
pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
def api_settings():
    """Get API settings for tests."""
    settings = get_api_settings()
    # Override for testing
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
    """Create valid JWT token for testing."""
    token = create_access_token(
        data={"sub": "testuser", "role": "signer"},  # Updated for RBAC
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
def api_key_headers(api_settings):
    """Create authentication headers with API key."""
    return {"X-API-Key": "test-api-key-123"}


@pytest.fixture
def sample_pdf():
    """
    Create minimal valid PDF for testing.

    Returns PDF bytes that can be used with files parameter.
    """
    # Minimal valid PDF structure
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Resources 4 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>
endobj
4 0 obj
<< /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >>
endobj
5 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Test PDF) Tj
ET
endstream
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000230 00000 n
0000000330 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
422
%%EOF
"""
    return pdf_content


@pytest.fixture
def sample_pdf_file(sample_pdf):
    """Create temporary PDF file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(sample_pdf)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    temp_path.unlink(missing_ok=True)


# --- Health & Auth Tests ---


async def test_health_check(client):
    """Test health check endpoint returns healthy status."""
    # Act
    response = await client.get("/health")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


async def test_auth_token_success(client):
    """Test successful authentication with valid credentials."""
    # Arrange
    credentials = {"username": "testuser", "password": "testpass"}

    # Act
    response = await client.post("/auth/token", json=credentials)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data


async def test_auth_token_empty_credentials(client):
    """Test authentication fails with empty credentials."""
    # Arrange
    credentials = {"username": "", "password": ""}

    # Act
    response = await client.post("/auth/token", json=credentials)

    # Assert - Pydantic validation fails before auth check
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()


async def test_auth_refresh_token(client, auth_headers):
    """Test token refresh with valid token."""
    # Act
    response = await client.post("/auth/refresh", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


async def test_auth_get_user_info(client, auth_headers):
    """Test retrieving current user information."""
    # Act
    response = await client.get("/auth/me", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "testuser"
    assert "email" in data
    assert data["role"] == "signer"  # Updated for RBAC: default role is signer
    assert data["disabled"] is False


async def test_protected_endpoint_without_auth(client):
    """Test protected endpoint returns 401 without authentication."""
    # Act
    response = await client.get("/api/v1/certificates/tokens")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_protected_endpoint_with_invalid_token(client):
    """Test protected endpoint returns 401 with invalid token."""
    # Arrange
    invalid_headers = {"Authorization": "Bearer invalid-token-123"}

    # Act
    response = await client.get("/api/v1/certificates/tokens", headers=invalid_headers)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_api_key_authentication(client, api_key_headers):
    """Test API key authentication works for protected endpoints."""
    # Act - Mock to avoid NSS errors
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        mock_instance = Mock()
        mock_instance.get_available_tokens.return_value = []
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/tokens", headers=api_key_headers)

    # Assert
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_503_SERVICE_UNAVAILABLE]


# --- Validate Tests ---


async def test_validate_unsigned_pdf(client, auth_headers, sample_pdf):
    """Test validating unsigned PDF returns correct status."""
    # Arrange
    files = {"file": ("test.pdf", sample_pdf, "application/pdf")}

    # Act
    response = await client.post("/api/v1/validate/", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["filename"] == "test.pdf"
    assert data["is_signed"] is False
    assert data["signature_count"] == 0


async def test_validate_missing_file(client, auth_headers):
    """Test validation fails when no file provided."""
    # Act
    response = await client.post("/api/v1/validate/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_validate_invalid_file_type(client, auth_headers):
    """Test validation fails with non-PDF file."""
    # Arrange
    files = {"file": ("test.txt", b"Not a PDF", "text/plain")}

    # Act
    response = await client.post("/api/v1/validate/", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "PDF" in response.json()["detail"]


async def test_validate_empty_file(client, auth_headers):
    """Test validation fails with empty file."""
    # Arrange
    files = {"file": ("empty.pdf", b"", "application/pdf")}

    # Act
    response = await client.post("/api/v1/validate/", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


async def test_validate_batch_success(client, auth_headers, sample_pdf):
    """Test batch validation with multiple PDFs."""
    # Arrange
    files = [
        ("files", ("test1.pdf", sample_pdf, "application/pdf")),
        ("files", ("test2.pdf", sample_pdf, "application/pdf")),
    ]

    # Act
    response = await client.post("/api/v1/validate/batch", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert len(data["results"]) == 2


async def test_validate_batch_empty(client, auth_headers):
    """Test batch validation fails with no files."""
    # Act
    response = await client.post("/api/v1/validate/batch", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_validate_batch_too_many_files(client, auth_headers, sample_pdf):
    """Test batch validation fails with too many files."""
    # Arrange - Create 51 files (over the limit of 50)
    files = [("files", (f"test{i}.pdf", sample_pdf, "application/pdf")) for i in range(51)]

    # Act
    response = await client.post("/api/v1/validate/batch", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


# --- Sign Tests ---


async def test_sign_returns_job_id(client, auth_headers, sample_pdf):
    """Test signing endpoint returns job ID for async processing."""
    # Arrange
    files = {"file": ("document.pdf", sample_pdf, "application/pdf")}

    # Act - Mock NSS and LTA handlers
    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        response = await client.post("/api/v1/sign/", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "pending"
    assert "message" in data


async def test_sign_with_parameters(client, auth_headers, sample_pdf):
    """Test signing with custom parameters."""
    # Arrange
    files = {"file": ("document.pdf", sample_pdf, "application/pdf")}
    params = {
        "reason": "Approval",
        "location": "Buenos Aires",
        "visible_signature": True,
        "embed_ltv": True,
    }

    # Act - Mock dependencies
    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        response = await client.post(
            "/api/v1/sign/", files=files, params=params, headers=auth_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "job_id" in data


async def test_sign_invalid_file_type(client, auth_headers):
    """Test signing fails with non-PDF file."""
    # Arrange
    files = {"file": ("document.txt", b"Not a PDF", "text/plain")}

    # Act - Mock handlers even though validation should fail before they're used
    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        response = await client.post("/api/v1/sign/", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


async def test_sign_no_filename(client, auth_headers):
    """Test signing fails with no filename."""
    # Arrange
    files = {"file": ("", b"%PDF-1.4", "application/pdf")}

    # Act - Mock handlers
    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        response = await client.post("/api/v1/sign/", files=files, headers=auth_headers)

    # Assert - FastAPI validates file before business logic
    assert response.status_code in [
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
    ]


async def test_sign_file_too_large(client, auth_headers, api_settings):
    """Test signing fails with file exceeding size limit."""
    # Arrange - Create file larger than max_upload_size_mb
    large_content = b"x" * (api_settings.max_upload_size_mb * 1024 * 1024 + 1)
    files = {"file": ("large.pdf", large_content, "application/pdf")}

    # Act - Mock handlers
    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        response = await client.post("/api/v1/sign/", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


async def test_get_sign_status_not_found(client, auth_headers):
    """Test getting status of non-existent job."""
    # Arrange
    fake_job_id = "00000000-0000-0000-0000-000000000000"

    # Act
    response = await client.get(f"/api/v1/sign/{fake_job_id}/status", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_get_sign_status_success(client, auth_headers, sample_pdf):
    """Test getting status of existing job."""
    # Arrange - Create a job first
    files = {"file": ("document.pdf", sample_pdf, "application/pdf")}

    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        create_response = await client.post("/api/v1/sign/", files=files, headers=auth_headers)
        job_id = create_response.json()["job_id"]

        # Act
        status_response = await client.get(f"/api/v1/sign/{job_id}/status", headers=auth_headers)

    # Assert
    assert status_response.status_code == status.HTTP_200_OK
    data = status_response.json()
    assert data["job_id"] == job_id
    assert "status" in data
    assert "filename" in data


async def test_download_signed_pdf_not_found(client, auth_headers):
    """Test downloading non-existent signed PDF."""
    # Arrange
    fake_job_id = "00000000-0000-0000-0000-000000000000"

    # Act
    response = await client.get(f"/api/v1/sign/{fake_job_id}/download", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_download_signed_pdf_not_completed(client, auth_headers, sample_pdf):
    """Test downloading PDF from incomplete job."""
    # Arrange - Create a job
    files = {"file": ("document.pdf", sample_pdf, "application/pdf")}

    with (
        patch("pdfsigner.api.routes.sign.NSSHandler") as mock_nss_class,
        patch("pdfsigner.api.routes.sign.LTAHandler") as mock_lta_class,
    ):
        mock_nss_class.return_value = Mock()
        mock_lta_class.return_value = None

        create_response = await client.post("/api/v1/sign/", files=files, headers=auth_headers)
        job_id = create_response.json()["job_id"]

        # Act - Try to download immediately (job is pending)
        download_response = await client.get(
            f"/api/v1/sign/{job_id}/download", headers=auth_headers
        )

    # Assert
    assert download_response.status_code == status.HTTP_400_BAD_REQUEST


async def test_sign_health_check(client):
    """Test signing service health check."""
    # Act
    response = await client.get("/api/v1/sign/health")

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "signing"


# --- Certificate Tests ---


async def test_list_tokens_without_nss(client, auth_headers):
    """Test listing tokens returns service unavailable without NSS."""
    # Act - Mock service to return error
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        from pdfsigner.exceptions import NSSConfigError

        mock_instance = Mock()
        mock_instance.get_available_tokens.side_effect = NSSConfigError("NSS not configured")
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/tokens", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


async def test_list_tokens_success(client, auth_headers):
    """Test listing tokens returns available tokens."""
    # Act - Mock service
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        mock_instance = Mock()
        mock_instance.get_available_tokens.return_value = ["Token1", "Token2"]
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/tokens", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2


async def test_list_certificates_empty(client, auth_headers):
    """Test listing certificates returns empty list without token."""
    # Act - Mock service
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        mock_instance = Mock()
        mock_instance.list_certificates.return_value = []
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


async def test_list_certificates_with_token_label(client, auth_headers):
    """Test listing certificates with specific token label."""
    # Act - Mock service
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        from datetime import datetime

        from pdfsigner.api.schemas.certificates import CertificateInfo

        mock_instance = Mock()
        mock_instance.list_certificates.return_value = [
            CertificateInfo(
                id="abc123",
                subject="CN=Test User",
                issuer="CN=Test CA",
                serial_number="123456",
                not_before=datetime(2024, 1, 1, tzinfo=UTC),
                not_after=datetime(2025, 1, 1, tzinfo=UTC),
                is_expired=False,
                days_until_expiry=365,
            )
        ]
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get(
            "/api/v1/certificates/",
            params={"token_label": "MyToken", "pin": "1234"},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)


async def test_get_certificate_not_found(client, auth_headers):
    """Test getting non-existent certificate."""
    # Act - Mock service
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        from pdfsigner.exceptions import CertificateNotFoundError

        mock_instance = Mock()
        mock_instance.get_certificate.side_effect = CertificateNotFoundError("Not found")
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/invalid-id", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_get_certificate_success(client, auth_headers):
    """Test getting certificate by ID."""
    # Act - Mock service
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        from datetime import datetime

        from pdfsigner.api.schemas.certificates import CertificateInfo

        mock_instance = Mock()
        mock_instance.get_certificate.return_value = CertificateInfo(
            id="abc123",
            subject="CN=Test User",
            issuer="CN=Test CA",
            serial_number="123456",
            not_before=datetime(2024, 1, 1, tzinfo=UTC),
            not_after=datetime(2025, 1, 1, tzinfo=UTC),
            is_expired=False,
            days_until_expiry=365,
        )
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/abc123", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK


async def test_get_certificate_chain(client, auth_headers):
    """Test getting certificate chain."""
    # Act - Mock service
    with patch("pdfsigner.api.routes.certificates.CertificateService") as mock_service:
        from datetime import datetime

        from pdfsigner.api.schemas.certificates import CertificateChain, CertificateInfo

        mock_instance = Mock()
        mock_instance.get_certificate_chain.return_value = CertificateChain(
            certificates=[
                CertificateInfo(
                    id="aaa",
                    subject="CN=End Entity",
                    issuer="CN=Intermediate CA",
                    serial_number="111",
                    not_before=datetime(2024, 1, 1, tzinfo=UTC),
                    not_after=datetime(2025, 1, 1, tzinfo=UTC),
                    is_expired=False,
                    days_until_expiry=365,
                ),
                CertificateInfo(
                    id="bbb",
                    subject="CN=Intermediate CA",
                    issuer="CN=Root CA",
                    serial_number="222",
                    not_before=datetime(2023, 1, 1, tzinfo=UTC),
                    not_after=datetime(2026, 1, 1, tzinfo=UTC),
                    is_expired=False,
                    days_until_expiry=730,
                ),
            ],
            is_complete=True,
            validation_errors=[],
        )
        mock_instance.close.return_value = None
        mock_service.return_value = mock_instance

        response = await client.get("/api/v1/certificates/abc123/chain", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "certificates" in data
    assert len(data["certificates"]) == 2


# --- Error Handling Tests ---


async def test_invalid_json_request(client, auth_headers):
    """Test API handles invalid JSON gracefully."""
    # Act
    response = await client.post(
        "/auth/token",
        content=b"invalid-json",
        headers={"Content-Type": "application/json"},
    )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_method_not_allowed(client):
    """Test API returns 405 for unsupported methods."""
    # Act
    response = await client.put("/health")

    # Assert
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


async def test_not_found_route(client):
    """Test API returns 404 for non-existent routes."""
    # Act
    response = await client.get("/api/v1/nonexistent")

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- Token Expiration Tests ---


async def test_expired_token(client, api_settings):
    """Test API rejects expired tokens."""
    # Arrange - Create expired token
    expired_token = create_access_token(
        data={"sub": "testuser", "role": "user"},
        expires_delta=timedelta(seconds=-1),  # Already expired
    )
    headers = {"Authorization": f"Bearer {expired_token}"}

    # Act
    response = await client.get("/auth/me", headers=headers)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_malformed_token(client):
    """Test API rejects malformed JWT tokens."""
    # Arrange
    headers = {"Authorization": "Bearer malformed.token.here"}

    # Act
    response = await client.get("/auth/me", headers=headers)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Role-Based Access Tests ---


async def test_admin_role_in_token(client, admin_headers):
    """Test admin role is correctly set in token."""
    # Act
    response = await client.get("/auth/me", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["role"] == "admin"


async def test_user_role_in_token(client, auth_headers):
    """Test user role is correctly set in token."""
    # Act
    response = await client.get("/auth/me", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["role"] == "signer"  # Updated for RBAC: default role is signer
