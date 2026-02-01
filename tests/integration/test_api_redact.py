"""
Integration tests for Redaction API.

Tests document redaction endpoints for PII/PHI removal.

Run with:
    uv run pytest tests/integration/test_api_redact.py -v
    uv run pytest tests/integration/test_api_redact.py -v --cov=src/pdfsigner/api/routes/redact
"""

from datetime import timedelta
from io import BytesIO
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
def auth_token():
    """Create valid JWT token with signer role."""
    token = create_access_token(
        data={"sub": "testuser", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auth_headers(auth_token):
    """Create authentication headers with JWT token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def sample_pdf():
    """Create minimal valid PDF for testing."""
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


# --- Redact Regions Tests ---


async def test_redact_regions_success(client, auth_headers, sample_pdf):
    """Test successful region-based redaction."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {
        "regions": [
            {"page": 0, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0},
        ],
        "output_filename": "redacted.pdf",
    }

    # Act - Mock redactor
    with patch("pdfsigner.api.routes.redact.get_pdf_redactor") as mock_redactor:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.output_path = "/tmp/redacted.pdf"
        mock_result.redaction_count = 1
        mock_result.pages_affected = [0]
        mock_result.errors = []
        mock_instance.redact_regions.return_value = mock_result
        mock_redactor.return_value = mock_instance

        response = await client.post(
            "/api/v1/redact/regions",
            files=files,
            data={"request": json.dumps(request_data)},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["redaction_count"] == 1


async def test_redact_regions_invalid_file_type(client, auth_headers):
    """Test redaction fails with non-PDF file."""
    # Arrange
    import json

    files = {"file": ("document.txt", BytesIO(b"Not a PDF"), "text/plain")}
    request_data = {"regions": [{"page": 0, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0}]}

    # Act
    response = await client.post(
        "/api/v1/redact/regions",
        files=files,
        data={"request": json.dumps(request_data)},
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "PDF" in response.json()["detail"]


async def test_redact_regions_unauthorized(client, sample_pdf):
    """Test redaction fails without authentication."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {"regions": [{"page": 0, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0}]}

    # Act
    response = await client.post(
        "/api/v1/redact/regions", files=files, data={"request": json.dumps(request_data)}
    )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Auto-Redact Tests ---


async def test_redact_auto_success(client, auth_headers, sample_pdf):
    """Test successful automatic PII redaction."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {
        "pii_types": ["ssn", "credit_card"],
        "min_confidence": 0.7,
        "output_filename": "redacted.pdf",
    }

    # Act - Mock redactor
    with patch("pdfsigner.api.routes.redact.get_pdf_redactor") as mock_redactor:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.output_path = "/tmp/redacted.pdf"
        mock_result.redaction_count = 2
        mock_result.pages_affected = [0]
        mock_result.errors = []
        mock_instance.redact_by_pattern.return_value = mock_result
        mock_redactor.return_value = mock_instance

        response = await client.post(
            "/api/v1/redact/auto",
            files=files,
            data={"request": json.dumps(request_data)},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["redaction_count"] == 2


async def test_redact_auto_no_pii_detected(client, auth_headers, sample_pdf):
    """Test auto-redaction with no PII detected."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {
        "pii_types": ["ssn"],
        "min_confidence": 0.7,
    }

    # Act - Mock redactor with no redactions
    with patch("pdfsigner.api.routes.redact.get_pdf_redactor") as mock_redactor:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.output_path = "/tmp/document.pdf"
        mock_result.redaction_count = 0
        mock_result.pages_affected = []
        mock_result.errors = []
        mock_instance.redact_by_pattern.return_value = mock_result
        mock_redactor.return_value = mock_instance

        response = await client.post(
            "/api/v1/redact/auto",
            files=files,
            data={"request": json.dumps(request_data)},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert data["redaction_count"] == 0
    assert "No PII" in data["message"]


async def test_redact_auto_invalid_file_type(client, auth_headers):
    """Test auto-redaction fails with non-PDF file."""
    # Arrange
    import json

    files = {"file": ("document.txt", BytesIO(b"Not a PDF"), "text/plain")}
    request_data = {"pii_types": ["ssn"]}

    # Act
    response = await client.post(
        "/api/v1/redact/auto",
        files=files,
        data={"request": json.dumps(request_data)},
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


async def test_redact_auto_multiple_pii_types(client, auth_headers, sample_pdf):
    """Test auto-redaction with multiple PII types."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {
        "pii_types": ["ssn", "credit_card", "email", "phone"],
        "min_confidence": 0.8,
    }

    # Act - Mock redactor
    with patch("pdfsigner.api.routes.redact.get_pdf_redactor") as mock_redactor:
        mock_instance = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.output_path = "/tmp/redacted.pdf"
        mock_result.redaction_count = 4
        mock_result.pages_affected = [0, 1]
        mock_result.errors = []
        mock_instance.redact_by_pattern.return_value = mock_result
        mock_redactor.return_value = mock_instance

        response = await client.post(
            "/api/v1/redact/auto",
            files=files,
            data={"request": json.dumps(request_data)},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["redaction_count"] == 4


# --- Preview Tests ---


async def test_preview_redactions_success(client, auth_headers, sample_pdf):
    """Test successful redaction preview generation."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {
        "regions": [{"page": 0, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0}],
        "page": 0,
        "dpi": 150,
    }

    # Act - Mock redactor
    with patch("pdfsigner.api.routes.redact.get_pdf_redactor") as mock_redactor:
        mock_instance = Mock()
        mock_instance.preview_redactions.return_value = b"PNG image data"
        mock_redactor.return_value = mock_instance

        response = await client.post(
            "/api/v1/redact/preview",
            files=files,
            data={"request": json.dumps(request_data)},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"] == "image/png"


async def test_preview_redactions_invalid_page(client, auth_headers, sample_pdf):
    """Test preview fails with invalid page number."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {
        "regions": [{"page": 99, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0}],
        "page": 99,
    }

    # Act - Mock redactor to raise ValueError
    with patch("pdfsigner.api.routes.redact.get_pdf_redactor") as mock_redactor:
        mock_instance = Mock()
        mock_instance.preview_redactions.side_effect = ValueError("Invalid page number")
        mock_redactor.return_value = mock_instance

        response = await client.post(
            "/api/v1/redact/preview",
            files=files,
            data={"request": json.dumps(request_data)},
            headers=auth_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST


async def test_preview_redactions_unauthorized(client, sample_pdf):
    """Test preview fails without authentication."""
    # Arrange
    import json

    files = {"file": ("document.pdf", BytesIO(sample_pdf), "application/pdf")}
    request_data = {"regions": [{"page": 0, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0}]}

    # Act
    response = await client.post(
        "/api/v1/redact/preview", files=files, data={"request": json.dumps(request_data)}
    )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_preview_redactions_invalid_file_type(client, auth_headers):
    """Test preview fails with non-PDF file."""
    # Arrange
    import json

    files = {"file": ("document.txt", BytesIO(b"Not a PDF"), "text/plain")}
    request_data = {"regions": [{"page": 0, "x0": 100.0, "y0": 200.0, "x1": 300.0, "y1": 220.0}]}

    # Act
    response = await client.post(
        "/api/v1/redact/preview",
        files=files,
        data={"request": json.dumps(request_data)},
        headers=auth_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
