"""
Shared fixtures for integration tests.

Provides common fixtures for API testing:
- HTTP client
- Authentication tokens and headers
- Sample PDFs
"""

import tempfile
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token


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
def auditor_token(api_settings):
    """Create valid auditor JWT token for testing."""
    token = create_access_token(
        data={"sub": "auditor", "role": "auditor"},
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
def auditor_headers(auditor_token):
    """Create authentication headers with auditor JWT token."""
    return {"Authorization": f"Bearer {auditor_token}"}


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
