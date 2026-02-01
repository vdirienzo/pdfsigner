"""
Integration tests for PHI/PII Scanner API endpoint.

Tests POST /api/v1/phi/scan endpoint for HIPAA compliance.
Covers detection, validation, error handling, and authentication.

Run with:
    uv run pytest tests/integration/test_api_phi.py -v -m compliance
    uv run pytest tests/integration/test_api_phi.py -v --cov=src/pdfsigner/api/routes/phi
"""

import fitz
import pytest
from fastapi import status

# Mark all tests in this module as anyio and compliance
pytestmark = [pytest.mark.anyio, pytest.mark.compliance]


# --- Fixtures ---


@pytest.fixture
def sample_pdf_with_phi() -> bytes:
    """
    Create PDF containing multiple PHI types for testing.

    Returns PDF bytes with SSN, email, phone, credit card, etc.
    """
    # Create temporary PDF with PHI
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    # Add text with various PHI types
    text_content = """
    PATIENT RECORD - CONFIDENTIAL

    Name: Jane Smith
    SSN: 123-45-6789
    Date of Birth: 03/25/1985

    Contact Information:
    Email: jane.smith@hospital.org
    Phone: (555) 987-6543
    Mobile: 555-234-5678

    Medical Record Number: MRN-ABC1234567
    Health Insurance: Member ID INS9876543210

    Payment Information:
    Credit Card: 4532015112830366

    Diagnosis: ICD-10 Code F32.1 - Major depressive disorder

    Prescription: Lisinopril 10mg daily for hypertension
    """

    page.insert_text((50, 50), text_content, fontsize=11)

    # Save to bytes
    pdf_bytes = doc.tobytes()
    doc.close()

    return pdf_bytes


@pytest.fixture
def sample_pdf_no_phi() -> bytes:
    """Create PDF without any PHI for testing."""
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)

    text_content = """
    General Information Document

    This document contains general information about
    healthcare services and does not include any
    personally identifiable information.

    Please contact your provider for more details.
    """

    page.insert_text((50, 50), text_content, fontsize=11)

    pdf_bytes = doc.tobytes()
    doc.close()

    return pdf_bytes


@pytest.fixture
def large_pdf() -> bytes:
    """Create large PDF with multiple pages for performance testing."""
    doc = fitz.open()

    # Create 50 pages with some PHI
    for i in range(50):
        page = doc.new_page(width=612, height=792)
        text = f"""
        Page {i + 1} of Medical Records

        Patient SSN: 123-45-{i:04d}
        Contact: patient{i}@example.com
        Phone: (555) {i:03d}-{i:04d}
        """
        page.insert_text((50, 50), text, fontsize=10)

    pdf_bytes = doc.tobytes()
    doc.close()

    return pdf_bytes


# --- Test Cases ---


async def test_scan_phi_successful_detection(client, auth_headers, sample_pdf_with_phi):
    """Test successful PHI scan with multiple PII types detected."""
    # Arrange
    files = {"file": ("patient_record.pdf", sample_pdf_with_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify response structure
    assert data["filename"] == "patient_record.pdf"
    assert data["has_pii"] is True
    assert data["total_matches"] > 0
    assert data["pages_scanned"] > 0
    assert data["error"] is None

    # Verify PHI types detected
    assert "by_type" in data
    by_type = data["by_type"]

    # Should detect at least SSN, email, and phone
    assert "ssn" in by_type
    assert "email" in by_type
    assert "phone" in by_type

    # Verify matches contain required fields
    assert "matches" in data
    assert len(data["matches"]) > 0

    first_match = data["matches"][0]
    assert "pii_type" in first_match
    assert "pii_type_display" in first_match
    assert "redacted_value" in first_match
    assert "confidence" in first_match
    assert "start_pos" in first_match
    assert "end_pos" in first_match

    # Verify timing information
    assert "scan_time_ms" in data
    assert data["scan_time_ms"] > 0


async def test_scan_phi_no_phi_detected(client, auth_headers, sample_pdf_no_phi):
    """Test scan returns correct status when no PHI found."""
    # Arrange
    files = {"file": ("general_info.pdf", sample_pdf_no_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["has_pii"] is False
    assert data["total_matches"] == 0
    assert data["risk_score"] == 0.0
    assert len(data["matches"]) == 0
    assert data["by_type"] == {}
    assert data["error"] is None


async def test_scan_phi_confidence_scoring_validation(client, auth_headers, sample_pdf_with_phi):
    """Test confidence scores are within valid range (0.0-1.0)."""
    # Arrange
    files = {"file": ("test.pdf", sample_pdf_with_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify all confidence scores are between 0.0 and 1.0
    for match in data["matches"]:
        confidence = match["confidence"]
        assert 0.0 <= confidence <= 1.0, f"Invalid confidence: {confidence}"

        # High-confidence detections should be >= 0.5
        if match["pii_type"] in ["ssn", "email", "credit_card"]:
            assert confidence >= 0.5, f"Low confidence for {match['pii_type']}: {confidence}"


async def test_scan_phi_risk_score_calculation(client, auth_headers, sample_pdf_with_phi):
    """Test risk score is calculated correctly based on PHI types."""
    # Arrange
    files = {"file": ("high_risk.pdf", sample_pdf_with_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify risk score
    risk_score = data["risk_score"]
    assert 0.0 <= risk_score <= 1.0, f"Invalid risk score: {risk_score}"

    # If SSN or credit card detected, risk should be high
    if "ssn" in data["by_type"] or "credit_card" in data["by_type"]:
        assert risk_score > 0.5, "Risk score should be high for SSN/credit card"


async def test_scan_phi_large_pdf_handling(client, auth_headers, large_pdf):
    """Test scanning large PDFs completes successfully."""
    # Arrange
    files = {"file": ("large_medical_records.pdf", large_pdf, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify all pages were scanned
    assert data["pages_scanned"] == 50
    assert data["has_pii"] is True

    # Verify performance (should complete in reasonable time)
    # Allowing up to 30 seconds for 50 pages
    assert data["scan_time_ms"] < 30000, "Scan took too long"


async def test_scan_phi_invalid_file_format_rejected(client, auth_headers):
    """Test non-PDF files are rejected."""
    # Arrange
    files = {"file": ("document.txt", b"Not a PDF file", "text/plain")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert "PDF" in data["detail"]


async def test_scan_phi_missing_file_returns_error(client, auth_headers):
    """Test missing file parameter returns validation error."""
    # Act - No files parameter
    response = await client.post("/api/v1/phi/scan", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_scan_phi_values_are_redacted(client, auth_headers, sample_pdf_with_phi):
    """Test PHI values are redacted in API response for security."""
    # Arrange
    files = {"file": ("sensitive.pdf", sample_pdf_with_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify redaction for each match type
    for match in data["matches"]:
        redacted = match["redacted_value"]
        pii_type = match["pii_type"]

        # Redacted values should contain asterisks
        if pii_type == "ssn":
            # SSN redacted as ***-**-6789
            assert "***" in redacted or "XXX" in redacted
            assert len(redacted) > 0
            # Verify the actual redacted_value field doesn't contain full SSN
            assert "123-45-6789" != redacted

        elif pii_type == "credit_card":
            # Credit card redacted as ****-****-****-0366
            assert "*" in redacted or "X" in redacted
            # Verify the actual redacted_value field doesn't contain full card
            assert "4532015112830366" != redacted

        elif pii_type == "email":
            # Email redacted as j***@hospital.org
            assert "*" in redacted or "@" in redacted

    # Verify all redacted_value fields contain redaction markers
    redacted_values = [m["redacted_value"] for m in data["matches"]]
    for redacted in redacted_values:
        # At least one should have asterisks (email might just show @domain)
        if any(pii_type in ["ssn", "credit_card", "phone"] for pii_type in data["by_type"]):
            has_redaction = any("*" in rv or "X" in rv for rv in redacted_values)
            assert has_redaction, "Expected redaction markers in sensitive values"


async def test_scan_phi_empty_file_rejected(client, auth_headers):
    """Test empty PDF file is rejected."""
    # Arrange
    files = {"file": ("empty.pdf", b"", "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert "empty" in data["detail"].lower()


async def test_scan_phi_requires_authentication(client, sample_pdf_with_phi):
    """Test endpoint requires authentication (no token provided)."""
    # Arrange
    files = {"file": ("test.pdf", sample_pdf_with_phi, "application/pdf")}

    # Act - No authentication headers
    response = await client.post("/api/v1/phi/scan", files=files)

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_scan_phi_api_key_authentication(client, api_key_headers, sample_pdf_no_phi):
    """Test API key authentication works for PHI scanning."""
    # Arrange
    files = {"file": ("test.pdf", sample_pdf_no_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=api_key_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "filename" in data
    assert "has_pii" in data


# --- Edge Cases ---


async def test_scan_phi_no_filename_provided(client, auth_headers):
    """Test handling of upload with no filename."""
    # Arrange
    files = {"file": ("", b"%PDF-1.4\n", "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert - Should reject files without filename
    assert response.status_code in [
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
    ]


async def test_scan_phi_invalid_pdf_structure(client, auth_headers):
    """Test handling of malformed PDF file."""
    # Arrange - Invalid PDF content
    files = {"file": ("corrupt.pdf", b"%PDF-1.4\ngarbage data", "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert - Should handle gracefully
    assert response.status_code in [
        status.HTTP_400_BAD_REQUEST,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
    ]


async def test_scan_phi_boundary_confidence_scores(client, auth_headers):
    """Test edge cases for confidence scoring (boundary values)."""
    # Arrange - Create PDF with ambiguous patterns
    doc = fitz.open()
    page = doc.new_page()

    # Text with patterns that might have lower confidence
    text_content = """
    Some numbers that might look like SSN: 111-11-1111
    Random digits: 123456789
    Not an email: notanemail@
    Partial phone: 555-
    """

    page.insert_text((50, 50), text_content, fontsize=11)
    pdf_bytes = doc.tobytes()
    doc.close()

    files = {"file": ("ambiguous.pdf", pdf_bytes, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # All confidence scores should still be valid
    for match in data["matches"]:
        assert 0.0 <= match["confidence"] <= 1.0


async def test_scan_phi_multiple_pages_context(client, auth_headers):
    """Test PHI detection across multiple pages maintains context."""
    # Arrange - Create multi-page PDF
    doc = fitz.open()

    for page_num in range(3):
        page = doc.new_page()
        text = f"""
        Page {page_num + 1}

        Patient Record Continued
        Email: patient{page_num}@example.com
        Phone: (555) {page_num}00-{page_num}000
        """
        page.insert_text((50, 50), text, fontsize=11)

    pdf_bytes = doc.tobytes()
    doc.close()

    files = {"file": ("multipage.pdf", pdf_bytes, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    assert data["pages_scanned"] == 3

    # Verify matches have correct page numbers
    for match in data["matches"]:
        if match["page"] is not None:
            assert 0 <= match["page"] < 3, f"Invalid page number: {match['page']}"


async def test_scan_phi_performance_metrics(client, auth_headers, sample_pdf_with_phi):
    """Test performance metrics are included in response."""
    # Arrange
    files = {"file": ("test.pdf", sample_pdf_with_phi, "application/pdf")}

    # Act
    response = await client.post("/api/v1/phi/scan", files=files, headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    # Verify performance metrics
    assert "scan_time_ms" in data
    assert isinstance(data["scan_time_ms"], (int, float))
    assert data["scan_time_ms"] > 0

    assert "pages_scanned" in data
    assert isinstance(data["pages_scanned"], int)
    assert data["pages_scanned"] > 0


# --- Documentation ---

__all__ = [
    "test_scan_phi_successful_detection",
    "test_scan_phi_no_phi_detected",
    "test_scan_phi_confidence_scoring_validation",
    "test_scan_phi_risk_score_calculation",
    "test_scan_phi_large_pdf_handling",
    "test_scan_phi_invalid_file_format_rejected",
    "test_scan_phi_missing_file_returns_error",
    "test_scan_phi_values_are_redacted",
    "test_scan_phi_empty_file_rejected",
    "test_scan_phi_requires_authentication",
    "test_scan_phi_api_key_authentication",
]
