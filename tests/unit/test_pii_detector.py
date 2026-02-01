"""
Tests for PII/PHI detection engine.

Tests cover:
- Pattern detection for each PII type
- Confidence scoring
- Risk calculation
- Luhn algorithm for credit cards
- Context-based detection
- PDF scanning with coordinates
"""

from pathlib import Path

import fitz
import pytest

from pdfsigner.core.detection import PDFScanner, PIIDetector, PIIMatch, PIIType, get_pii_detector
from pdfsigner.core.detection.patterns import has_context_word, luhn_checksum, redact_value

# --- Fixtures ---


@pytest.fixture
def detector() -> PIIDetector:
    """Get PII detector instance."""
    return PIIDetector()


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    """Create a sample PDF with PII for testing."""
    pdf_path = tmp_path / "test_pii.pdf"
    doc = fitz.open()
    page = doc.new_page()

    # Add text with various PII types
    text_content = """
    Patient Information

    Name: John Doe
    SSN: 123-45-6789
    DOB: 01/15/1980

    Contact: john.doe@example.com
    Phone: (555) 123-4567

    Medical Record Number: MRN: ABC1234567
    Insurance: Member ID: INS9876543210

    Diagnosis: F32.1 (Major depressive disorder)

    Prescription: Take Lisinopril 10mg daily
    """

    page.insert_text((50, 50), text_content, fontsize=12)
    doc.save(str(pdf_path))
    doc.close()

    return pdf_path


# --- Pattern Tests ---


def test_detect_ssn_with_dashes(detector: PIIDetector):
    """Test SSN detection with dashes."""
    text = "My SSN is 123-45-6789"
    matches = detector.scan_text(text)

    assert len(matches) == 1
    assert matches[0].pii_type == PIIType.SSN
    assert matches[0].value == "123-45-6789"
    assert matches[0].confidence >= 0.85


def test_detect_ssn_without_dashes(detector: PIIDetector):
    """Test SSN detection without dashes."""
    text = "Social Security Number: 123456789"
    matches = detector.scan_text(text)

    ssn_matches = [m for m in matches if m.pii_type == PIIType.SSN]
    assert len(ssn_matches) >= 1
    assert ssn_matches[0].value == "123456789"


def test_reject_invalid_ssn(detector: PIIDetector):
    """Test rejection of invalid SSN patterns."""
    text = "Not a valid SSN: 000-00-0000 or 666-00-0000 or 900-00-0000"
    matches = detector.scan_text(text)

    ssn_matches = [m for m in matches if m.pii_type == PIIType.SSN]
    assert len(ssn_matches) == 0  # Invalid SSNs should not match


def test_detect_credit_card_visa(detector: PIIDetector):
    """Test Visa credit card detection with Luhn validation."""
    # Valid Visa test card: 4532015112830366
    text = "Card number: 4532015112830366"
    matches = detector.scan_text(text)

    cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
    assert len(cc_matches) >= 1
    assert cc_matches[0].confidence >= 0.85


def test_detect_credit_card_mastercard(detector: PIIDetector):
    """Test Mastercard detection with Luhn validation."""
    # Valid Mastercard test: 5425233430109903
    text = "Credit card: 5425233430109903"
    matches = detector.scan_text(text)

    cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
    assert len(cc_matches) >= 1


def test_detect_credit_card_amex(detector: PIIDetector):
    """Test American Express detection."""
    # Valid Amex test: 374245455400126
    text = "Amex: 374245455400126"
    matches = detector.scan_text(text)

    cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
    assert len(cc_matches) >= 1


def test_reject_invalid_credit_card_luhn(detector: PIIDetector):
    """Test rejection of credit cards with invalid Luhn checksum."""
    text = "Invalid card: 4532015112830367"  # Last digit wrong
    matches = detector.scan_text(text)

    cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
    assert len(cc_matches) == 0  # Should fail Luhn validation


def test_detect_email(detector: PIIDetector):
    """Test email address detection."""
    text = "Contact me at john.doe@example.com for details"
    matches = detector.scan_text(text)

    email_matches = [m for m in matches if m.pii_type == PIIType.EMAIL]
    assert len(email_matches) == 1
    assert email_matches[0].value == "john.doe@example.com"
    assert email_matches[0].confidence >= 0.85


def test_detect_phone_various_formats(detector: PIIDetector):
    """Test phone number detection in various formats."""
    text = """
    Phone formats:
    (555) 123-4567
    555-123-4567
    555.123.4567
    +1 555 123 4567
    1-555-123-4567
    """
    matches = detector.scan_text(text)

    phone_matches = [m for m in matches if m.pii_type == PIIType.PHONE]
    assert len(phone_matches) >= 4  # At least 4 different formats


def test_detect_dob_with_context(detector: PIIDetector):
    """Test date of birth detection with context words."""
    text = "Date of Birth: 01/15/1980"
    matches = detector.scan_text(text)

    dob_matches = [m for m in matches if m.pii_type == PIIType.DOB]
    assert len(dob_matches) >= 1
    assert dob_matches[0].confidence >= 0.85


def test_skip_date_without_dob_context(detector: PIIDetector):
    """Test that dates without DOB context are not detected."""
    text = "The meeting is scheduled for 01/15/2024"
    matches = detector.scan_text(text)

    dob_matches = [m for m in matches if m.pii_type == PIIType.DOB]
    assert len(dob_matches) == 0  # No DOB context, should be skipped


def test_detect_medical_record_with_label(detector: PIIDetector):
    """Test medical record number detection with label."""
    text = "Patient MRN: ABC1234567"
    matches = detector.scan_text(text)

    mrn_matches = [m for m in matches if m.pii_type == PIIType.MEDICAL_RECORD]
    assert len(mrn_matches) >= 1
    assert mrn_matches[0].confidence >= 0.90


def test_detect_health_plan_id(detector: PIIDetector):
    """Test health plan ID detection."""
    text = "Member ID: INS9876543210"
    matches = detector.scan_text(text)

    plan_matches = [m for m in matches if m.pii_type == PIIType.HEALTH_PLAN_ID]
    assert len(plan_matches) >= 1
    assert plan_matches[0].confidence >= 0.90


def test_detect_icd10_diagnosis_code(detector: PIIDetector):
    """Test ICD-10 diagnosis code detection."""
    text = "Diagnosis code: F32.1"
    matches = detector.scan_text(text)

    dx_matches = [m for m in matches if m.pii_type == PIIType.DIAGNOSIS_CODE]
    assert len(dx_matches) >= 1


def test_detect_common_icd10_code(detector: PIIDetector):
    """Test detection of common ICD-10 codes."""
    text = "Patient has I10 and E11.9"
    matches = detector.scan_text(text)

    dx_matches = [m for m in matches if m.pii_type == PIIType.DIAGNOSIS_CODE]
    assert len(dx_matches) >= 2


def test_detect_prescription(detector: PIIDetector):
    """Test prescription detection."""
    text = "Rx: Take Lisinopril 10mg daily"
    matches = detector.scan_text(text)

    rx_matches = [m for m in matches if m.pii_type == PIIType.PRESCRIPTION]
    assert len(rx_matches) >= 1


# --- Confidence Scoring Tests ---


def test_confidence_with_context(detector: PIIDetector):
    """Test that context words increase confidence."""
    text_with_context = "SSN: 123-45-6789"
    text_without_context = "Random number: 123-45-6789"

    matches_with = detector.scan_text(text_with_context)
    matches_without = detector.scan_text(text_without_context)

    ssn_with = [m for m in matches_with if m.pii_type == PIIType.SSN][0]
    ssn_without = [m for m in matches_without if m.pii_type == PIIType.SSN][0]

    assert ssn_with.confidence > ssn_without.confidence


def test_scan_with_confidence_threshold(detector: PIIDetector):
    """Test filtering by confidence threshold."""
    text = "SSN: 123-45-6789 and 123456789"
    matches_all = detector.scan_text(text)
    matches_high = detector.scan_with_confidence(text, min_confidence=0.90)

    assert len(matches_high) <= len(matches_all)


# --- Risk Score Tests ---


def test_risk_score_no_pii(detector: PIIDetector):
    """Test risk score with no PII detected."""
    matches: list[PIIMatch] = []
    risk_score = detector.get_risk_score(matches)
    assert risk_score == 0.0


def test_risk_score_low_sensitivity(detector: PIIDetector):
    """Test risk score with low-sensitivity PII (email only)."""
    text = "Contact: user@example.com"
    matches = detector.scan_text(text)
    risk_score = detector.get_risk_score(matches)

    assert 0.0 < risk_score < 0.5  # Low risk


def test_risk_score_high_sensitivity(detector: PIIDetector):
    """Test risk score with high-sensitivity PII (SSN, CC)."""
    text = "SSN: 123-45-6789 and CC: 4532015112830366"
    matches = detector.scan_text(text)
    risk_score = detector.get_risk_score(matches)

    assert risk_score > 0.7  # High risk


def test_risk_score_multiple_matches(detector: PIIDetector):
    """Test that multiple PII matches increase risk score."""
    text_few = "Email: user@example.com"
    text_many = """
    SSN: 123-45-6789
    Email: user@example.com
    Phone: (555) 123-4567
    DOB: 01/15/1980
    """

    matches_few = detector.scan_text(text_few)
    matches_many = detector.scan_text(text_many)

    risk_few = detector.get_risk_score(matches_few)
    risk_many = detector.get_risk_score(matches_many)

    assert risk_many > risk_few


# --- Utility Function Tests ---


def test_luhn_checksum_valid():
    """Test Luhn algorithm with valid credit card."""
    assert luhn_checksum("4532015112830366") is True  # Valid Visa
    assert luhn_checksum("5425233430109903") is True  # Valid Mastercard
    assert luhn_checksum("374245455400126") is True  # Valid Amex


def test_luhn_checksum_invalid():
    """Test Luhn algorithm with invalid credit card."""
    assert luhn_checksum("4532015112830367") is False  # Last digit wrong
    assert luhn_checksum("1234567890123456") is False  # Invalid


def test_has_context_word_found():
    """Test context word detection when present."""
    text = "The SSN is 123-45-6789 in the record"
    position = text.find("123")
    assert has_context_word(text, position, ["ssn"], window=20) is True


def test_has_context_word_not_found():
    """Test context word detection when absent."""
    text = "Random number 123-45-6789 for reference"
    position = text.find("123")
    assert has_context_word(text, position, ["medical", "patient"], window=20) is False


def test_redact_ssn():
    """Test SSN redaction."""
    assert redact_value("123-45-6789", "ssn") == "***-**-6789"


def test_redact_credit_card():
    """Test credit card redaction."""
    assert redact_value("4532015112830366", "credit_card") == "**** **** **** 0366"


def test_redact_email():
    """Test email redaction."""
    assert redact_value("user@example.com", "email") == "***@example.com"


def test_redact_phone():
    """Test phone number redaction."""
    assert redact_value("(555) 123-4567", "phone") == "(***) ***-4567"


# --- PDF Scanner Tests ---


def test_pdf_scanner_extract_text(sample_pdf: Path):
    """Test PDF text extraction."""
    scanner = PDFScanner()
    text_blocks = scanner.extract_text_with_positions(sample_pdf)

    assert len(text_blocks) > 0
    assert any("123-45-6789" in block.text for block in text_blocks)


def test_pdf_scanner_detect_pii(sample_pdf: Path):
    """Test PII detection in PDF."""
    scanner = PDFScanner()
    matches = scanner.scan_pdf(sample_pdf)

    assert len(matches) > 0

    # Check that we detect various PII types
    pii_types = {m.pii_type for m in matches}
    assert PIIType.SSN in pii_types
    assert PIIType.EMAIL in pii_types


def test_pdf_scanner_page_numbers(sample_pdf: Path):
    """Test that page numbers are correctly assigned."""
    scanner = PDFScanner()
    matches = scanner.scan_pdf(sample_pdf)

    # All matches should have page number 0 (first page)
    for match in matches:
        assert match.page is not None
        assert match.page == 0


def test_pdf_scanner_bounding_boxes(sample_pdf: Path):
    """Test that bounding boxes are assigned."""
    scanner = PDFScanner()
    matches = scanner.scan_pdf(sample_pdf)

    # At least some matches should have bounding boxes
    matches_with_bbox = [m for m in matches if m.bbox is not None]
    assert len(matches_with_bbox) > 0

    # Bounding boxes should have 4 coordinates
    for match in matches_with_bbox:
        assert len(match.bbox) == 4
        x1, y1, x2, y2 = match.bbox
        assert x2 > x1  # Width > 0
        assert y2 > y1  # Height > 0


def test_pdf_scanner_nonexistent_file():
    """Test error handling for nonexistent PDF."""
    scanner = PDFScanner()

    with pytest.raises(FileNotFoundError):
        scanner.scan_pdf("/nonexistent/file.pdf")


# --- Integration Tests ---


def test_full_document_scan(sample_pdf: Path):
    """Test complete document scan workflow."""
    scanner = PDFScanner()
    detector = get_pii_detector()

    # Scan PDF
    matches = scanner.scan_pdf(sample_pdf)

    # Calculate risk
    risk_score = detector.get_risk_score(matches)

    # Verify results
    assert len(matches) >= 5  # Should find multiple PII instances
    assert risk_score > 0.5  # Document has significant PII
    assert all(m.redacted_value for m in matches)  # All values redacted
    assert all(m.context for m in matches)  # All have context


def test_match_to_dict_serialization(detector: PIIDetector):
    """Test PIIMatch serialization to dict."""
    text = "SSN: 123-45-6789"
    matches = detector.scan_text(text)

    match_dict = matches[0].to_dict()

    assert "pii_type" in match_dict
    assert "redacted_value" in match_dict
    assert "confidence" in match_dict
    assert match_dict["pii_type"] == "ssn"
    assert isinstance(match_dict["confidence"], float)


def test_singleton_detector():
    """Test that get_pii_detector returns singleton."""
    detector1 = get_pii_detector()
    detector2 = get_pii_detector()

    assert detector1 is detector2


def test_context_extraction(detector: PIIDetector):
    """Test that context is correctly extracted."""
    text = "The patient's social security number is 123-45-6789 for identification."
    matches = detector.scan_text(text)

    ssn_match = [m for m in matches if m.pii_type == PIIType.SSN][0]
    assert len(ssn_match.context) > 0
    assert "123-45-6789" in ssn_match.context


def test_multiple_pii_types_in_text(detector: PIIDetector):
    """Test detection of multiple PII types in one text."""
    text = """
    Patient: John Doe
    SSN: 123-45-6789
    Email: john@example.com
    Phone: (555) 123-4567
    DOB: 01/15/1980
    MRN: MED12345678
    """
    matches = detector.scan_text(text)

    pii_types_found = {m.pii_type for m in matches}

    assert PIIType.SSN in pii_types_found
    assert PIIType.EMAIL in pii_types_found
    assert PIIType.PHONE in pii_types_found
    assert PIIType.DOB in pii_types_found
    assert len(matches) >= 4
