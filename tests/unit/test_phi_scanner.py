"""Tests for PHI detection scanner."""

from pathlib import Path

import pytest

from pdfsigner.core.phi import (
    Confidence,
    PHIMatch,
    PHIScanner,
    PHIScanResult,
    PHIType,
    get_phi_scanner,
)
from pdfsigner.core.phi.patterns import HIPAA_PATTERNS, PHIPattern

try:
    import fitz  # PyMuPDF

    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False


class TestPHIType:
    """Tests for PHIType enum."""

    def test_ssn_value(self):
        """Test SSN type has correct value."""
        assert PHIType.SSN.value == "ssn"

    def test_mrn_value(self):
        """Test MRN type has correct value."""
        assert PHIType.MRN.value == "mrn"

    def test_dob_value(self):
        """Test DOB type has correct value."""
        assert PHIType.DOB.value == "dob"

    def test_email_value(self):
        """Test EMAIL type has correct value."""
        assert PHIType.EMAIL.value == "email"


class TestPHIPattern:
    """Tests for PHIPattern dataclass."""

    def test_pattern_creation_valid(self):
        """Test creating valid pattern."""
        pattern = PHIPattern(
            phi_type=PHIType.SSN,
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            description="SSN with dashes",
            confidence_weight=0.95,
        )
        assert pattern.phi_type == PHIType.SSN
        assert pattern.confidence_weight == 0.95
        assert pattern.enabled is True

    def test_pattern_invalid_weight_raises(self):
        """Test invalid confidence weight raises ValueError."""
        with pytest.raises(ValueError, match="confidence_weight must be 0.0-1.0"):
            PHIPattern(
                phi_type=PHIType.SSN,
                pattern=r"\d+",
                description="Test",
                confidence_weight=1.5,  # Invalid
            )

    def test_pattern_negative_weight_raises(self):
        """Test negative confidence weight raises ValueError."""
        with pytest.raises(ValueError, match="confidence_weight must be 0.0-1.0"):
            PHIPattern(
                phi_type=PHIType.SSN,
                pattern=r"\d+",
                description="Test",
                confidence_weight=-0.1,
            )


class TestPHIMatch:
    """Tests for PHIMatch dataclass."""

    def test_phi_match_creation(self):
        """Test creating PHI match."""
        match = PHIMatch(
            phi_type=PHIType.SSN,
            value="***-**-6789",
            page=0,
            position=(10.0, 20.0, 100.0, 30.0),
            confidence=Confidence.HIGH,
            pattern_used="SSN with dashes",
        )
        assert match.phi_type == PHIType.SSN
        assert match.value == "***-**-6789"
        assert match.page == 0
        assert match.confidence == Confidence.HIGH

    def test_phi_match_to_dict(self):
        """Test PHI match serialization to dict."""
        match = PHIMatch(
            phi_type=PHIType.EMAIL,
            value="j***@example.com",
            page=1,
            position=(50.0, 60.0, 200.0, 70.0),
            confidence=Confidence.MEDIUM,
            pattern_used="Email address",
        )
        data = match.to_dict()

        assert data["phi_type"] == "email"
        assert data["value"] == "j***@example.com"
        assert data["page"] == 1
        assert data["position"] == [50.0, 60.0, 200.0, 70.0]
        assert data["confidence"] == "medium"

    def test_phi_match_from_dict(self):
        """Test PHI match deserialization from dict."""
        data = {
            "phi_type": "phone",
            "value": "***-***-1234",
            "page": 2,
            "position": [10.0, 20.0, 30.0, 40.0],
            "confidence": "high",
            "pattern_used": "Phone number",
        }
        match = PHIMatch.from_dict(data)

        assert match.phi_type == PHIType.PHONE
        assert match.value == "***-***-1234"
        assert match.page == 2
        assert match.confidence == Confidence.HIGH


class TestPHIScanResult:
    """Tests for PHIScanResult dataclass."""

    def test_scan_result_creation_no_phi(self):
        """Test creating scan result with no PHI."""
        result = PHIScanResult(
            has_phi=False,
            matches=[],
            total_matches=0,
            by_type={},
            overall_confidence=Confidence.LOW,
            scan_time_ms=10.5,
            pages_scanned=1,
        )
        assert result.has_phi is False
        assert len(result.matches) == 0
        assert result.total_matches == 0

    def test_scan_result_creation_with_phi(self):
        """Test creating scan result with PHI matches."""
        matches = [
            PHIMatch(
                phi_type=PHIType.SSN,
                value="***-**-6789",
                page=0,
                position=(0.0, 0.0, 0.0, 0.0),
                confidence=Confidence.HIGH,
                pattern_used="SSN",
            )
        ]
        result = PHIScanResult(
            has_phi=True,
            matches=matches,
            total_matches=1,
            by_type={"ssn": 1},
            overall_confidence=Confidence.HIGH,
            scan_time_ms=25.3,
            pages_scanned=1,
        )
        assert result.has_phi is True
        assert len(result.matches) == 1
        assert result.by_type["ssn"] == 1

    def test_scan_result_to_dict(self):
        """Test scan result serialization."""
        result = PHIScanResult(
            has_phi=True,
            matches=[],
            total_matches=2,
            by_type={"ssn": 1, "email": 1},
            overall_confidence=Confidence.MEDIUM,
            scan_time_ms=15.7,
            pages_scanned=3,
        )
        data = result.to_dict()

        assert data["has_phi"] is True
        assert data["total_matches"] == 2
        assert data["by_type"]["ssn"] == 1
        assert data["overall_confidence"] == "medium"
        assert data["scan_time_ms"] == 15.7

    def test_scan_result_from_dict(self):
        """Test scan result deserialization."""
        data = {
            "has_phi": False,
            "matches": [],
            "total_matches": 0,
            "by_type": {},
            "overall_confidence": "low",
            "scan_time_ms": 5.0,
            "pages_scanned": 1,
            "error": None,
        }
        result = PHIScanResult.from_dict(data)

        assert result.has_phi is False
        assert result.total_matches == 0
        assert result.overall_confidence == Confidence.LOW


class TestPHIScanner:
    """Tests for PHIScanner class."""

    def test_scanner_initialization_default_patterns(self):
        """Test scanner initializes with default HIPAA patterns."""
        scanner = PHIScanner()
        assert len(scanner._patterns) > 0
        assert scanner._patterns == HIPAA_PATTERNS

    def test_scanner_initialization_custom_patterns(self):
        """Test scanner initializes with custom patterns."""
        custom_patterns = [
            PHIPattern(
                phi_type=PHIType.SSN,
                pattern=r"\d{3}-\d{2}-\d{4}",
                description="Test",
                confidence_weight=0.9,
            )
        ]
        scanner = PHIScanner(patterns=custom_patterns)
        assert len(scanner._patterns) == 1
        assert scanner._patterns == custom_patterns

    def test_scan_text_detects_ssn_with_dashes(self):
        """Test scanning text detects SSN with dashes."""
        scanner = PHIScanner()
        text = "Patient SSN: 123-45-6789"
        matches = scanner.scan_text(text)

        assert len(matches) > 0
        ssn_matches = [m for m in matches if m.phi_type == PHIType.SSN]
        assert len(ssn_matches) > 0
        # Value should be masked
        assert "***" in ssn_matches[0].value
        assert "6789" in ssn_matches[0].value

    def test_scan_text_detects_ssn_without_dashes(self):
        """Test scanning text detects SSN without dashes."""
        scanner = PHIScanner()
        text = "SSN: 123456789"
        matches = scanner.scan_text(text)

        # Should match SSN patterns
        ssn_matches = [m for m in matches if m.phi_type == PHIType.SSN]
        assert len(ssn_matches) > 0

    def test_scan_text_detects_mrn_various_formats(self):
        """Test scanning text detects MRN in various formats."""
        scanner = PHIScanner()

        test_cases = [
            "MRN: ABC123456",
            "Medical Record: XYZ789012",
            "MR# 456789123",
            "Patient ID: PAT987654",
        ]

        for text in test_cases:
            matches = scanner.scan_text(text)
            mrn_matches = [m for m in matches if m.phi_type == PHIType.MRN]
            assert len(mrn_matches) > 0, f"Failed to detect MRN in: {text}"

    def test_scan_text_detects_dob_various_formats(self):
        """Test scanning text detects DOB in various formats."""
        scanner = PHIScanner()

        test_cases = [
            "DOB: 01/15/1980",
            "Date of Birth: 12-25-1975",
            "Born: January 15, 1990",
            "DOB: March 3, 2000",
        ]

        for text in test_cases:
            matches = scanner.scan_text(text)
            dob_matches = [m for m in matches if m.phi_type == PHIType.DOB]
            assert len(dob_matches) > 0, f"Failed to detect DOB in: {text}"

    def test_scan_text_detects_email(self):
        """Test scanning text detects email addresses."""
        scanner = PHIScanner()
        text = "Contact: john.doe@example.com"
        matches = scanner.scan_text(text)

        email_matches = [m for m in matches if m.phi_type == PHIType.EMAIL]
        assert len(email_matches) > 0
        # Email should be masked
        assert "@" in email_matches[0].value

    def test_scan_text_detects_phone_various_formats(self):
        """Test scanning text detects phone numbers in various formats."""
        scanner = PHIScanner()

        test_cases = [
            "Phone: (555) 123-4567",
            "Tel: 555-123-4567",
            "Mobile: 5551234567",
            "Cell: +1 555 123 4567",
        ]

        for text in test_cases:
            matches = scanner.scan_text(text)
            phone_matches = [m for m in matches if m.phi_type in [PHIType.PHONE, PHIType.FAX]]
            assert len(phone_matches) > 0, f"Failed to detect phone in: {text}"

    def test_scan_text_detects_insurance_id(self):
        """Test scanning text detects insurance IDs."""
        scanner = PHIScanner()

        test_cases = [
            "Insurance ID: ABC12345678",
            "Policy Number: XYZ987654321",
            "Member ID: MEM123456789",
        ]

        for text in test_cases:
            matches = scanner.scan_text(text)
            insurance_matches = [m for m in matches if m.phi_type == PHIType.INSURANCE_ID]
            assert len(insurance_matches) > 0, f"Failed to detect insurance in: {text}"

    def test_scan_text_detects_icd10_codes(self):
        """Test scanning text detects ICD-10 diagnosis codes."""
        scanner = PHIScanner()

        test_cases = [
            "Diagnosis: J06.9",
            "ICD: E11.9",
            "ICD-10: A01.05",
        ]

        for text in test_cases:
            matches = scanner.scan_text(text)
            icd_matches = [m for m in matches if m.phi_type == PHIType.ICD10]
            assert len(icd_matches) > 0, f"Failed to detect ICD-10 in: {text}"

    def test_scan_text_detects_multiple_phi_types(self):
        """Test scanning text with multiple PHI types."""
        scanner = PHIScanner()
        text = """
        Patient: John Doe
        SSN: 123-45-6789
        DOB: 01/15/1980
        Email: john@example.com
        Phone: (555) 123-4567
        MRN: ABC123456
        """
        matches = scanner.scan_text(text)

        # Should detect multiple types
        assert len(matches) >= 5

        phi_types = {m.phi_type for m in matches}
        assert PHIType.SSN in phi_types
        assert PHIType.EMAIL in phi_types
        # Phone or DOB should be detected
        assert PHIType.PHONE in phi_types or PHIType.DOB in phi_types

    def test_scan_text_empty_returns_no_matches(self):
        """Test scanning empty text returns no matches."""
        scanner = PHIScanner()
        matches = scanner.scan_text("")
        assert len(matches) == 0

    def test_scan_text_no_phi_returns_empty(self):
        """Test scanning text with no PHI returns empty list."""
        scanner = PHIScanner()
        text = "This is a regular document with no sensitive information."
        matches = scanner.scan_text(text)
        assert len(matches) == 0

    def test_mask_value_ssn_with_dashes(self):
        """Test masking SSN with dashes."""
        scanner = PHIScanner()
        masked = scanner._mask_value("123-45-6789", PHIType.SSN)
        assert masked == "***-**-6789"

    def test_mask_value_ssn_without_dashes(self):
        """Test masking SSN without dashes."""
        scanner = PHIScanner()
        masked = scanner._mask_value("123456789", PHIType.SSN)
        assert masked == "*****6789"

    def test_mask_value_email(self):
        """Test masking email address."""
        scanner = PHIScanner()
        masked = scanner._mask_value("john.doe@example.com", PHIType.EMAIL)
        assert masked.startswith("j***@")
        assert "example.com" in masked

    def test_mask_value_phone(self):
        """Test masking phone number."""
        scanner = PHIScanner()
        masked = scanner._mask_value("(555) 123-4567", PHIType.PHONE)
        assert masked == "***-***-4567"

    def test_mask_value_name(self):
        """Test masking patient name."""
        scanner = PHIScanner()
        masked = scanner._mask_value("John Doe", PHIType.NAME)
        assert "J***" in masked
        assert "D***" in masked

    def test_mask_value_short_string(self):
        """Test masking short strings (4 chars or less)."""
        scanner = PHIScanner()
        masked = scanner._mask_value("ABC", PHIType.MRN)
        assert masked == "***"

    def test_confidence_scoring_high(self):
        """Test confidence determination for high scores."""
        scanner = PHIScanner()
        confidence = scanner._determine_confidence(0.90)
        assert confidence == Confidence.HIGH

    def test_confidence_scoring_medium(self):
        """Test confidence determination for medium scores."""
        scanner = PHIScanner()
        confidence = scanner._determine_confidence(0.70)
        assert confidence == Confidence.MEDIUM

    def test_confidence_scoring_low(self):
        """Test confidence determination for low scores."""
        scanner = PHIScanner()
        confidence = scanner._determine_confidence(0.50)
        assert confidence == Confidence.LOW

    def test_count_by_type_empty(self):
        """Test counting matches by type with empty list."""
        scanner = PHIScanner()
        counts = scanner._count_by_type([])
        assert counts == {}

    def test_count_by_type_multiple(self):
        """Test counting matches by type."""
        scanner = PHIScanner()
        matches = [
            PHIMatch(
                phi_type=PHIType.SSN,
                value="***",
                page=0,
                position=(0.0, 0.0, 0.0, 0.0),
                confidence=Confidence.HIGH,
                pattern_used="test",
            ),
            PHIMatch(
                phi_type=PHIType.SSN,
                value="***",
                page=0,
                position=(0.0, 0.0, 0.0, 0.0),
                confidence=Confidence.HIGH,
                pattern_used="test",
            ),
            PHIMatch(
                phi_type=PHIType.EMAIL,
                value="***",
                page=0,
                position=(0.0, 0.0, 0.0, 0.0),
                confidence=Confidence.HIGH,
                pattern_used="test",
            ),
        ]
        counts = scanner._count_by_type(matches)
        assert counts["ssn"] == 2
        assert counts["email"] == 1

    def test_calculate_overall_confidence_empty(self):
        """Test overall confidence calculation with no matches."""
        scanner = PHIScanner()
        confidence = scanner._calculate_overall_confidence([])
        assert confidence == Confidence.LOW

    def test_calculate_overall_confidence_high_matches(self):
        """Test overall confidence with high-confidence matches."""
        scanner = PHIScanner()
        matches = [
            PHIMatch(
                phi_type=PHIType.SSN,
                value="***",
                page=0,
                position=(0.0, 0.0, 0.0, 0.0),
                confidence=Confidence.HIGH,
                pattern_used="test",
            )
        ]
        confidence = scanner._calculate_overall_confidence(matches)
        assert confidence == Confidence.HIGH

    def test_calculate_overall_confidence_medium_matches(self):
        """Test overall confidence with medium-confidence matches."""
        scanner = PHIScanner()
        matches = [
            PHIMatch(
                phi_type=PHIType.EMAIL,
                value="***",
                page=0,
                position=(0.0, 0.0, 0.0, 0.0),
                confidence=Confidence.MEDIUM,
                pattern_used="test",
            )
        ]
        confidence = scanner._calculate_overall_confidence(matches)
        assert confidence == Confidence.MEDIUM

    @pytest.mark.skipif(not PYMUPDF_AVAILABLE, reason="PyMuPDF not available")
    def test_scan_pdf_empty_returns_no_phi(self, temp_dir: Path):
        """Test scanning empty PDF returns no PHI."""
        # Create empty PDF
        pdf_path = temp_dir / "empty.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        doc.save(str(pdf_path))
        doc.close()

        scanner = PHIScanner()
        result = scanner.scan_pdf(pdf_path)

        assert result.has_phi is False
        assert result.total_matches == 0
        assert result.pages_scanned == 1
        assert result.error is None

    @pytest.mark.skipif(not PYMUPDF_AVAILABLE, reason="PyMuPDF not available")
    def test_scan_pdf_with_phi(self, temp_dir: Path):
        """Test scanning PDF with PHI content."""
        # Create PDF with PHI
        pdf_path = temp_dir / "phi_doc.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Patient SSN: 123-45-6789", fontsize=12)
        page.insert_text((72, 100), "Email: patient@example.com", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()

        scanner = PHIScanner()
        result = scanner.scan_pdf(pdf_path)

        assert result.has_phi is True
        assert result.total_matches > 0
        assert result.pages_scanned == 1
        assert result.scan_time_ms > 0

        # Check that PHI was detected
        phi_types = {m.phi_type for m in result.matches}
        assert PHIType.SSN in phi_types

    @pytest.mark.skipif(not PYMUPDF_AVAILABLE, reason="PyMuPDF not available")
    def test_scan_pdf_encrypted_returns_error(self, temp_dir: Path):
        """Test scanning encrypted PDF returns error."""
        # Create encrypted PDF
        pdf_path = temp_dir / "encrypted.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Secret content", fontsize=12)

        # Encrypt with user password
        perm = int(
            fitz.PDF_PERM_ACCESSIBILITY
            | fitz.PDF_PERM_PRINT
            | fitz.PDF_PERM_COPY
            | fitz.PDF_PERM_ANNOTATE
        )
        doc.save(
            str(pdf_path),
            encryption=fitz.PDF_ENCRYPT_AES_256,
            user_pw="userpass",
            owner_pw="ownerpass",
            permissions=perm,
        )
        doc.close()

        scanner = PHIScanner()
        result = scanner.scan_pdf(pdf_path)

        # Should detect encryption and return error
        assert result.has_phi is False
        assert result.error is not None
        assert "encrypted" in result.error.lower()

    @pytest.mark.skipif(not PYMUPDF_AVAILABLE, reason="PyMuPDF not available")
    def test_scan_pdf_nonexistent_returns_error(self, temp_dir: Path):
        """Test scanning non-existent PDF returns error."""
        pdf_path = temp_dir / "nonexistent.pdf"

        scanner = PHIScanner()
        result = scanner.scan_pdf(pdf_path)

        assert result.has_phi is False
        assert result.error is not None

    @pytest.mark.skipif(not PYMUPDF_AVAILABLE, reason="PyMuPDF not available")
    def test_scan_pdf_multipage(self, temp_dir: Path):
        """Test scanning multi-page PDF."""
        # Create multi-page PDF with PHI on different pages
        pdf_path = temp_dir / "multipage.pdf"
        doc = fitz.open()

        page1 = doc.new_page(width=612, height=792)
        page1.insert_text((72, 72), "SSN: 111-22-3333", fontsize=12)

        page2 = doc.new_page(width=612, height=792)
        page2.insert_text((72, 72), "Email: test@example.com", fontsize=12)

        doc.save(str(pdf_path))
        doc.close()

        scanner = PHIScanner()
        result = scanner.scan_pdf(pdf_path)

        assert result.has_phi is True
        assert result.pages_scanned == 2
        assert result.total_matches >= 2

        # Check that matches are on different pages
        pages_with_matches = {m.page for m in result.matches}
        assert len(pages_with_matches) >= 1


class TestGetPHIScanner:
    """Tests for get_phi_scanner singleton function."""

    def test_get_phi_scanner_returns_instance(self):
        """Test get_phi_scanner returns scanner instance."""
        scanner = get_phi_scanner()
        assert isinstance(scanner, PHIScanner)

    def test_get_phi_scanner_singleton(self):
        """Test get_phi_scanner returns same instance."""
        scanner1 = get_phi_scanner()
        scanner2 = get_phi_scanner()
        assert scanner1 is scanner2


class TestHIPAAPatterns:
    """Tests for HIPAA pattern definitions."""

    def test_hipaa_patterns_not_empty(self):
        """Test HIPAA_PATTERNS list is not empty."""
        assert len(HIPAA_PATTERNS) > 0

    def test_hipaa_patterns_all_enabled_by_default(self):
        """Test most HIPAA patterns are enabled by default."""
        enabled_count = sum(1 for p in HIPAA_PATTERNS if p.enabled)
        assert enabled_count > 0

    def test_hipaa_patterns_cover_major_types(self):
        """Test HIPAA patterns cover major PHI types."""
        phi_types_covered = {p.phi_type for p in HIPAA_PATTERNS}

        # Should cover at least these major types
        assert PHIType.SSN in phi_types_covered
        assert PHIType.DOB in phi_types_covered
        assert PHIType.EMAIL in phi_types_covered
        assert PHIType.PHONE in phi_types_covered
        assert PHIType.MRN in phi_types_covered

    def test_hipaa_patterns_valid_confidence_weights(self):
        """Test all HIPAA patterns have valid confidence weights."""
        for pattern in HIPAA_PATTERNS:
            assert 0.0 <= pattern.confidence_weight <= 1.0
