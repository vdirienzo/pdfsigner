"""
test_hipaa_report.py - Tests for HIPAA report generation

Author: Homero Thompson del Lago del Terror
"""

import json
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from pdfsigner.core.reports import (
    EmergencyAccessSummary,
    EncryptionSummary,
    HIPAAReport,
    HIPAAReportGenerator,
    PHIAccessSummary,
    ReportConfig,
    ReportFormat,
    ReportSection,
    UserAccessSummary,
    generate_hipaa_report,
)


class TestReportFormat:
    """Tests for ReportFormat enum."""

    def test_report_format_values(self):
        """Test ReportFormat enum values."""
        assert ReportFormat.PDF == "pdf"
        assert ReportFormat.JSON == "json"
        assert ReportFormat.CSV == "csv"

    def test_report_format_from_string(self):
        """Test creating ReportFormat from string."""
        assert ReportFormat("pdf") == ReportFormat.PDF
        assert ReportFormat("json") == ReportFormat.JSON
        assert ReportFormat("csv") == ReportFormat.CSV


class TestReportSection:
    """Tests for ReportSection enum."""

    def test_report_section_values(self):
        """Test ReportSection enum values."""
        assert ReportSection.SUMMARY == "summary"
        assert ReportSection.USER_ACCESS == "user_access"
        assert ReportSection.ENCRYPTION_USAGE == "encryption_usage"
        assert ReportSection.EMERGENCY_ACCESS == "emergency_access"
        assert ReportSection.PHI_ACCESS == "phi_access"
        assert ReportSection.AUDIT_INTEGRITY == "audit_integrity"

    def test_report_section_from_string(self):
        """Test creating ReportSection from string."""
        assert ReportSection("summary") == ReportSection.SUMMARY
        assert ReportSection("user_access") == ReportSection.USER_ACCESS


class TestReportConfig:
    """Tests for ReportConfig dataclass."""

    def test_report_config_creation(self):
        """Test creating ReportConfig with required fields."""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 31)

        config = ReportConfig(
            start_date=start,
            end_date=end,
        )

        assert config.start_date == start
        assert config.end_date == end
        assert config.sections == []
        assert config.format == ReportFormat.PDF
        assert config.include_details is True

    def test_report_config_with_sections(self):
        """Test ReportConfig with specific sections."""
        config = ReportConfig(
            start_date=datetime.now(),
            end_date=datetime.now(),
            sections=[ReportSection.USER_ACCESS, ReportSection.ENCRYPTION_USAGE],
            format=ReportFormat.JSON,
        )

        assert len(config.sections) == 2
        assert ReportSection.USER_ACCESS in config.sections
        assert ReportSection.ENCRYPTION_USAGE in config.sections
        assert config.format == ReportFormat.JSON

    def test_report_config_to_dict(self):
        """Test ReportConfig serialization to dict."""
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 31)

        config = ReportConfig(
            start_date=start,
            end_date=end,
            sections=[ReportSection.USER_ACCESS],
            format=ReportFormat.CSV,
        )

        data = config.to_dict()

        assert data["start_date"] == start.isoformat()
        assert data["end_date"] == end.isoformat()
        assert data["sections"] == ["user_access"]
        assert data["format"] == "csv"
        assert data["include_details"] is True

    def test_report_config_from_dict(self):
        """Test ReportConfig deserialization from dict."""
        data = {
            "start_date": "2024-01-01T00:00:00",
            "end_date": "2024-01-31T23:59:59",
            "sections": ["user_access", "encryption_usage"],
            "format": "pdf",
            "include_details": False,
        }

        config = ReportConfig.from_dict(data)

        assert config.start_date == datetime(2024, 1, 1, 0, 0, 0)
        assert config.end_date == datetime(2024, 1, 31, 23, 59, 59)
        assert len(config.sections) == 2
        assert config.format == ReportFormat.PDF
        assert config.include_details is False


class TestUserAccessSummary:
    """Tests for UserAccessSummary dataclass."""

    def test_user_access_summary_creation(self):
        """Test creating UserAccessSummary."""
        summary = UserAccessSummary(
            total_users=10,
            active_users=8,
            logins=25,
            failed_logins=3,
            sessions_created=25,
            sessions_terminated=20,
            unique_documents_accessed=15,
        )

        assert summary.total_users == 10
        assert summary.active_users == 8
        assert summary.logins == 25
        assert summary.failed_logins == 3
        assert summary.sessions_created == 25
        assert summary.sessions_terminated == 20
        assert summary.unique_documents_accessed == 15

    def test_user_access_summary_serialization(self):
        """Test UserAccessSummary to_dict and from_dict."""
        summary = UserAccessSummary(
            total_users=5,
            active_users=4,
            logins=10,
            failed_logins=1,
            sessions_created=10,
            sessions_terminated=8,
            unique_documents_accessed=7,
        )

        data = summary.to_dict()
        assert data["total_users"] == 5
        assert data["logins"] == 10

        restored = UserAccessSummary.from_dict(data)
        assert restored.total_users == summary.total_users
        assert restored.logins == summary.logins


class TestEncryptionSummary:
    """Tests for EncryptionSummary dataclass."""

    def test_encryption_summary_creation(self):
        """Test creating EncryptionSummary."""
        summary = EncryptionSummary(
            documents_encrypted=20,
            documents_decrypted=15,
            encryption_method="aes256",
            phi_documents_encrypted=5,
        )

        assert summary.documents_encrypted == 20
        assert summary.documents_decrypted == 15
        assert summary.encryption_method == "aes256"
        assert summary.phi_documents_encrypted == 5

    def test_encryption_summary_serialization(self):
        """Test EncryptionSummary to_dict and from_dict."""
        summary = EncryptionSummary(
            documents_encrypted=10,
            documents_decrypted=5,
            encryption_method="aes256",
            phi_documents_encrypted=3,
        )

        data = summary.to_dict()
        assert data["documents_encrypted"] == 10
        assert data["encryption_method"] == "aes256"

        restored = EncryptionSummary.from_dict(data)
        assert restored.documents_encrypted == summary.documents_encrypted
        assert restored.encryption_method == summary.encryption_method


class TestEmergencyAccessSummary:
    """Tests for EmergencyAccessSummary dataclass."""

    def test_emergency_access_summary_creation(self):
        """Test creating EmergencyAccessSummary."""
        summary = EmergencyAccessSummary(
            requests_made=5,
            requests_approved=3,
            requests_denied=2,
            documents_accessed=10,
            unique_users=4,
        )

        assert summary.requests_made == 5
        assert summary.requests_approved == 3
        assert summary.requests_denied == 2
        assert summary.documents_accessed == 10
        assert summary.unique_users == 4

    def test_emergency_access_summary_serialization(self):
        """Test EmergencyAccessSummary to_dict and from_dict."""
        summary = EmergencyAccessSummary(
            requests_made=3,
            requests_approved=2,
            requests_denied=1,
            documents_accessed=5,
            unique_users=2,
        )

        data = summary.to_dict()
        assert data["requests_made"] == 3
        assert data["requests_approved"] == 2

        restored = EmergencyAccessSummary.from_dict(data)
        assert restored.requests_made == summary.requests_made
        assert restored.requests_approved == summary.requests_approved


class TestPHIAccessSummary:
    """Tests for PHIAccessSummary dataclass."""

    def test_phi_access_summary_creation(self):
        """Test creating PHIAccessSummary."""
        summary = PHIAccessSummary(
            documents_scanned=50,
            documents_with_phi=15,
            phi_types_detected={"ssn": 5, "email": 10},
            blocked_operations=2,
        )

        assert summary.documents_scanned == 50
        assert summary.documents_with_phi == 15
        assert summary.phi_types_detected == {"ssn": 5, "email": 10}
        assert summary.blocked_operations == 2

    def test_phi_access_summary_serialization(self):
        """Test PHIAccessSummary to_dict and from_dict."""
        summary = PHIAccessSummary(
            documents_scanned=30,
            documents_with_phi=10,
            phi_types_detected={"ssn": 3, "mrn": 7},
            blocked_operations=1,
        )

        data = summary.to_dict()
        assert data["documents_scanned"] == 30
        assert data["phi_types_detected"] == {"ssn": 3, "mrn": 7}

        restored = PHIAccessSummary.from_dict(data)
        assert restored.documents_scanned == summary.documents_scanned
        assert restored.phi_types_detected == summary.phi_types_detected


class TestHIPAAReport:
    """Tests for HIPAAReport dataclass."""

    def test_hipaa_report_creation(self):
        """Test creating HIPAAReport with minimal fields."""
        report = HIPAAReport(
            report_id="test-123",
            title="Test Report",
            organization="Test Org",
            generated_at=datetime.now(),
            period_start=datetime(2024, 1, 1),
            period_end=datetime(2024, 1, 31),
        )

        assert report.report_id == "test-123"
        assert report.title == "Test Report"
        assert report.organization == "Test Org"
        assert report.user_access is None
        assert report.encryption is None
        assert report.compliance_status == "unknown"

    def test_hipaa_report_with_sections(self):
        """Test HIPAAReport with all sections populated."""
        user_access = UserAccessSummary(
            total_users=5,
            active_users=4,
            logins=10,
            failed_logins=1,
            sessions_created=10,
            sessions_terminated=8,
            unique_documents_accessed=7,
        )

        encryption = EncryptionSummary(
            documents_encrypted=10,
            documents_decrypted=5,
            encryption_method="aes256",
            phi_documents_encrypted=3,
        )

        report = HIPAAReport(
            report_id="test-456",
            title="Full Report",
            organization="Test Org",
            generated_at=datetime.now(),
            period_start=datetime(2024, 1, 1),
            period_end=datetime(2024, 1, 31),
            user_access=user_access,
            encryption=encryption,
            compliance_status="compliant",
        )

        assert report.user_access is not None
        assert report.user_access.total_users == 5
        assert report.encryption is not None
        assert report.encryption.documents_encrypted == 10
        assert report.compliance_status == "compliant"

    def test_hipaa_report_serialization(self):
        """Test HIPAAReport to_dict."""
        report = HIPAAReport(
            report_id="test-789",
            title="Serialization Test",
            organization="Test Org",
            generated_at=datetime(2024, 2, 1, 12, 0, 0),
            period_start=datetime(2024, 1, 1),
            period_end=datetime(2024, 1, 31),
        )

        data = report.to_dict()

        assert data["report_id"] == "test-789"
        assert data["title"] == "Serialization Test"
        assert data["generated_at"] == "2024-02-01T12:00:00"
        assert data["compliance_status"] == "unknown"

    def test_hipaa_report_deserialization(self):
        """Test HIPAAReport from_dict."""
        data = {
            "report_id": "test-abc",
            "title": "Deserialization Test",
            "organization": "Test Org",
            "generated_at": "2024-02-01T12:00:00",
            "period_start": "2024-01-01T00:00:00",
            "period_end": "2024-01-31T23:59:59",
            "user_access": None,
            "encryption": None,
            "emergency_access": None,
            "phi_access": None,
            "compliance_status": "warning",
            "compliance_checks": [],
        }

        report = HIPAAReport.from_dict(data)

        assert report.report_id == "test-abc"
        assert report.title == "Deserialization Test"
        assert report.generated_at == datetime(2024, 2, 1, 12, 0, 0)
        assert report.compliance_status == "warning"


class TestHIPAAReportGenerator:
    """Tests for HIPAAReportGenerator."""

    def test_generator_initialization(self):
        """Test creating HIPAAReportGenerator."""
        generator = HIPAAReportGenerator()
        assert generator is not None
        assert generator._settings is None

    @patch("pdfsigner.config.settings.get_settings")
    def test_generator_settings_lazy_load(self, mock_get_settings):
        """Test lazy loading of settings."""
        mock_settings = Mock()
        mock_settings.encryption_strength = "aes256"
        mock_get_settings.return_value = mock_settings

        generator = HIPAAReportGenerator()
        assert generator._settings is None

        # Access settings
        settings = generator.settings
        assert settings == mock_settings
        assert generator._settings == mock_settings
        mock_get_settings.assert_called_once()

    @patch("pdfsigner.core.compliance.get_compliance_checker")
    @patch("pdfsigner.core.audit.get_audit_logger")
    @patch("pdfsigner.config.settings.get_settings")
    def test_generate_report_all_sections(
        self, mock_get_settings, mock_get_audit_logger, mock_get_compliance
    ):
        """Test generating report with all sections."""
        # Mock settings
        mock_settings = Mock()
        mock_settings.encryption_strength = "aes256"
        mock_get_settings.return_value = mock_settings

        # Mock audit logger
        mock_logger = Mock()
        mock_event1 = Mock()
        mock_event1.event_type.value = "session_start"
        mock_event1.user_id = "user1"
        mock_event1.document_path = "/path/to/doc.pdf"

        mock_event2 = Mock()
        mock_event2.event_type.value = "encrypt_success"
        mock_event2.details = {}

        mock_logger.get_events.return_value = [mock_event1, mock_event2]
        mock_get_audit_logger.return_value = mock_logger

        # Mock compliance checker (to avoid dependencies)
        mock_get_compliance.side_effect = ImportError("Not available")

        # Create config
        config = ReportConfig(
            start_date=datetime.now() - timedelta(days=30),
            end_date=datetime.now(),
            sections=[
                ReportSection.USER_ACCESS,
                ReportSection.ENCRYPTION_USAGE,
                ReportSection.PHI_ACCESS,
            ],
        )

        # Generate report
        generator = HIPAAReportGenerator()
        report = generator.generate(config)

        # Verify report structure
        assert report.report_id is not None
        assert report.title == "HIPAA Compliance Audit Report"
        assert report.organization == "PDFSigner"
        assert report.user_access is not None
        assert report.encryption is not None
        assert report.phi_access is not None
        assert report.emergency_access is None  # Not requested

    @patch("pdfsigner.core.compliance.get_compliance_checker")
    @patch("pdfsigner.core.audit.get_audit_logger")
    @patch("pdfsigner.config.settings.get_settings")
    def test_generate_user_access_summary(
        self, mock_get_settings, mock_get_audit_logger, mock_get_compliance
    ):
        """Test generating user access summary."""
        mock_settings = Mock()
        mock_get_settings.return_value = mock_settings

        # Create mock events
        mock_events = []
        for i in range(5):
            mock_event = Mock()
            mock_event.event_type.value = "session_start"
            mock_event.user_id = f"user{i % 3}"  # 3 unique users
            mock_event.document_path = f"/doc{i}.pdf"
            mock_events.append(mock_event)

        mock_logger = Mock()
        mock_logger.get_events.return_value = mock_events
        mock_get_audit_logger.return_value = mock_logger

        # Mock compliance checker (to avoid dependencies)
        mock_get_compliance.side_effect = ImportError("Not available")

        config = ReportConfig(
            start_date=datetime.now() - timedelta(days=7),
            end_date=datetime.now(),
            sections=[ReportSection.USER_ACCESS],
        )

        generator = HIPAAReportGenerator()
        report = generator.generate(config)

        assert report.user_access is not None
        assert report.user_access.total_users == 3  # 3 unique users
        assert report.user_access.logins == 5

    @patch("pdfsigner.core.emergency.get_emergency_repository")
    @patch("pdfsigner.config.settings.get_settings")
    def test_generate_emergency_access_summary(self, mock_get_settings, mock_get_emergency_repo):
        """Test generating emergency access summary."""
        mock_settings = Mock()
        mock_get_settings.return_value = mock_settings

        # Mock repository
        mock_repo = Mock()
        mock_conn = Mock()
        mock_cursor = Mock()

        mock_request1 = Mock()
        mock_request1.status.value = "approved"
        mock_request1.requester_id = "user1"
        mock_request1.documents_accessed = ["/doc1.pdf", "/doc2.pdf"]

        mock_request2 = Mock()
        mock_request2.status.value = "denied"
        mock_request2.requester_id = "user2"
        mock_request2.documents_accessed = []

        mock_cursor.fetchall.return_value = []
        mock_conn.execute.return_value = mock_cursor
        mock_conn.__enter__ = Mock(return_value=mock_conn)
        mock_conn.__exit__ = Mock(return_value=False)

        mock_repo._get_connection.return_value = mock_conn
        mock_repo._row_to_request.side_effect = [mock_request1, mock_request2]
        mock_get_emergency_repo.return_value = mock_repo

        config = ReportConfig(
            start_date=datetime.now() - timedelta(days=30),
            end_date=datetime.now(),
            sections=[ReportSection.EMERGENCY_ACCESS],
        )

        generator = HIPAAReportGenerator()
        summary = generator._generate_emergency_summary(config)

        assert summary.requests_made == 0  # Empty mock data
        assert summary.requests_approved == 0
        assert summary.requests_denied == 0

    def test_export_json(self):
        """Test exporting report as JSON."""
        report = HIPAAReport(
            report_id="test-json",
            title="JSON Export Test",
            organization="Test Org",
            generated_at=datetime(2024, 2, 1, 12, 0, 0),
            period_start=datetime(2024, 1, 1),
            period_end=datetime(2024, 1, 31),
        )

        generator = HIPAAReportGenerator()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = Path(f.name)

        try:
            generator._export_json(report, temp_path)

            # Verify file exists and contains valid JSON
            assert temp_path.exists()
            data = json.loads(temp_path.read_text())
            assert data["report_id"] == "test-json"
            assert data["title"] == "JSON Export Test"
        finally:
            temp_path.unlink()

    def test_export_csv(self):
        """Test exporting report as CSV."""
        user_access = UserAccessSummary(
            total_users=5,
            active_users=4,
            logins=10,
            failed_logins=1,
            sessions_created=10,
            sessions_terminated=8,
            unique_documents_accessed=7,
        )

        report = HIPAAReport(
            report_id="test-csv",
            title="CSV Export Test",
            organization="Test Org",
            generated_at=datetime.now(),
            period_start=datetime(2024, 1, 1),
            period_end=datetime(2024, 1, 31),
            user_access=user_access,
        )

        generator = HIPAAReportGenerator()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = Path(f.name)

        try:
            generator._export_csv(report, temp_path)

            # Verify file exists and contains CSV data
            assert temp_path.exists()
            content = temp_path.read_text()
            assert "Section,Metric,Value" in content
            assert "User Access" in content
            assert "total_users,5" in content
        finally:
            temp_path.unlink()

    def test_export_pdf(self):
        """Test exporting report as PDF."""

        # Mock fitz module
        mock_fitz = MagicMock()
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_doc.new_page.return_value = mock_page
        mock_fitz.open.return_value = mock_doc

        sys.modules["fitz"] = mock_fitz

        try:
            report = HIPAAReport(
                report_id="test-pdf",
                title="PDF Export Test",
                organization="Test Org",
                generated_at=datetime(2024, 2, 1, 12, 0, 0),
                period_start=datetime(2024, 1, 1),
                period_end=datetime(2024, 1, 31),
                compliance_status="compliant",
            )

            generator = HIPAAReportGenerator()

            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pdf") as f:
                temp_path = Path(f.name)

            try:
                generator._export_pdf(report, temp_path)

                # Verify PyMuPDF was called correctly
                mock_fitz.open.assert_called_once()
                mock_doc.new_page.assert_called_once_with(width=612, height=792)
                mock_doc.save.assert_called_once_with(str(temp_path))
                mock_doc.close.assert_called_once()
            finally:
                if temp_path.exists():
                    temp_path.unlink()
        finally:
            # Cleanup mock
            if "fitz" in sys.modules:
                del sys.modules["fitz"]


class TestGenerateHIPAAReport:
    """Tests for generate_hipaa_report convenience function."""

    @patch("pdfsigner.core.reports.hipaa_report.HIPAAReportGenerator.generate")
    def test_generate_hipaa_report_default_params(self, mock_generate):
        """Test convenience function with default parameters."""
        mock_report = Mock()
        mock_generate.return_value = mock_report

        _ = generate_hipaa_report()

        # Verify generator was called
        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        config = call_args[0][0]

        # Check config was created with correct defaults
        assert isinstance(config, ReportConfig)
        assert config.format == ReportFormat.PDF
        assert len(config.sections) == 6  # All sections

    @patch("pdfsigner.core.reports.hipaa_report.HIPAAReportGenerator.generate")
    def test_generate_hipaa_report_custom_days(self, mock_generate):
        """Test convenience function with custom days."""
        mock_report = Mock()
        mock_generate.return_value = mock_report

        _ = generate_hipaa_report(days=7)

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        config = call_args[0][0]

        # Verify date range is approximately 7 days
        date_diff = (config.end_date - config.start_date).days
        assert date_diff == 7

    @patch("pdfsigner.core.reports.hipaa_report.HIPAAReportGenerator.generate")
    def test_generate_hipaa_report_with_output_path(self, mock_generate):
        """Test convenience function with output path."""
        mock_report = Mock()
        mock_generate.return_value = mock_report

        output_path = Path("/tmp/report.json")
        _ = generate_hipaa_report(days=14, output_path=output_path, format=ReportFormat.JSON)

        mock_generate.assert_called_once()
        call_args = mock_generate.call_args
        # Check config was passed (first positional argument)
        config = call_args[0][0]
        assert config.format == ReportFormat.JSON
        # Check output_path was passed (second positional argument)
        assert call_args[0][1] == output_path
