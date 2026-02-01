"""Tests for HIPAA compliance status checker."""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from pdfsigner.core.compliance import (
    ComplianceCategory,
    ComplianceCheck,
    ComplianceReport,
    ComplianceStatus,
    ComplianceStatusChecker,
    get_compliance_checker,
)


class TestComplianceStatus:
    """Tests for ComplianceStatus enum."""

    def test_compliance_status_enum_values(self):
        """Test enum has expected values."""
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.WARNING.value == "warning"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.UNKNOWN.value == "unknown"

    def test_compliance_status_is_string_enum(self):
        """Test enum inherits from str."""
        assert isinstance(ComplianceStatus.COMPLIANT, str)
        assert ComplianceStatus.COMPLIANT == "compliant"


class TestComplianceCategory:
    """Tests for ComplianceCategory enum."""

    def test_compliance_category_enum_values(self):
        """Test enum has expected values."""
        assert ComplianceCategory.ENCRYPTION.value == "encryption"
        assert ComplianceCategory.AUDIT_CONTROLS.value == "audit_controls"
        assert ComplianceCategory.ACCESS_CONTROL.value == "access_control"
        assert ComplianceCategory.SESSION_MANAGEMENT.value == "session_management"
        assert ComplianceCategory.TEMP_FILE_SECURITY.value == "temp_file_security"
        assert ComplianceCategory.PHI_DETECTION.value == "phi_detection"
        assert ComplianceCategory.EMERGENCY_ACCESS.value == "emergency_access"

    def test_compliance_category_is_string_enum(self):
        """Test enum inherits from str."""
        assert isinstance(ComplianceCategory.ENCRYPTION, str)
        assert ComplianceCategory.ENCRYPTION == "encryption"


class TestComplianceCheck:
    """Tests for ComplianceCheck dataclass."""

    def test_compliance_check_creation(self):
        """Test creating a compliance check."""
        check = ComplianceCheck(
            name="Test Check",
            category=ComplianceCategory.ENCRYPTION,
            status=ComplianceStatus.COMPLIANT,
            hipaa_reference="§164.312(a)(2)(iv)",
            description="Test description",
            details="Test details",
        )

        assert check.name == "Test Check"
        assert check.category == ComplianceCategory.ENCRYPTION
        assert check.status == ComplianceStatus.COMPLIANT
        assert check.hipaa_reference == "§164.312(a)(2)(iv)"
        assert check.description == "Test description"
        assert check.details == "Test details"
        assert check.remediation is None
        assert isinstance(check.last_checked, datetime)

    def test_compliance_check_with_remediation(self):
        """Test check with remediation steps."""
        check = ComplianceCheck(
            name="Test Check",
            category=ComplianceCategory.ENCRYPTION,
            status=ComplianceStatus.NON_COMPLIANT,
            hipaa_reference="§164.312(a)(2)(iv)",
            description="Test description",
            details="Test details",
            remediation="Fix this issue",
        )

        assert check.remediation == "Fix this issue"

    def test_compliance_check_serialization(self):
        """Test to_dict and from_dict methods."""
        check = ComplianceCheck(
            name="Test Check",
            category=ComplianceCategory.ENCRYPTION,
            status=ComplianceStatus.COMPLIANT,
            hipaa_reference="§164.312(a)(2)(iv)",
            description="Test description",
            details="Test details",
            remediation="Fix this",
        )

        # Serialize
        data = check.to_dict()
        assert isinstance(data, dict)
        assert data["name"] == "Test Check"
        assert data["category"] == "encryption"
        assert data["status"] == "compliant"
        assert isinstance(data["last_checked"], str)

        # Deserialize
        restored = ComplianceCheck.from_dict(data)
        assert restored.name == check.name
        assert restored.category == check.category
        assert restored.status == check.status
        assert isinstance(restored.last_checked, datetime)


class TestComplianceReport:
    """Tests for ComplianceReport dataclass."""

    @pytest.fixture
    def sample_checks(self):
        """Create sample compliance checks."""
        return [
            ComplianceCheck(
                name="Check 1",
                category=ComplianceCategory.ENCRYPTION,
                status=ComplianceStatus.COMPLIANT,
                hipaa_reference="§164.312(a)(2)(iv)",
                description="Encryption",
                details="AES-256 enabled",
            ),
            ComplianceCheck(
                name="Check 2",
                category=ComplianceCategory.AUDIT_CONTROLS,
                status=ComplianceStatus.WARNING,
                hipaa_reference="§164.312(b)",
                description="Audit",
                details="Minor issues",
                remediation="Check logs",
            ),
            ComplianceCheck(
                name="Check 3",
                category=ComplianceCategory.ACCESS_CONTROL,
                status=ComplianceStatus.NON_COMPLIANT,
                hipaa_reference="§164.312(a)(1)",
                description="Access control",
                details="RBAC disabled",
                remediation="Enable RBAC",
            ),
        ]

    def test_compliance_report_creation(self, sample_checks):
        """Test creating a compliance report."""
        report = ComplianceReport(
            checks=sample_checks,
            overall_status=ComplianceStatus.NON_COMPLIANT,
            compliant_count=1,
            warning_count=1,
            non_compliant_count=1,
        )

        assert len(report.checks) == 3
        assert report.overall_status == ComplianceStatus.NON_COMPLIANT
        assert report.compliant_count == 1
        assert report.warning_count == 1
        assert report.non_compliant_count == 1
        assert isinstance(report.generated_at, datetime)

    def test_compliance_report_is_hipaa_compliant_true(self):
        """Test is_hipaa_compliant returns True when no non-compliant checks."""
        checks = [
            ComplianceCheck(
                name="Check 1",
                category=ComplianceCategory.ENCRYPTION,
                status=ComplianceStatus.COMPLIANT,
                hipaa_reference="§164.312(a)(2)(iv)",
                description="Encryption",
                details="OK",
            )
        ]

        report = ComplianceReport(
            checks=checks,
            overall_status=ComplianceStatus.COMPLIANT,
            compliant_count=1,
            warning_count=0,
            non_compliant_count=0,
        )

        assert report.is_hipaa_compliant is True

    def test_compliance_report_is_hipaa_compliant_false(self, sample_checks):
        """Test is_hipaa_compliant returns False when non-compliant checks exist."""
        report = ComplianceReport(
            checks=sample_checks,
            overall_status=ComplianceStatus.NON_COMPLIANT,
            compliant_count=1,
            warning_count=1,
            non_compliant_count=1,
        )

        assert report.is_hipaa_compliant is False

    def test_compliance_report_to_dict(self, sample_checks):
        """Test report serialization."""
        report = ComplianceReport(
            checks=sample_checks,
            overall_status=ComplianceStatus.NON_COMPLIANT,
            compliant_count=1,
            warning_count=1,
            non_compliant_count=1,
        )

        data = report.to_dict()
        assert isinstance(data, dict)
        assert len(data["checks"]) == 3
        assert data["overall_status"] == "non_compliant"
        assert data["compliant_count"] == 1
        assert data["warning_count"] == 1
        assert data["non_compliant_count"] == 1
        assert data["is_hipaa_compliant"] is False
        assert isinstance(data["generated_at"], str)


class TestComplianceStatusChecker:
    """Tests for ComplianceStatusChecker."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        settings = Mock()
        settings.healthcare_mode = True
        settings.encryption_default_strength = "aes256"
        settings.healthcare_session_timeout_minutes = 15
        settings.temp_secure_delete = True
        settings.phi_detection_enabled = True
        settings.healthcare_emergency_require_approval = True
        settings.audit_enabled = True
        return settings

    @pytest.fixture
    def checker(self, mock_settings):
        """Create checker with mocked settings."""
        checker = ComplianceStatusChecker()
        checker._settings = mock_settings
        return checker

    def test_check_encryption_compliant(self, checker, mock_settings):
        """Test encryption check passes when AES-256 and healthcare mode enabled."""
        mock_settings.healthcare_mode = True
        mock_settings.encryption_default_strength = "aes256"

        result = checker._check_encryption()

        assert result.name == "PDF Encryption"
        assert result.category == ComplianceCategory.ENCRYPTION
        assert result.status == ComplianceStatus.COMPLIANT
        assert "AES-256" in result.details

    def test_check_encryption_warning_aes128(self, checker, mock_settings):
        """Test encryption check warns when using AES-128."""
        mock_settings.healthcare_mode = True
        mock_settings.encryption_default_strength = "aes128"

        result = checker._check_encryption()

        assert result.status == ComplianceStatus.WARNING
        assert "aes128" in result.details
        assert result.remediation is not None

    def test_check_encryption_warning_no_healthcare(self, checker, mock_settings):
        """Test encryption check warns when healthcare mode disabled."""
        mock_settings.healthcare_mode = False

        result = checker._check_encryption()

        assert result.status == ComplianceStatus.WARNING
        assert "Healthcare mode is disabled" in result.details
        assert "Enable healthcare_mode" in result.remediation

    def test_check_audit_controls_compliant(self, checker, mock_settings):
        """Test audit controls check passes when integrity is functioning."""
        mock_settings.audit_enabled = True

        mock_manager = Mock()
        mock_signed_event = Mock()
        mock_manager.sign_event.return_value = mock_signed_event
        mock_manager.verify_event.return_value = (True, "Valid")

        with patch(
            "pdfsigner.core.audit.get_audit_integrity_manager",
            return_value=mock_manager,
        ):
            result = checker._check_audit_controls()

        assert result.status == ComplianceStatus.COMPLIANT
        assert "functioning correctly" in result.details.lower()

    def test_check_audit_controls_non_compliant_disabled(self, checker, mock_settings):
        """Test audit controls fails when audit logging is disabled."""
        mock_settings.audit_enabled = False

        result = checker._check_audit_controls()

        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert "disabled" in result.details.lower()

    def test_check_audit_controls_non_compliant_verification_failed(self, checker, mock_settings):
        """Test audit controls fails when event verification fails."""
        mock_settings.audit_enabled = True

        mock_manager = Mock()
        mock_signed_event = Mock()
        mock_manager.sign_event.return_value = mock_signed_event
        mock_manager.verify_event.return_value = (False, "HMAC mismatch")

        with patch(
            "pdfsigner.core.audit.get_audit_integrity_manager",
            return_value=mock_manager,
        ):
            result = checker._check_audit_controls()

        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert "verification failed" in result.details.lower()

    def test_check_audit_controls_warning_on_error(self, checker, mock_settings):
        """Test audit controls returns warning if verification fails."""
        mock_settings.audit_enabled = True

        with patch(
            "pdfsigner.core.audit.get_audit_integrity_manager",
            side_effect=Exception("Audit system error"),
        ):
            result = checker._check_audit_controls()

        assert result.status == ComplianceStatus.WARNING
        assert "Could not verify" in result.details

    def test_check_access_control_compliant(self, checker, mock_settings):
        """Test access control check passes when healthcare mode enabled."""
        mock_settings.healthcare_mode = True

        result = checker._check_access_control()

        assert result.status == ComplianceStatus.COMPLIANT
        assert "RBAC enabled" in result.details

    def test_check_access_control_warning_no_healthcare(self, checker, mock_settings):
        """Test access control warns when healthcare mode disabled."""
        mock_settings.healthcare_mode = False

        result = checker._check_access_control()

        assert result.status == ComplianceStatus.WARNING
        assert "Healthcare mode disabled" in result.details

    def test_check_session_management_compliant(self, checker, mock_settings):
        """Test session management passes with 15 minute timeout."""
        mock_settings.healthcare_mode = True
        mock_settings.healthcare_session_timeout_minutes = 15

        result = checker._check_session_management()

        assert result.status == ComplianceStatus.COMPLIANT
        assert "15 minutes" in result.details
        assert result.remediation is None

    def test_check_session_management_warning_long_timeout(self, checker, mock_settings):
        """Test session management warns with timeout >15 minutes."""
        mock_settings.healthcare_mode = True
        mock_settings.healthcare_session_timeout_minutes = 20

        result = checker._check_session_management()

        assert result.status == ComplianceStatus.WARNING
        assert "20 minutes" in result.details
        assert result.remediation is not None

    def test_check_session_management_non_compliant_very_long(self, checker, mock_settings):
        """Test session management fails with very long timeout."""
        mock_settings.healthcare_mode = True
        mock_settings.healthcare_session_timeout_minutes = 60

        result = checker._check_session_management()

        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert "60 minutes" in result.details

    def test_check_temp_file_security_compliant(self, checker, mock_settings):
        """Test temp file security passes when secure delete enabled."""
        mock_settings.temp_secure_delete = True

        result = checker._check_temp_file_security()

        assert result.status == ComplianceStatus.COMPLIANT
        assert "DoD 5220.22-M" in result.details

    def test_check_temp_file_security_non_compliant(self, checker, mock_settings):
        """Test temp file security fails when secure delete disabled."""
        mock_settings.temp_secure_delete = False

        result = checker._check_temp_file_security()

        assert result.status == ComplianceStatus.NON_COMPLIANT
        assert "disabled" in result.details

    def test_check_phi_detection_compliant(self, checker, mock_settings):
        """Test PHI detection passes when enabled."""
        mock_settings.phi_detection_enabled = True

        result = checker._check_phi_detection()

        assert result.status == ComplianceStatus.COMPLIANT
        assert "enabled" in result.details.lower()

    def test_check_phi_detection_warning_disabled(self, checker, mock_settings):
        """Test PHI detection warns when disabled."""
        mock_settings.phi_detection_enabled = False

        result = checker._check_phi_detection()

        assert result.status == ComplianceStatus.WARNING
        assert "not enabled" in result.details

    def test_check_emergency_access_compliant(self, checker, mock_settings):
        """Test emergency access passes when approval required."""
        mock_settings.healthcare_mode = True
        mock_settings.healthcare_emergency_require_approval = True

        result = checker._check_emergency_access()

        assert result.status == ComplianceStatus.COMPLIANT
        assert "requires admin approval" in result.details

    def test_check_emergency_access_warning_no_approval(self, checker, mock_settings):
        """Test emergency access warns when approval not required."""
        mock_settings.healthcare_mode = True
        mock_settings.healthcare_emergency_require_approval = False

        result = checker._check_emergency_access()

        assert result.status == ComplianceStatus.WARNING
        assert "does not require approval" in result.details

    def test_check_all_returns_report(self, checker):
        """Test check_all returns complete report."""
        report = checker.check_all()

        assert isinstance(report, ComplianceReport)
        assert len(report.checks) == 7  # All 7 checks
        assert report.compliant_count >= 0
        assert report.warning_count >= 0
        assert report.non_compliant_count >= 0

    def test_check_all_calculates_overall_status_compliant(self, checker, mock_settings):
        """Test overall status is COMPLIANT when all checks pass."""
        # Configure all checks to pass
        mock_settings.healthcare_mode = True
        mock_settings.encryption_default_strength = "aes256"
        mock_settings.healthcare_session_timeout_minutes = 15
        mock_settings.temp_secure_delete = True
        mock_settings.phi_detection_enabled = True
        mock_settings.healthcare_emergency_require_approval = True
        mock_settings.audit_enabled = True

        # Mock audit check to pass
        mock_manager = Mock()
        mock_signed_event = Mock()
        mock_manager.sign_event.return_value = mock_signed_event
        mock_manager.verify_event.return_value = (True, "Valid")

        with patch(
            "pdfsigner.core.audit.get_audit_integrity_manager",
            return_value=mock_manager,
        ):
            report = checker.check_all()

        assert report.overall_status == ComplianceStatus.COMPLIANT
        assert report.non_compliant_count == 0

    def test_check_all_calculates_overall_status_warning(self, checker, mock_settings):
        """Test overall status is WARNING when some checks warn."""
        mock_settings.healthcare_mode = True
        mock_settings.encryption_default_strength = "aes128"  # Warning
        mock_settings.audit_enabled = True

        # Mock audit check
        mock_manager = Mock()
        mock_signed_event = Mock()
        mock_manager.sign_event.return_value = mock_signed_event
        mock_manager.verify_event.return_value = (True, "Valid")

        with patch(
            "pdfsigner.core.audit.get_audit_integrity_manager",
            return_value=mock_manager,
        ):
            report = checker.check_all()

        assert report.overall_status == ComplianceStatus.WARNING
        assert report.warning_count > 0

    def test_check_all_calculates_overall_status_non_compliant(self, checker, mock_settings):
        """Test overall status is NON_COMPLIANT when any check fails."""
        mock_settings.temp_secure_delete = False  # Non-compliant
        mock_settings.audit_enabled = True

        # Mock audit check
        mock_manager = Mock()
        mock_signed_event = Mock()
        mock_manager.sign_event.return_value = mock_signed_event
        mock_manager.verify_event.return_value = (True, "Valid")

        with patch(
            "pdfsigner.core.audit.get_audit_integrity_manager",
            return_value=mock_manager,
        ):
            report = checker.check_all()

        assert report.overall_status == ComplianceStatus.NON_COMPLIANT
        assert report.non_compliant_count > 0


class TestSingletonPattern:
    """Tests for singleton pattern implementation."""

    def test_singleton_pattern(self):
        """Test get_compliance_checker returns singleton."""
        checker1 = get_compliance_checker()
        checker2 = get_compliance_checker()

        assert checker1 is checker2

    def test_singleton_is_compliance_status_checker(self):
        """Test singleton returns correct type."""
        checker = get_compliance_checker()

        assert isinstance(checker, ComplianceStatusChecker)


# ============================================================================
# Multi-Standard Compliance Checker Tests (NEW)
# ============================================================================


from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance import (
    ComplianceChecker,
    ComplianceStandard,
    ControlStatus,
    MultiStandardReport,
    get_controls_for_standard,
    get_multi_standard_checker,
)


class TestMultiStandardEnums:
    """Tests for multi-standard enum types."""

    def test_compliance_standard_values(self):
        """Test all standard enum values exist."""
        assert ComplianceStandard.HIPAA.value == "hipaa"
        assert ComplianceStandard.NIST_800_53.value == "nist_800_53"
        assert ComplianceStandard.FEDRAMP.value == "fedramp"
        assert ComplianceStandard.EIDAS.value == "eidas"
        assert ComplianceStandard.GDPR.value == "gdpr"
        assert ComplianceStandard.SOC2.value == "soc2"

    def test_control_status_values(self):
        """Test all control status values exist."""
        assert ControlStatus.PASSED.value == "passed"
        assert ControlStatus.FAILED.value == "failed"
        assert ControlStatus.NOT_APPLICABLE.value == "not_applicable"
        assert ControlStatus.PARTIAL.value == "partial"


class TestMultiStandardControlDefinitions:
    """Tests for control definitions registry."""

    def test_get_controls_for_hipaa(self):
        """Test retrieving HIPAA controls."""
        controls = get_controls_for_standard(ComplianceStandard.HIPAA)

        assert len(controls) == 7
        control_ids = [c.control_id for c in controls]
        assert "HIPAA-164.312(a)(1)" in control_ids
        assert "HIPAA-164.312(b)" in control_ids

    def test_get_controls_for_nist(self):
        """Test retrieving NIST 800-53 controls."""
        controls = get_controls_for_standard(ComplianceStandard.NIST_800_53)

        assert len(controls) == 9
        control_ids = [c.control_id for c in controls]
        assert "AC-2" in control_ids
        assert "AU-9" in control_ids

    def test_get_controls_for_fedramp(self):
        """Test retrieving FedRAMP controls."""
        controls = get_controls_for_standard(ComplianceStandard.FEDRAMP)

        assert len(controls) == 4
        control_ids = [c.control_id for c in controls]
        assert "FR-IA-2" in control_ids

    def test_get_controls_for_eidas(self):
        """Test retrieving eIDAS controls."""
        controls = get_controls_for_standard(ComplianceStandard.EIDAS)

        assert len(controls) == 4
        control_ids = [c.control_id for c in controls]
        assert "eIDAS-Art.32" in control_ids

    def test_get_controls_for_gdpr(self):
        """Test retrieving GDPR controls."""
        controls = get_controls_for_standard(ComplianceStandard.GDPR)

        assert len(controls) == 5
        control_ids = [c.control_id for c in controls]
        assert "GDPR-Art.17" in control_ids

    def test_get_controls_for_soc2(self):
        """Test retrieving SOC 2 controls."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)

        assert len(controls) == 5
        control_ids = [c.control_id for c in controls]
        assert "CC6.1" in control_ids


class TestMultiStandardChecker:
    """Tests for multi-standard ComplianceChecker."""

    @pytest.fixture
    def minimal_settings(self):
        """Create minimal settings (no compliance features)."""
        return Settings(
            healthcare_mode=False,
            audit_enabled=False,
            mfa_enabled=False,
            fips_mode_enabled=False,
            gdpr_enabled=False,
        )

    @pytest.fixture
    def full_hipaa_settings(self):
        """Create settings with full HIPAA compliance."""
        return Settings(
            healthcare_mode=True,
            healthcare_session_timeout_minutes=15,
            healthcare_max_sessions=3,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
            audit_enabled=True,
            audit_retention_days=2190,  # 6 years
            encryption_default_strength="aes256",
            encryption_hipaa_mode=True,
            encryption_store_in_keyring=True,
            ltv_enabled=True,
            archive_ts_enabled=True,
            mfa_enabled=True,
            mfa_required_for_roles=["ADMIN"],
            password_min_length=12,
        )

    @pytest.fixture
    def checker_minimal(self, minimal_settings):
        """Create checker with minimal settings."""
        return ComplianceChecker(minimal_settings)

    @pytest.fixture
    def checker_hipaa(self, full_hipaa_settings):
        """Create checker with HIPAA-compliant settings."""
        return ComplianceChecker(full_hipaa_settings)

    # Basic Checker Tests

    def test_multi_checker_initialization(self, minimal_settings):
        """Test ComplianceChecker initialization."""
        checker = ComplianceChecker(minimal_settings)

        assert checker.settings == minimal_settings

    def test_get_multi_standard_checker_singleton(self):
        """Test get_multi_standard_checker returns singleton."""
        checker1 = get_multi_standard_checker()
        checker2 = get_multi_standard_checker()

        # Should be same instance if settings unchanged
        assert checker1 is checker2

    def test_get_multi_standard_checker_with_custom_settings(self, minimal_settings):
        """Test get_multi_standard_checker with custom settings."""
        checker = get_multi_standard_checker(minimal_settings)

        assert checker.settings == minimal_settings

    # HIPAA Tests

    def test_hipaa_check_returns_report(self, checker_minimal):
        """Test HIPAA check returns ComplianceReport."""
        report = checker_minimal.check_hipaa()

        assert isinstance(report, MultiStandardReport)
        assert report.standard == ComplianceStandard.HIPAA
        assert 0 <= report.score <= 100
        assert report.generated_at is not None

    def test_hipaa_check_minimal_compliance_fails(self, checker_minimal):
        """Test HIPAA check with minimal settings fails most controls."""
        report = checker_minimal.check_hipaa()

        # Most controls should fail
        assert len(report.failed_controls) > len(report.passed_controls)
        assert report.score < 50  # Less than 50% compliant

    def test_hipaa_check_full_compliance_passes(self, checker_hipaa):
        """Test HIPAA check with full compliance settings."""
        report = checker_hipaa.check_hipaa()

        # Most controls should pass
        assert len(report.passed_controls) >= 5
        assert report.score > 80  # At least 80% compliant

    def test_hipaa_unique_user_id_requires_healthcare_mode(self, checker_minimal):
        """Test HIPAA unique user ID check requires healthcare_mode."""
        report = checker_minimal.check_hipaa()

        # Find the unique user ID control
        control = next(c for c in report.failed_controls if "164.312(a)(1)" in c.control_id)

        assert control.status == ControlStatus.FAILED
        assert "healthcare_mode is disabled" in control.evidence

    def test_hipaa_emergency_access_check(self, checker_hipaa):
        """Test HIPAA emergency access check."""
        report = checker_hipaa.check_hipaa()

        # Find emergency access control
        control = next(c for c in report.passed_controls if "164.312(a)(2)(i)" in c.control_id)

        assert control.status == ControlStatus.PASSED
        assert any("Emergency access" in e for e in control.evidence)

    def test_hipaa_automatic_logoff_check(self, checker_hipaa):
        """Test HIPAA automatic logoff check."""
        report = checker_hipaa.check_hipaa()

        # Find automatic logoff control
        control = next(c for c in report.passed_controls if "164.312(a)(2)(iii)" in c.control_id)

        assert control.status == ControlStatus.PASSED
        assert any("15 minutes" in e for e in control.evidence)

    def test_hipaa_encryption_check_aes256(self, checker_hipaa):
        """Test HIPAA encryption check with AES-256."""
        report = checker_hipaa.check_hipaa()

        # Find encryption control
        control = next(c for c in report.passed_controls if "164.312(a)(2)(iv)" in c.control_id)

        assert control.status == ControlStatus.PASSED
        assert any("AES-256" in e for e in control.evidence)

    # NIST 800-53 Tests

    def test_nist_check_returns_report(self, checker_minimal):
        """Test NIST check returns ComplianceReport."""
        report = checker_minimal.check_nist_800_53()

        assert isinstance(report, MultiStandardReport)
        assert report.standard == ComplianceStandard.NIST_800_53

    def test_nist_crypto_protection_with_fips(self):
        """Test NIST SC-13 with FIPS enabled."""
        settings = Settings(fips_mode_enabled=True, fips_strict_mode=True)
        checker = ComplianceChecker(settings)

        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "SC-13")

        assert control.status == ControlStatus.PASSED
        assert any("FIPS 140-2" in e for e in control.evidence)

    # FedRAMP Tests

    def test_fedramp_check_returns_report(self, checker_minimal):
        """Test FedRAMP check returns ComplianceReport."""
        report = checker_minimal.check_fedramp()

        assert isinstance(report, MultiStandardReport)
        assert report.standard == ComplianceStandard.FEDRAMP

    def test_fedramp_mfa_requirement(self, checker_minimal):
        """Test FedRAMP MFA requirement fails without MFA."""
        report = checker_minimal.check_fedramp()

        control = next(c for c in report.failed_controls if c.control_id == "FR-IA-2")

        assert control.status == ControlStatus.FAILED
        assert "mfa_enabled is false" in control.evidence

    # eIDAS Tests

    def test_eidas_check_returns_report(self, checker_minimal):
        """Test eIDAS check returns ComplianceReport."""
        report = checker_minimal.check_eidas()

        assert isinstance(report, MultiStandardReport)
        assert report.standard == ComplianceStandard.EIDAS

    def test_eidas_technical_standards_check(self):
        """Test eIDAS PAdES-LTA compliance check."""
        settings = Settings(ltv_enabled=True, archive_ts_enabled=True)
        checker = ComplianceChecker(settings)

        report = checker.check_eidas()

        control = next(c for c in report.passed_controls if c.control_id == "eIDAS-Art.34")

        assert control.status == ControlStatus.PASSED
        assert any("PAdES-LTA" in e for e in control.evidence)

    # GDPR Tests

    def test_gdpr_check_returns_report(self, checker_minimal):
        """Test GDPR check returns ComplianceReport."""
        report = checker_minimal.check_gdpr()

        assert isinstance(report, MultiStandardReport)
        assert report.standard == ComplianceStandard.GDPR

    def test_gdpr_requires_enabled_flag(self, checker_minimal):
        """Test GDPR checks require gdpr_enabled flag."""
        report = checker_minimal.check_gdpr()

        # All controls should fail without gdpr_enabled
        assert all(
            "gdpr_enabled is false" in c.evidence
            for c in report.failed_controls
            if c.status == ControlStatus.FAILED
        )

    # SOC 2 Tests

    def test_soc2_check_returns_report(self, checker_minimal):
        """Test SOC 2 check returns ComplianceReport."""
        report = checker_minimal.check_soc2()

        assert isinstance(report, MultiStandardReport)
        assert report.standard == ComplianceStandard.SOC2

    def test_soc2_encryption_check(self):
        """Test SOC 2 CC6.7 encryption check."""
        settings = Settings(encryption_default_strength="aes256")
        checker = ComplianceChecker(settings)

        report = checker.check_soc2()

        control = next(c for c in report.passed_controls if c.control_id == "CC6.7")

        assert control.status == ControlStatus.PASSED
        assert any("AES-256" in e for e in control.evidence)

    # Overall Compliance Tests

    def test_check_all_returns_all_standards(self, checker_minimal):
        """Test check_all returns reports for all standards."""
        reports = checker_minimal.check_all()

        assert len(reports) == 6
        assert ComplianceStandard.HIPAA in reports
        assert ComplianceStandard.NIST_800_53 in reports
        assert ComplianceStandard.FEDRAMP in reports
        assert ComplianceStandard.EIDAS in reports
        assert ComplianceStandard.GDPR in reports
        assert ComplianceStandard.SOC2 in reports

    def test_get_overall_score_minimal_compliance(self, checker_minimal):
        """Test overall score with minimal compliance."""
        score = checker_minimal.get_overall_score()

        assert 0 <= score <= 100
        # Minimal settings should have low compliance
        assert score < 50

    def test_get_overall_score_high_compliance(self, checker_hipaa):
        """Test overall score with high compliance settings."""
        score = checker_hipaa.get_overall_score()

        assert 0 <= score <= 100
        # HIPAA-compliant settings should score reasonably well
        assert score > 60

    def test_report_contains_recommendations(self, checker_minimal):
        """Test report contains actionable recommendations."""
        report = checker_minimal.check_hipaa()

        # Should have recommendations for failed controls
        assert len(report.recommendations) > 0
        assert all(isinstance(r, str) for r in report.recommendations)

    def test_control_check_structure(self, checker_minimal):
        """Test ControlCheck has expected structure."""
        report = checker_minimal.check_hipaa()

        control = report.failed_controls[0]

        assert hasattr(control, "control_id")
        assert hasattr(control, "name")
        assert hasattr(control, "description")
        assert hasattr(control, "standard")
        assert hasattr(control, "status")
        assert hasattr(control, "evidence")
        assert hasattr(control, "recommendations")
        assert isinstance(control.evidence, list)
        assert isinstance(control.recommendations, list)

    def test_compliance_report_structure(self, checker_minimal):
        """Test ComplianceReport has expected structure."""
        report = checker_minimal.check_hipaa()

        assert hasattr(report, "standard")
        assert hasattr(report, "score")
        assert hasattr(report, "passed_controls")
        assert hasattr(report, "failed_controls")
        assert hasattr(report, "partial_controls")
        assert hasattr(report, "recommendations")
        assert hasattr(report, "generated_at")
        assert isinstance(report.passed_controls, list)
        assert isinstance(report.failed_controls, list)
        assert isinstance(report.partial_controls, list)

    def test_score_calculation_weights_controls(self):
        """Test score calculation uses control weights."""
        # Settings that pass some but not all controls
        settings = Settings(
            audit_enabled=True,  # Passes some controls
            healthcare_mode=False,  # Fails healthcare controls
        )
        checker = ComplianceChecker(settings)

        report = checker.check_hipaa()

        # Score should be between 0 and 100
        assert 0 <= report.score <= 100

        # Should have some passed and some failed
        assert len(report.passed_controls) > 0
        assert len(report.failed_controls) > 0
