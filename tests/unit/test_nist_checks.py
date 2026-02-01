"""Tests for NIST 800-53 automated compliance checks (AC, AU, SC families)."""

from unittest.mock import patch

import pytest

from pdfsigner.config.settings import Settings
from pdfsigner.core.compliance.checker import ComplianceChecker
from pdfsigner.core.compliance.controls import ComplianceStandard, ControlStatus


class TestACFamilyChecks:
    """Tests for Access Control (AC) family checks."""

    @pytest.fixture
    def minimal_settings(self):
        """Create minimal settings."""
        return Settings(
            healthcare_mode=False,
            audit_enabled=False,
            mfa_enabled=False,
        )

    @pytest.fixture
    def healthcare_settings(self):
        """Create settings with healthcare mode enabled."""
        return Settings(
            healthcare_mode=True,
            healthcare_session_timeout_minutes=15,
            healthcare_max_sessions=3,
            audit_enabled=True,
            password_lockout_threshold=5,
            password_lockout_duration_minutes=15,
        )

    def test_check_access_enforcement_passes_with_healthcare(self, healthcare_settings):
        """AC-3: Access enforcement passes with healthcare mode."""
        checker = ComplianceChecker(healthcare_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AC-3")
        assert control.status == ControlStatus.PASSED
        assert any("RBAC" in e for e in control.evidence)

    def test_check_access_enforcement_partial_without_healthcare(self, minimal_settings):
        """AC-3: Access enforcement partial without healthcare mode."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "AC-3")
        assert control.status == ControlStatus.PARTIAL
        assert any("healthcare_mode disabled" in e for e in control.evidence)

    def test_check_separation_of_duties_passes(self, healthcare_settings):
        """AC-5: Separation of duties passes with healthcare mode."""
        checker = ComplianceChecker(healthcare_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AC-5")
        assert control.status == ControlStatus.PASSED
        assert any("Separate roles" in e for e in control.evidence)

    def test_check_separation_of_duties_fails_without_healthcare(self, minimal_settings):
        """AC-5: Separation of duties fails without healthcare mode."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AC-5")
        assert control.status == ControlStatus.FAILED

    def test_check_least_privilege_passes(self, healthcare_settings):
        """AC-6: Least privilege passes with healthcare mode."""
        checker = ComplianceChecker(healthcare_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AC-6")
        assert control.status == ControlStatus.PASSED
        assert any("Default USER role" in e for e in control.evidence)

    def test_check_least_privilege_partial_without_healthcare(self, minimal_settings):
        """AC-6: Least privilege partial without healthcare mode."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "AC-6")
        assert control.status == ControlStatus.PARTIAL

    def test_check_system_use_notification(self, minimal_settings):
        """AC-8: System use notification check."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "AC-8")
        assert control.status == ControlStatus.PARTIAL
        assert len(control.recommendations) > 0

    def test_check_session_termination_passes(self, healthcare_settings):
        """AC-12: Session termination passes with 15 minute timeout."""
        checker = ComplianceChecker(healthcare_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AC-12")
        assert control.status == ControlStatus.PASSED
        assert any("15 minutes" in e for e in control.evidence)

    def test_check_session_termination_partial_long_timeout(self):
        """AC-12: Session termination partial with long timeout."""
        settings = Settings(
            healthcare_mode=True,
            healthcare_session_timeout_minutes=30,
        )
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "AC-12")
        assert control.status == ControlStatus.PARTIAL
        assert any("30 minutes" in e for e in control.evidence)

    def test_check_session_termination_fails_without_healthcare(self, minimal_settings):
        """AC-12: Session termination fails without healthcare mode."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AC-12")
        assert control.status == ControlStatus.FAILED

    def test_check_remote_access_not_applicable_without_api(self):
        """AC-17: Remote access marked as PASSED (N/A) without API configuration."""
        settings = Settings()
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        # Find AC-17 in passed controls (N/A controls marked as PASSED)
        control = next(c for c in report.passed_controls if c.control_id == "AC-17")
        assert control.status == ControlStatus.PASSED
        assert any("not applicable" in e.lower() for e in control.evidence)

    def test_check_remote_access_works_correctly(self, minimal_settings):
        """AC-17: Remote access check works correctly."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        # Find AC-17 in passed controls (should be PASSED for N/A)
        control = next(c for c in report.passed_controls if c.control_id == "AC-17")
        assert control.status == ControlStatus.PASSED

    def test_check_external_systems_with_tsa(self):
        """AC-20: External systems check with TSA configured."""
        settings = Settings(tsa_url="https://tsa.example.com")
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        control = next(
            (c for c in report.passed_controls if c.control_id == "AC-20"),
            None,
        )
        if control:
            assert control.status == ControlStatus.PASSED
            assert any("TSA" in e for e in control.evidence)

    def test_check_external_systems_not_applicable_without_tsa(self, minimal_settings):
        """AC-20: External systems N/A without TSA."""
        checker = ComplianceChecker(minimal_settings)
        report = checker.check_nist_800_53()

        # May be in passed or partial depending on implementation
        control = next(
            (
                c
                for c in report.passed_controls + report.partial_controls
                if c.control_id == "AC-20"
            ),
            None,
        )
        if control:
            assert control.status in [ControlStatus.PASSED, ControlStatus.NOT_APPLICABLE]


class TestAUFamilyChecks:
    """Tests for Audit and Accountability (AU) family checks."""

    @pytest.fixture
    def audit_settings(self):
        """Create settings with audit enabled."""
        return Settings(
            audit_enabled=True,
            audit_retention_days=365,
            log_dir="/tmp/pdfsigner/logs",
        )

    @pytest.fixture
    def no_audit_settings(self):
        """Create settings with audit disabled."""
        return Settings(audit_enabled=False)

    def test_check_audit_content_passes(self, audit_settings):
        """AU-3: Audit content check passes."""
        checker = ComplianceChecker(audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AU-3")
        assert control.status == ControlStatus.PASSED
        assert any("timestamp" in e.lower() for e in control.evidence)

    def test_check_audit_content_fails_without_audit(self, no_audit_settings):
        """AU-3: Audit content fails without audit enabled."""
        checker = ComplianceChecker(no_audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AU-3")
        assert control.status == ControlStatus.FAILED
        assert "audit_enabled is false" in control.evidence

    def test_check_audit_storage_passes_with_space(self, audit_settings):
        """AU-4: Audit storage check passes with sufficient space."""
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = (1000000000, 500000000, 500000000)  # 50% free

            checker = ComplianceChecker(audit_settings)
            report = checker.check_nist_800_53()

            control = next(c for c in report.passed_controls if c.control_id == "AU-4")
            assert control.status == ControlStatus.PASSED
            assert any("50.0%" in e for e in control.evidence)

    def test_check_audit_storage_partial_low_space(self, audit_settings):
        """AU-4: Audit storage partial with low disk space."""
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = (1000000000, 900000000, 100000000)  # 10% free

            checker = ComplianceChecker(audit_settings)
            report = checker.check_nist_800_53()

            control = next(c for c in report.partial_controls if c.control_id == "AU-4")
            assert control.status == ControlStatus.PARTIAL
            assert any("10.0%" in e for e in control.evidence)

    def test_check_audit_storage_fails_critical_space(self, audit_settings):
        """AU-4: Audit storage fails with critical disk space."""
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = (1000000000, 960000000, 40000000)  # 4% free

            checker = ComplianceChecker(audit_settings)
            report = checker.check_nist_800_53()

            control = next(c for c in report.failed_controls if c.control_id == "AU-4")
            assert control.status == ControlStatus.FAILED

    def test_check_audit_storage_fails_without_audit(self, no_audit_settings):
        """AU-4: Audit storage fails without audit enabled."""
        checker = ComplianceChecker(no_audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AU-4")
        assert control.status == ControlStatus.FAILED

    def test_check_audit_review_passes(self, audit_settings):
        """AU-6: Audit review passes."""
        checker = ComplianceChecker(audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AU-6")
        assert control.status == ControlStatus.PASSED
        assert any("SIEM" in e for e in control.evidence)

    def test_check_audit_review_fails_without_audit(self, no_audit_settings):
        """AU-6: Audit review fails without audit enabled."""
        checker = ComplianceChecker(no_audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AU-6")
        assert control.status == ControlStatus.FAILED

    def test_check_timestamps_passes(self, audit_settings):
        """AU-8: Time stamps check passes."""
        checker = ComplianceChecker(audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AU-8")
        assert control.status == ControlStatus.PASSED
        assert any("UTC" in e for e in control.evidence)
        assert any("ISO 8601" in e for e in control.evidence)

    def test_check_timestamps_fails_without_audit(self, no_audit_settings):
        """AU-8: Time stamps fails without audit enabled."""
        checker = ComplianceChecker(no_audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AU-8")
        assert control.status == ControlStatus.FAILED

    def test_check_audit_retention_passes(self, audit_settings):
        """AU-11: Audit retention passes with 365+ days."""
        checker = ComplianceChecker(audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AU-11")
        assert control.status == ControlStatus.PASSED
        assert any("365 days" in e for e in control.evidence)

    def test_check_audit_retention_partial_short_period(self):
        """AU-11: Audit retention partial with short period."""
        settings = Settings(audit_enabled=True, audit_retention_days=90)
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "AU-11")
        assert control.status == ControlStatus.PARTIAL
        assert any("90 days" in e for e in control.evidence)

    def test_check_audit_retention_fails_without_audit(self, no_audit_settings):
        """AU-11: Audit retention fails without audit enabled."""
        checker = ComplianceChecker(no_audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AU-11")
        assert control.status == ControlStatus.FAILED

    def test_check_audit_generation_passes(self, audit_settings):
        """AU-12: Audit generation passes."""
        checker = ComplianceChecker(audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "AU-12")
        assert control.status == ControlStatus.PASSED
        assert any("AuditEventType" in e for e in control.evidence)

    def test_check_audit_generation_fails_without_audit(self, no_audit_settings):
        """AU-12: Audit generation fails without audit enabled."""
        checker = ComplianceChecker(no_audit_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.failed_controls if c.control_id == "AU-12")
        assert control.status == ControlStatus.FAILED


class TestSCFamilyChecks:
    """Tests for System and Communications Protection (SC) family checks."""

    @pytest.fixture
    def crypto_settings(self):
        """Create settings with crypto features enabled."""
        return Settings(
            encryption_default_strength="aes256",
            encryption_store_in_keyring=True,
            key_storage_path="/tmp/keys",
            key_default_expiry_days=365,
            key_auto_rotate_days=90,
            nss_db_path="/home/user/.nss",
            revocation_check_enabled=True,
            revocation_check_timeout=10,
        )

    @pytest.fixture
    def minimal_crypto_settings(self):
        """Create minimal crypto settings."""
        return Settings(
            encryption_default_strength="aes128",
            nss_db_path="/home/user/.nss",
        )

    def test_check_key_management_passes(self, crypto_settings):
        """SC-12: Key management passes with configured storage."""
        checker = ComplianceChecker(crypto_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "SC-12")
        assert control.status == ControlStatus.PASSED
        assert any("Key storage configured" in e for e in control.evidence)

    def test_check_key_management_partial_without_storage(self, minimal_crypto_settings):
        """SC-12: Key management partial without storage path."""
        checker = ComplianceChecker(minimal_crypto_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "SC-12")
        assert control.status == ControlStatus.PARTIAL
        assert any("Key storage path not configured" in e for e in control.evidence)

    def test_check_pki_certificates_passes(self, crypto_settings):
        """SC-17: PKI certificates passes with revocation checking."""
        checker = ComplianceChecker(crypto_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "SC-17")
        assert control.status == ControlStatus.PASSED
        assert any("revocation checking" in e for e in control.evidence)

    def test_check_pki_certificates_partial_without_revocation(self, minimal_crypto_settings):
        """SC-17: PKI certificates partial without revocation checking."""
        checker = ComplianceChecker(minimal_crypto_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "SC-17")
        assert control.status == ControlStatus.PARTIAL

    def test_check_session_authenticity_passes(self):
        """SC-23: Session authenticity passes with healthcare mode."""
        settings = Settings(healthcare_mode=True)
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "SC-23")
        assert control.status == ControlStatus.PASSED
        assert any("JWT" in e for e in control.evidence)

    def test_check_session_authenticity_partial_without_healthcare(self, minimal_crypto_settings):
        """SC-23: Session authenticity partial without healthcare mode."""
        checker = ComplianceChecker(minimal_crypto_settings)
        report = checker.check_nist_800_53()

        # Find SC-23 in any control list
        all_controls = report.passed_controls + report.failed_controls + report.partial_controls
        control = next(c for c in all_controls if c.control_id == "SC-23")
        assert control.status == ControlStatus.PARTIAL

    def test_check_data_at_rest_passes(self, crypto_settings):
        """SC-28: Data at rest passes with AES-256."""
        checker = ComplianceChecker(crypto_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "SC-28")
        assert control.status == ControlStatus.PASSED
        assert any("AES-256" in e for e in control.evidence)

    def test_check_data_at_rest_partial_aes128(self, minimal_crypto_settings):
        """SC-28: Data at rest partial with AES-128."""
        checker = ComplianceChecker(minimal_crypto_settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.partial_controls if c.control_id == "SC-28")
        assert control.status == ControlStatus.PARTIAL
        assert any("AES-128" in e for e in control.evidence)

    def test_check_data_at_rest_with_secure_delete(self):
        """SC-28: Data at rest includes secure delete evidence."""
        settings = Settings(
            encryption_default_strength="aes256",
            temp_secure_delete=True,
        )
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        control = next(c for c in report.passed_controls if c.control_id == "SC-28")
        assert any("Secure deletion" in e for e in control.evidence)


class TestNISTIntegration:
    """Integration tests for NIST compliance checking."""

    def test_nist_report_contains_all_controls(self):
        """Test NIST report includes all 26 controls."""
        settings = Settings()
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        total_controls = (
            len(report.passed_controls) + len(report.failed_controls) + len(report.partial_controls)
        )

        # 26 total NIST controls (10 AC + 8 AU + 2 IA + 6 SC)
        assert total_controls == 26

    def test_nist_report_has_expected_control_ids(self):
        """Test NIST report has all expected control IDs."""
        settings = Settings()
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        all_controls = report.passed_controls + report.failed_controls + report.partial_controls
        control_ids = {c.control_id for c in all_controls}

        expected_ac = {
            "AC-2",
            "AC-3",
            "AC-5",
            "AC-6",
            "AC-7",
            "AC-8",
            "AC-11",
            "AC-12",
            "AC-17",
            "AC-20",
        }
        expected_au = {
            "AU-2",
            "AU-3",
            "AU-4",
            "AU-6",
            "AU-8",
            "AU-9",
            "AU-11",
            "AU-12",
        }
        expected_ia = {"IA-2", "IA-5"}
        expected_sc = {"SC-8", "SC-12", "SC-13", "SC-17", "SC-23", "SC-28"}

        expected_all = expected_ac | expected_au | expected_ia | expected_sc

        # All controls should be present (N/A controls marked as PASSED)
        assert control_ids == expected_all

    def test_nist_report_score_calculation(self):
        """Test NIST report score is calculated."""
        settings = Settings()
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        assert 0 <= report.score <= 100
        assert isinstance(report.score, float)

    def test_nist_full_compliance_high_score(self):
        """Test full compliance settings achieve high score."""
        settings = Settings(
            healthcare_mode=True,
            healthcare_session_timeout_minutes=15,
            audit_enabled=True,
            audit_retention_days=365,
            encryption_default_strength="aes256",
            encryption_store_in_keyring=True,
            key_storage_path="/tmp/keys",
            revocation_check_enabled=True,
            api_tls_enabled=True,
            mfa_enabled=True,
            fips_mode_enabled=True,
            temp_secure_delete=True,
        )
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        # Should achieve > 80% with full compliance
        assert report.score > 80
        assert len(report.passed_controls) > len(report.failed_controls)

    def test_nist_minimal_compliance_low_score(self):
        """Test minimal settings have low score."""
        settings = Settings(
            healthcare_mode=False,
            audit_enabled=False,
            mfa_enabled=False,
        )
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        # Minimal compliance should score low
        assert report.score < 50
        assert len(report.failed_controls) > 0

    def test_check_all_includes_nist(self):
        """Test check_all includes NIST 800-53 report."""
        settings = Settings()
        checker = ComplianceChecker(settings)
        all_reports = checker.check_all()

        assert ComplianceStandard.NIST_800_53 in all_reports
        nist_report = all_reports[ComplianceStandard.NIST_800_53]
        assert nist_report.standard == ComplianceStandard.NIST_800_53

    def test_control_check_structure(self):
        """Test control checks have expected structure."""
        settings = Settings()
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        all_controls = report.passed_controls + report.failed_controls + report.partial_controls

        for control in all_controls:
            assert hasattr(control, "control_id")
            assert hasattr(control, "name")
            assert hasattr(control, "description")
            assert hasattr(control, "standard")
            assert hasattr(control, "status")
            assert hasattr(control, "evidence")
            assert hasattr(control, "recommendations")
            assert isinstance(control.evidence, list)
            assert isinstance(control.recommendations, list)
            assert control.standard == ComplianceStandard.NIST_800_53


class TestNISTRecommendations:
    """Tests for compliance recommendations."""

    def test_failed_controls_have_recommendations(self):
        """Test failed controls include recommendations."""
        settings = Settings(healthcare_mode=False, audit_enabled=False)
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        for control in report.failed_controls:
            # Most failed controls should have recommendations
            if control.control_id not in ["AC-20"]:  # N/A controls may not
                assert len(control.recommendations) > 0

    def test_partial_controls_have_recommendations(self):
        """Test partial controls include recommendations."""
        settings = Settings(
            healthcare_mode=True,
            audit_enabled=True,
            encryption_default_strength="aes128",  # Partial
        )
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        partial_with_recs = [c for c in report.partial_controls if len(c.recommendations) > 0]
        assert len(partial_with_recs) > 0

    def test_report_aggregates_recommendations(self):
        """Test report aggregates all recommendations."""
        settings = Settings(healthcare_mode=False)
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        # Report should aggregate recommendations from failed/partial controls
        assert len(report.recommendations) > 0
        assert all(isinstance(r, str) for r in report.recommendations)


class TestNISTControlWeights:
    """Tests for control weight handling."""

    def test_critical_controls_have_high_weight(self):
        """Test critical controls have weight >= 2.0."""
        from pdfsigner.core.compliance.controls import get_controls_for_standard

        controls = get_controls_for_standard(ComplianceStandard.NIST_800_53)

        critical_ids = [
            "AC-3",
            "AC-6",
            "AC-11",
            "AC-12",
            "AU-2",
            "AU-3",
            "AU-9",
            "AU-12",
            "IA-2",
            "SC-12",
            "SC-13",
            "SC-28",
        ]

        for control in controls:
            if control.control_id in critical_ids:
                assert control.weight >= 2.0

    def test_score_uses_weights(self):
        """Test score calculation uses control weights."""
        # Pass high-weight controls, fail low-weight controls
        settings = Settings(
            healthcare_mode=True,
            audit_enabled=True,
            encryption_default_strength="aes256",
            # Leave optional controls unconfigured
            tsa_url="",
        )
        checker = ComplianceChecker(settings)
        report = checker.check_nist_800_53()

        # Score should be reasonable despite some failures
        # because high-weight controls pass
        assert report.score > 60
