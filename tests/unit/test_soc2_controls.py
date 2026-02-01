"""Tests for SOC 2 CC1-CC4 and CC9 controls."""

from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.compliance.communication import (
    CommunicationChecker,
    get_communication_checker,
)
from pdfsigner.core.compliance.controls import (
    ComplianceStandard,
    ControlStatus,
    get_controls_for_standard,
)
from pdfsigner.core.compliance.governance import GovernanceChecker, get_governance_checker
from pdfsigner.core.compliance.monitoring import MonitoringChecker, get_monitoring_checker
from pdfsigner.core.compliance.risk_assessment import (
    RiskAssessmentChecker,
    get_risk_assessment_checker,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_project_root(tmp_path):
    """Create a mock project structure."""
    # Create basic structure
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'pdfsigner'\n")
    (tmp_path / "src" / "pdfsigner" / "core").mkdir(parents=True)
    (tmp_path / "docs" / "security").mkdir(parents=True)

    # Create audit module
    audit_dir = tmp_path / "src" / "pdfsigner" / "core" / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "audit_logger.py").touch()
    (audit_dir / "audit_event.py").touch()
    (audit_dir / "audit_integrity.py").touch()
    (audit_dir / "siem_exporter.py").touch()

    # Create compliance module
    compliance_dir = tmp_path / "src" / "pdfsigner" / "core" / "compliance"
    compliance_dir.mkdir(parents=True)
    (compliance_dir / "checker.py").touch()
    (compliance_dir / "report_generator.py").touch()
    (compliance_dir / "formatters.py").touch()

    # Create breach module
    breach_dir = tmp_path / "src" / "pdfsigner" / "core" / "breach"
    breach_dir.mkdir(parents=True)
    (breach_dir / "breach_detector.py").touch()
    (breach_dir / "breach_manager.py").touch()
    (breach_dir / "breach_repository.py").touch()

    # Create API module
    api_dir = tmp_path / "src" / "pdfsigner" / "api"
    api_dir.mkdir(parents=True)
    (api_dir / "main.py").touch()
    (api_dir / "middleware").mkdir()
    (api_dir / "middleware" / "tls.py").touch()

    # Create exceptions
    (tmp_path / "src" / "pdfsigner" / "exceptions.py").touch()

    # Create config
    config_dir = tmp_path / "src" / "pdfsigner" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.py").touch()

    # Create security docs
    (tmp_path / "docs" / "security" / "access-control-policy.md").write_text("# Access Control\n")
    (tmp_path / "docs" / "security" / "audit-policy.md").write_text("# Audit\n")
    (tmp_path / "docs" / "security" / "encryption-policy.md").write_text("# Encryption\n")
    (tmp_path / "docs" / "security" / "incident-response-plan.md").write_text("# IRP\n")
    (tmp_path / "docs" / "security" / "change-management.md").write_text("# Change Mgmt\n")
    (tmp_path / "docs" / "security" / "SSP.md").write_text("# SLA response time\n")

    # Create SECURITY.md
    (tmp_path / "docs" / "SECURITY.md").write_text("# Security\nThreat model and risks\n")

    # Create SECURITY_AUDIT_REPORT.md
    (tmp_path / "docs" / "SECURITY_AUDIT_REPORT.md").write_text("# Audit Report\n")

    # Create CLAUDE.md
    (tmp_path / "CLAUDE.md").write_text("# Project\nSecurity and compliance requirements\n")

    # Create README.md
    (tmp_path / "README.md").write_text("# PDFSigner\nAPI endpoints available\n")

    # Create CHANGELOG.md
    (tmp_path / "CHANGELOG.md").write_text("## [1.0.0]\n### Security\n- Fix CVE-2024-001\n")

    return tmp_path


# =============================================================================
# CC1: Governance Tests
# =============================================================================


class TestGovernanceChecker:
    """Tests for GovernanceChecker (CC1)."""

    def test_governance_checker_initialization(self, mock_project_root):
        """Test governance checker initialization."""
        checker = GovernanceChecker(mock_project_root)
        assert checker.project_root == mock_project_root

    def test_governance_checker_auto_detect_root(self):
        """Test automatic project root detection."""
        checker = GovernanceChecker()
        assert checker.project_root is not None
        assert (checker.project_root / "pyproject.toml").exists()

    def test_check_organization_structure_success(self, mock_project_root):
        """Test CC1.1 organization structure check passes."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_organization_structure()

        assert result.control_id == "CC1.1"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert any("roles" in f.lower() or "rbac" in f.lower() for f in result.findings)

    def test_check_organization_structure_separation_of_duties(self, mock_project_root):
        """Test CC1.1 verifies separation of duties."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_organization_structure()

        assert result.evidence.get("admin_permissions") is not None
        assert result.evidence.get("auditor_permissions") is not None
        # Auditor should not have all admin permissions
        assert "separation of duties" in " ".join(result.findings).lower()

    def test_check_management_philosophy_success(self, mock_project_root):
        """Test CC1.2 management philosophy check passes."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_management_philosophy()

        assert result.control_id == "CC1.2"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert len(result.evidence.get("existing_policies", [])) >= 4

    def test_check_management_philosophy_missing_docs(self, tmp_path):
        """Test CC1.2 fails when security docs missing."""
        # Don't create security docs
        (tmp_path / "pyproject.toml").write_text("[project]\n")

        checker = GovernanceChecker(tmp_path)
        result = checker.check_management_philosophy()

        assert result.status == ControlStatus.FAILED
        assert any("not found" in f.lower() for f in result.findings)

    def test_check_board_oversight_success(self, mock_project_root):
        """Test CC1.3 board oversight check passes."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_board_oversight()

        assert result.control_id == "CC1.3"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert result.evidence.get("audit_components") is not None

    def test_check_board_oversight_siem_export(self, mock_project_root):
        """Test CC1.3 detects SIEM export capability."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_board_oversight()

        assert result.evidence.get("siem_export") is True
        assert any("siem" in f.lower() for f in result.findings)

    def test_check_competence_success(self, mock_project_root):
        """Test CC1.4 competence check passes."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_competence()

        assert result.control_id == "CC1.4"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert result.evidence.get("total_permissions") > 0

    def test_check_competence_no_god_mode(self, mock_project_root):
        """Test CC1.4 verifies no role has all permissions."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_competence()

        # Should report separation of duties enforced
        findings_text = " ".join(result.findings).lower()
        assert (
            "no god mode roles" in findings_text
            or "separation of duties" in findings_text
            or result.status == ControlStatus.PARTIAL
        )

    def test_check_accountability_success(self, mock_project_root):
        """Test CC1.5 accountability check passes."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_accountability()

        assert result.control_id == "CC1.5"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert result.evidence.get("audit_events_defined") is True

    def test_check_accountability_audit_integrity(self, mock_project_root):
        """Test CC1.5 verifies audit integrity."""
        checker = GovernanceChecker(mock_project_root)
        result = checker.check_accountability()

        assert result.evidence.get("audit_integrity") is True
        assert any("hmac" in f.lower() or "integrity" in f.lower() for f in result.findings)

    def test_run_all_governance_checks(self, mock_project_root):
        """Test running all CC1 governance checks."""
        checker = GovernanceChecker(mock_project_root)
        results = checker.run_all_checks()

        assert len(results) == 5
        assert all(r.control_id.startswith("CC1.") for r in results)

    def test_governance_checker_singleton(self, mock_project_root):
        """Test governance checker singleton pattern."""
        checker1 = get_governance_checker(mock_project_root)
        checker2 = get_governance_checker()

        assert checker1 is checker2


# =============================================================================
# CC2: Communication Tests
# =============================================================================


class TestCommunicationChecker:
    """Tests for CommunicationChecker (CC2)."""

    def test_communication_checker_initialization(self, mock_project_root):
        """Test communication checker initialization."""
        checker = CommunicationChecker(mock_project_root)
        assert checker.project_root == mock_project_root

    def test_check_internal_communication_success(self, mock_project_root):
        """Test CC2.1 internal communication check passes."""
        checker = CommunicationChecker(mock_project_root)
        result = checker.check_internal_communication()

        assert result.control_id == "CC2.1"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert result.evidence.get("policy_count", 0) >= 4

    def test_check_internal_communication_claude_md(self, mock_project_root):
        """Test CC2.1 verifies CLAUDE.md has security section."""
        checker = CommunicationChecker(mock_project_root)
        result = checker.check_internal_communication()

        assert result.evidence.get("claude_md_has_security") is True

    def test_check_external_communication_success(self, mock_project_root):
        """Test CC2.2 external communication check passes."""
        checker = CommunicationChecker(mock_project_root)
        result = checker.check_external_communication()

        assert result.control_id == "CC2.2"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert result.evidence.get("api_exists") is True

    def test_check_external_communication_openapi(self, mock_project_root):
        """Test CC2.2 detects OpenAPI documentation."""
        checker = CommunicationChecker(mock_project_root)
        result = checker.check_external_communication()

        assert result.evidence.get("openapi_docs") is True
        assert any("openapi" in f.lower() or "api docs" in f.lower() for f in result.findings)

    def test_check_communication_channels_success(self, mock_project_root):
        """Test CC2.3 communication channels check passes."""
        checker = CommunicationChecker(mock_project_root)
        result = checker.check_communication_channels()

        assert result.control_id == "CC2.3"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]

    def test_check_communication_channels_tls(self, mock_project_root):
        """Test CC2.3 detects TLS middleware."""
        checker = CommunicationChecker(mock_project_root)
        result = checker.check_communication_channels()

        assert result.evidence.get("tls_middleware_exists") is True
        assert result.evidence.get("tls_available") is True

    def test_run_all_communication_checks(self, mock_project_root):
        """Test running all CC2 communication checks."""
        checker = CommunicationChecker(mock_project_root)
        results = checker.run_all_checks()

        assert len(results) == 3
        assert all(r.control_id.startswith("CC2.") for r in results)

    def test_communication_checker_singleton(self, mock_project_root):
        """Test communication checker singleton pattern."""
        checker1 = get_communication_checker(mock_project_root)
        checker2 = get_communication_checker()

        assert checker1 is checker2


# =============================================================================
# CC3: Risk Assessment Tests
# =============================================================================


class TestRiskAssessmentChecker:
    """Tests for RiskAssessmentChecker (CC3)."""

    def test_risk_assessment_checker_initialization(self, mock_project_root):
        """Test risk assessment checker initialization."""
        checker = RiskAssessmentChecker(mock_project_root)
        assert checker.project_root == mock_project_root

    def test_check_risk_identification_success(self, mock_project_root):
        """Test CC3.1 risk identification check passes."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_identification()

        assert result.control_id == "CC3.1"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]

    def test_check_risk_identification_security_md(self, mock_project_root):
        """Test CC3.1 detects SECURITY.md."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_identification()

        assert "security_md_path" in result.evidence
        assert any("security.md" in f.lower() for f in result.findings)

    def test_check_risk_identification_missing_security_md(self, tmp_path):
        """Test CC3.1 fails when SECURITY.md missing."""
        (tmp_path / "pyproject.toml").write_text("[project]\n")

        checker = RiskAssessmentChecker(tmp_path)
        result = checker.check_risk_identification()

        assert result.status == ControlStatus.FAILED
        assert any("not found" in f.lower() for f in result.findings)

    def test_check_risk_analysis_success(self, mock_project_root):
        """Test CC3.2 risk analysis check passes."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_analysis()

        assert result.control_id == "CC3.2"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]

    def test_check_risk_analysis_audit_report(self, mock_project_root):
        """Test CC3.2 detects security audit report."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_analysis()

        assert result.evidence.get("audit_report") is True
        assert any("audit report" in f.lower() for f in result.findings)

    def test_check_risk_mitigation_success(self, mock_project_root):
        """Test CC3.3 risk mitigation check passes."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_mitigation()

        assert result.control_id == "CC3.3"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]

    def test_check_risk_mitigation_sla(self, mock_project_root):
        """Test CC3.3 detects SLA documentation."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_mitigation()

        # SLA defined in SSP.md
        assert any("sla" in f.lower() for f in result.findings)

    def test_check_risk_monitoring_success(self, mock_project_root):
        """Test CC3.4 risk monitoring check passes."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_monitoring()

        assert result.control_id == "CC3.4"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]

    def test_check_risk_monitoring_breach_detection(self, mock_project_root):
        """Test CC3.4 detects breach detection system."""
        checker = RiskAssessmentChecker(mock_project_root)
        result = checker.check_risk_monitoring()

        assert result.evidence.get("breach_components") is not None
        assert len(result.evidence.get("breach_components", [])) == 3

    def test_run_all_risk_assessment_checks(self, mock_project_root):
        """Test running all CC3 risk assessment checks."""
        checker = RiskAssessmentChecker(mock_project_root)
        results = checker.run_all_checks()

        assert len(results) == 4
        assert all(r.control_id.startswith("CC3.") for r in results)

    def test_risk_assessment_checker_singleton(self, mock_project_root):
        """Test risk assessment checker singleton pattern."""
        checker1 = get_risk_assessment_checker(mock_project_root)
        checker2 = get_risk_assessment_checker()

        assert checker1 is checker2


# =============================================================================
# CC4: Monitoring Tests
# =============================================================================


class TestMonitoringChecker:
    """Tests for MonitoringChecker (CC4)."""

    def test_monitoring_checker_initialization(self, mock_project_root):
        """Test monitoring checker initialization."""
        checker = MonitoringChecker(mock_project_root)
        assert checker.project_root == mock_project_root

    def test_check_monitoring_controls_success(self, mock_project_root):
        """Test CC4.1 monitoring controls check passes."""
        checker = MonitoringChecker(mock_project_root)
        result = checker.check_monitoring_controls()

        assert result.control_id == "CC4.1"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]
        assert result.evidence.get("audit_components_count", 0) > 0

    def test_check_monitoring_controls_comprehensive(self, mock_project_root):
        """Test CC4.1 detects comprehensive monitoring system."""
        checker = MonitoringChecker(mock_project_root)
        result = checker.check_monitoring_controls()

        # Should detect audit, SIEM, and breach detection
        assert result.evidence.get("siem_export") is True
        assert result.evidence.get("breach_detection") is True

    def test_check_reporting_deficiencies_success(self, mock_project_root):
        """Test CC4.2 reporting deficiencies check passes."""
        checker = MonitoringChecker(mock_project_root)
        result = checker.check_reporting_deficiencies()

        assert result.control_id == "CC4.2"
        assert result.status in [ControlStatus.PASSED, ControlStatus.PARTIAL]

    def test_check_reporting_deficiencies_components(self, mock_project_root):
        """Test CC4.2 detects reporting components."""
        checker = MonitoringChecker(mock_project_root)
        result = checker.check_reporting_deficiencies()

        assert result.evidence.get("compliance_checker") is True
        assert result.evidence.get("report_generator") is True
        assert result.evidence.get("audit_trail") is True

    def test_run_all_monitoring_checks(self, mock_project_root):
        """Test running all CC4 monitoring checks."""
        checker = MonitoringChecker(mock_project_root)
        results = checker.run_all_checks()

        assert len(results) == 2
        assert all(r.control_id.startswith("CC4.") for r in results)

    def test_monitoring_checker_singleton(self, mock_project_root):
        """Test monitoring checker singleton pattern."""
        checker1 = get_monitoring_checker(mock_project_root)
        checker2 = get_monitoring_checker()

        assert checker1 is checker2


# =============================================================================
# Control Definitions Tests
# =============================================================================


class TestControlDefinitions:
    """Tests for SOC 2 control definitions."""

    def test_soc2_controls_cc1_defined(self):
        """Test CC1 controls are defined."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)
        cc1_controls = [c for c in controls if c.control_id.startswith("CC1.")]

        assert len(cc1_controls) == 5
        assert all(c.category == "Control Environment" for c in cc1_controls)

    def test_soc2_controls_cc2_defined(self):
        """Test CC2 controls are defined."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)
        cc2_controls = [c for c in controls if c.control_id.startswith("CC2.")]

        assert len(cc2_controls) == 3
        assert all(c.category == "Communication" for c in cc2_controls)

    def test_soc2_controls_cc3_defined(self):
        """Test CC3 controls are defined."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)
        cc3_controls = [c for c in controls if c.control_id.startswith("CC3.")]

        assert len(cc3_controls) == 4
        assert all(c.category == "Risk Assessment" for c in cc3_controls)

    def test_soc2_controls_cc4_defined(self):
        """Test CC4 controls are defined."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)
        cc4_controls = [c for c in controls if c.control_id.startswith("CC4.")]

        assert len(cc4_controls) == 2
        assert all(c.category == "Monitoring" for c in cc4_controls)

    def test_soc2_controls_cc9_defined(self):
        """Test CC9 controls are defined."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)
        cc9_controls = [c for c in controls if c.control_id.startswith("CC9.")]

        assert len(cc9_controls) == 2
        assert all(c.category == "Risk Mitigation" for c in cc9_controls)

    def test_soc2_total_controls_count(self):
        """Test total SOC 2 controls count."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)

        # CC1(5) + CC2(3) + CC3(4) + CC4(2) + CC6(3) + CC7(1) + CC8(1) + CC9(2) = 21
        assert len(controls) >= 21

    def test_soc2_control_check_funcs_defined(self):
        """Test all SOC 2 controls have check functions defined."""
        controls = get_controls_for_standard(ComplianceStandard.SOC2)

        for control in controls:
            assert control.check_func is not None
            assert control.check_func.startswith("_check_soc2_")


# =============================================================================
# Integration Tests
# =============================================================================


class TestComplianceCheckerIntegration:
    """Integration tests for ComplianceChecker with new controls."""

    @patch("pdfsigner.config.settings.get_settings")
    def test_check_soc2_includes_new_controls(self, mock_get_settings):
        """Test SOC 2 check includes CC1-CC4 and CC9 controls."""
        from pdfsigner.core.compliance import ComplianceChecker

        # Create a mock settings object
        mock_settings = MagicMock()
        mock_settings.audit_enabled = True
        mock_settings.audit_retention_days = 365
        mock_settings.healthcare_mode = True
        mock_settings.mfa_enabled = True
        mock_settings.encryption_default_strength = "aes256"
        mock_get_settings.return_value = mock_settings

        checker = ComplianceChecker(mock_settings)
        report = checker.check_soc2()

        # Verify new controls are checked
        control_ids = [
            c.control_id
            for c in report.passed_controls + report.failed_controls + report.partial_controls
        ]

        assert any(cid.startswith("CC1.") for cid in control_ids)
        assert any(cid.startswith("CC2.") for cid in control_ids)
        assert any(cid.startswith("CC3.") for cid in control_ids)
        assert any(cid.startswith("CC4.") for cid in control_ids)

    @patch("pdfsigner.config.settings.get_settings")
    def test_check_soc2_governance_integration(self, mock_get_settings):
        """Test SOC 2 governance checks integrate with checker."""
        from pdfsigner.core.compliance import ComplianceChecker

        mock_settings = MagicMock()
        mock_get_settings.return_value = mock_settings

        checker = ComplianceChecker(mock_settings)

        # Should not raise exception
        report = checker.check_soc2()
        assert report is not None
        assert report.standard == ComplianceStandard.SOC2

    def test_checker_imports_new_modules(self):
        """Test checker can import new compliance modules."""
        from pdfsigner.core.compliance import (
            CommunicationChecker,
            GovernanceChecker,
            MonitoringChecker,
            RiskAssessmentChecker,
        )

        assert GovernanceChecker is not None
        assert CommunicationChecker is not None
        assert RiskAssessmentChecker is not None
        assert MonitoringChecker is not None
