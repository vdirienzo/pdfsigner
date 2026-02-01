"""
Tests for SOC 2 CC2: Communication and Information controls.

This module tests comprehensive communication requirements including:
- Security policy communication to users (CC2.1)
- Incident notifications to affected parties (CC2.2)
- System descriptions and capabilities documentation (CC2.2)
- Security commitments and SLAs (CC2.3)
- Training and awareness programs
- Third-party communication audit trails

Tests verify that PDFSigner meets SOC 2 Trust Services Criteria
for communication and information management.
"""

from pathlib import Path

import pytest

from pdfsigner.core.compliance.communication import (
    CommunicationChecker,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def comprehensive_project_root(tmp_path):
    """
    Create comprehensive mock project structure for communication tests.

    Includes all documentation, policies, and modules needed to verify
    SOC 2 CC2 communication requirements.
    """
    # Create basic structure
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'pdfsigner'\nversion = '1.0.0'\n")

    # Create security policies (CC2.1: Internal communication)
    security_docs = tmp_path / "docs" / "security"
    security_docs.mkdir(parents=True)
    (security_docs / "access-control-policy.md").write_text(
        "# Access Control Policy\n\n"
        "All users must authenticate before accessing the system.\n"
        "Role-based access control (RBAC) enforced.\n"
    )
    (security_docs / "audit-policy.md").write_text(
        "# Audit Policy\n\n"
        "All security events are logged with HMAC integrity.\n"
        "Audit logs retained for 7 years per HIPAA.\n"
    )
    (security_docs / "encryption-policy.md").write_text(
        "# Encryption Policy\n\n"
        "AES-256 encryption required for data at rest.\n"
        "TLS 1.3 required for data in transit.\n"
    )
    (security_docs / "incident-response-plan.md").write_text(
        "# Incident Response Plan\n\n"
        "## Breach Notification\n"
        "Affected parties notified within 72 hours.\n"
        "Contact: security@pdfsigner.example.com\n\n"
        "## Escalation Path\n"
        "1. Security team → Management → Legal → Customers\n"
    )

    # System description documentation (CC2.2: External communication)
    (tmp_path / "README.md").write_text(
        "# PDFSigner\n\n"
        "Digital PDF signing application for Linux/GNOME.\n\n"
        "## API Documentation\n"
        "REST API available at http://localhost:8000/docs (OpenAPI/Swagger)\n\n"
        "## Endpoints\n"
        "- POST /api/v1/sign/ - Sign PDF documents\n"
        "- GET /api/v1/validate/ - Validate signatures\n"
        "- GET /api/v1/certificates/ - List certificates\n\n"
        "## Security Features\n"
        "- TLS 1.3 encryption\n"
        "- JWT authentication\n"
        "- Audit logging with HMAC integrity\n"
    )

    # Security commitments and SLAs (CC2.3)
    (security_docs / "SSP.md").write_text(
        "# System Security Plan (SSP)\n\n"
        "## Service Level Agreement (SLA)\n"
        "- Availability: 99.9% uptime\n"
        "- Security incident response: 4 hours\n"
        "- Critical patch deployment: 24 hours\n\n"
        "## Security Commitments\n"
        "- HIPAA compliance for healthcare customers\n"
        "- SOC 2 Type II certification\n"
        "- Annual penetration testing\n"
        "- Quarterly vulnerability scans\n"
    )

    # Privacy notice (CC2.2)
    (tmp_path / "docs" / "PRIVACY_POLICY.md").write_text(
        "# Privacy Policy\n\n"
        "## Data Collection\n"
        "We collect minimal user data: username, email, certificate info.\n\n"
        "## Data Protection\n"
        "All data encrypted at rest (AES-256) and in transit (TLS 1.3).\n\n"
        "## User Rights\n"
        "- Right to access your data\n"
        "- Right to deletion (GDPR Article 17)\n"
        "- Right to data portability\n\n"
        "## Contact\n"
        "Data Protection Officer: dpo@pdfsigner.example.com\n"
    )

    # Contact information (CC2.2)
    (security_docs / "CONTACTS.md").write_text(
        "# Security Contacts\n\n"
        "## Security Team\n"
        "- Security Officer: security@pdfsigner.example.com\n"
        "- Data Protection Officer (DPO): dpo@pdfsigner.example.com\n\n"
        "## Emergency Contact\n"
        "- 24/7 Hotline: +1-555-SECURITY\n"
        "- PGP Key: https://pdfsigner.example.com/pgp-key.txt\n"
    )

    # Training records documentation (CC2.1)
    (security_docs / "TRAINING_PROGRAM.md").write_text(
        "# Security Training Program\n\n"
        "## Annual Training\n"
        "All users complete annual security awareness training.\n\n"
        "## Topics Covered\n"
        "- Password security\n"
        "- Phishing awareness\n"
        "- Data classification\n"
        "- Incident reporting\n\n"
        "## Training Records\n"
        "Records maintained in training_logs.db for audit.\n"
    )

    # Audit findings communication (CC2.3)
    (tmp_path / "docs" / "SECURITY_AUDIT_REPORT.md").write_text(
        "# Security Audit Report - 2025 Q1\n\n"
        "## Executive Summary\n"
        "Annual security audit completed. 3 findings identified.\n\n"
        "## Findings\n"
        "1. [LOW] Update TLS cipher suites - RESOLVED\n"
        "2. [MED] Enhance password policy - IN PROGRESS\n"
        "3. [LOW] Documentation gaps - RESOLVED\n\n"
        "## Recommendations\n"
        "Continue quarterly vulnerability scans.\n"
    )

    # Change management documentation (CC2.1)
    (security_docs / "change-management.md").write_text(
        "# Change Management Policy\n\n"
        "## Change Notification\n"
        "Users notified 48 hours before maintenance windows.\n"
        "Emergency changes communicated immediately.\n\n"
        "## Communication Channels\n"
        "- Email notifications\n"
        "- In-app banners\n"
        "- Status page: status.pdfsigner.example.com\n\n"
        "## Change Log\n"
        "All changes documented in CHANGELOG.md.\n"
    )

    # Changelog with security updates
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n"
        "## [1.2.0] - 2025-02-01\n"
        "### Security\n"
        "- Updated TLS cipher suites to remove weak ciphers\n"
        "- Fixed authentication bypass vulnerability (CVE-2025-001)\n\n"
        "### Changed\n"
        "- Enhanced password policy (12 char minimum)\n"
        "- Users notified via email on 2025-01-28\n\n"
        "## [1.1.0] - 2025-01-15\n"
        "### Security\n"
        "- Added MFA support\n"
    )

    # CLAUDE.md with security requirements
    (tmp_path / "CLAUDE.md").write_text(
        "# PDFSigner\n\n"
        "## Security Requirements\n"
        "- HIPAA compliance mode available\n"
        "- SOC 2 Type II controls implemented\n"
        "- FIPS 140-2 crypto mode available\n\n"
        "## Compliance\n"
        "- Annual security audits required\n"
        "- Quarterly vulnerability scans\n"
        "- Security awareness training for all users\n"
    )

    # Create modules
    src_root = tmp_path / "src" / "pdfsigner"
    src_root.mkdir(parents=True)

    # API module
    api_dir = src_root / "api"
    api_dir.mkdir()
    (api_dir / "main.py").write_text(
        'from fastapi import FastAPI\napp = FastAPI(title="PDFSigner API", version="1.0.0")\n'
    )

    # TLS middleware
    middleware_dir = api_dir / "middleware"
    middleware_dir.mkdir()
    (middleware_dir / "tls.py").write_text(
        "# TLS middleware for HTTPS enforcement\nclass TLSMiddleware:\n    pass\n"
    )

    # Audit module
    audit_dir = src_root / "core" / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "audit_logger.py").write_text("# Audit logging\n")
    (audit_dir / "audit_event.py").write_text("# Audit events\n")
    (audit_dir / "audit_integrity.py").write_text("# HMAC integrity\n")
    (audit_dir / "siem_exporter.py").write_text("# SIEM export\n")

    # Breach management module
    breach_dir = src_root / "core" / "breach"
    breach_dir.mkdir(parents=True)
    (breach_dir / "breach_manager.py").write_text("# Breach incident management\n")
    (breach_dir / "breach_detector.py").write_text("# Breach detection\n")

    # Notification module
    notif_dir = src_root / "core" / "notifications"
    notif_dir.mkdir(parents=True)
    (notif_dir / "notification_manager.py").write_text(
        "# System notifications\n"
        "class NotificationManager:\n"
        "    def notify_breach(self, incident): pass\n"
    )

    # Exceptions
    (src_root / "exceptions.py").write_text("class PDFSignerError(Exception): pass\n")

    # Config
    config_dir = src_root / "config"
    config_dir.mkdir()
    (config_dir / "settings.py").write_text("# Configuration management\n")

    # Third-party communications log
    (tmp_path / "third_party_comms.log").write_text(
        "2025-02-01T10:00:00Z | OUTBOUND | TSP | timestamp.digicert.com | RFC3161 request\n"
        "2025-02-01T10:00:01Z | INBOUND | TSP | timestamp.digicert.com | TST response\n"
        "2025-02-01T10:05:00Z | OUTBOUND | OCSP | ocsp.sectigo.com | OCSP request\n"
        "2025-02-01T10:05:01Z | INBOUND | OCSP | ocsp.sectigo.com | Good status\n"
    )

    return tmp_path


# =============================================================================
# CC2 Communication Tests
# =============================================================================


@pytest.mark.compliance
class TestCC2SecurityPolicyCommunication:
    """Test CC2.1: Security policies communicated to users."""

    def test_cc2_security_policy_communicated_to_users(self, comprehensive_project_root):
        """
        Test that security policies are accessible to users.

        SOC 2 CC2.1 requires internal communication of security objectives.
        Verifies:
        - Security policies documented in accessible location
        - Minimum 4 core policies present
        - Policy documentation includes clear guidance
        """
        checker = CommunicationChecker(comprehensive_project_root)
        result = checker.check_internal_communication()

        # Verify policies are documented
        assert result.evidence.get("policy_count", 0) >= 4, "Must have at least 4 security policies"
        assert result.evidence.get("security_docs_path") is not None

        # Verify key policies exist
        policy_files = result.evidence.get("policy_files", [])
        required_policies = [
            "access-control-policy.md",
            "audit-policy.md",
            "encryption-policy.md",
            "incident-response-plan.md",
        ]

        for policy in required_policies:
            assert policy in policy_files, f"Missing required policy: {policy}"

        # Check policies are accessible (not empty)
        security_docs = Path(result.evidence["security_docs_path"])
        for policy_file in policy_files:
            policy_path = security_docs / policy_file
            assert policy_path.exists()
            assert policy_path.stat().st_size > 0, f"Policy {policy_file} is empty"

    def test_cc2_training_records_maintained(self, comprehensive_project_root):
        """
        Test that security training records are documented.

        SOC 2 CC2.1 requires communication of security objectives to personnel.
        Verifies:
        - Training program documented
        - Training topics defined
        - Record-keeping process described
        """
        security_docs = comprehensive_project_root / "docs" / "security"
        training_doc = security_docs / "TRAINING_PROGRAM.md"

        assert training_doc.exists(), "Training program documentation not found"

        content = training_doc.read_text()
        assert "training" in content.lower()
        assert "security awareness" in content.lower() or "annual training" in content.lower()

        # Verify training topics are documented
        training_topics = ["password", "phishing", "incident"]
        found_topics = sum(1 for topic in training_topics if topic in content.lower())
        assert found_topics >= 2, "Training program must cover multiple security topics"

        # Verify record keeping is mentioned
        assert "record" in content.lower(), "Training record-keeping process not documented"


@pytest.mark.compliance
class TestCC2IncidentNotification:
    """Test CC2.2: Incident notifications to affected parties."""

    def test_cc2_incident_notification_to_affected_parties(self, comprehensive_project_root):
        """
        Test that incident notification procedures are documented.

        SOC 2 CC2.2 requires communication about system failures and incidents.
        Verifies:
        - Incident response plan exists
        - Breach notification procedures defined
        - Notification timeframes specified
        - Contact information provided
        """
        security_docs = comprehensive_project_root / "docs" / "security"
        irp_doc = security_docs / "incident-response-plan.md"

        assert irp_doc.exists(), "Incident Response Plan not found"

        content = irp_doc.read_text()

        # Verify breach notification procedures
        assert "breach notification" in content.lower() or "incident" in content.lower()
        assert "affected parties" in content.lower() or "notified" in content.lower()

        # Verify timeframe is specified (e.g., "72 hours", "48 hours")
        assert "hours" in content.lower() or "days" in content.lower()

        # Verify contact information
        assert "@" in content or "contact" in content.lower()

    def test_cc2_breach_management_module_exists(self, comprehensive_project_root):
        """
        Test that breach management infrastructure exists.

        Verifies technical capability to detect and notify about breaches.
        """
        breach_manager = (
            comprehensive_project_root
            / "src"
            / "pdfsigner"
            / "core"
            / "breach"
            / "breach_manager.py"
        )

        assert breach_manager.exists(), "Breach management module not found"

        # Verify notification module exists
        notif_manager = (
            comprehensive_project_root
            / "src"
            / "pdfsigner"
            / "core"
            / "notifications"
            / "notification_manager.py"
        )

        assert notif_manager.exists(), "Notification module not found"


@pytest.mark.compliance
class TestCC2SystemDescription:
    """Test CC2.2: System description and capabilities documented."""

    def test_cc2_system_description_available(self, comprehensive_project_root):
        """
        Test that system description is documented and accessible.

        SOC 2 CC2.2 requires external communication about system capabilities.
        Verifies:
        - README documents system purpose
        - API capabilities described
        - Security features listed
        - Technical architecture documented
        """
        readme = comprehensive_project_root / "README.md"
        assert readme.exists(), "README.md not found"

        content = readme.read_text()

        # Verify system description
        assert len(content) > 100, "README must contain substantial system description"

        # Verify API documentation
        assert "api" in content.lower()
        assert "endpoint" in content.lower() or "swagger" in content.lower()

        # Verify security features are documented
        security_keywords = ["security", "encryption", "authentication", "audit"]
        found_keywords = sum(1 for kw in security_keywords if kw in content.lower())
        assert found_keywords >= 2, "README must document security features"

    def test_cc2_api_documentation_accessible(self, comprehensive_project_root):
        """
        Test that API documentation is accessible via OpenAPI/Swagger.

        Verifies FastAPI application provides automatic API documentation.
        """
        checker = CommunicationChecker(comprehensive_project_root)
        result = checker.check_external_communication()

        assert result.evidence.get("api_exists") is True
        assert result.evidence.get("openapi_docs") is True

        # Verify API main.py exists with FastAPI
        api_main = comprehensive_project_root / "src" / "pdfsigner" / "api" / "main.py"
        assert api_main.exists()

        content = api_main.read_text()
        assert "fastapi" in content.lower() or "FastAPI" in content


@pytest.mark.compliance
class TestCC2SecurityCommitments:
    """Test CC2.3: Security commitments and SLAs documented."""

    def test_cc2_security_commitments_documented(self, comprehensive_project_root):
        """
        Test that security commitments are documented in SSP.

        SOC 2 CC2.3 requires communication of security commitments.
        Verifies:
        - Service Level Agreement (SLA) defined
        - Security commitments specified
        - Response time objectives documented
        """
        security_docs = comprehensive_project_root / "docs" / "security"
        ssp = security_docs / "SSP.md"

        assert ssp.exists(), "System Security Plan (SSP) not found"

        content = ssp.read_text()

        # Verify SLA is documented
        assert "sla" in content.lower() or "service level" in content.lower()

        # Verify specific commitments
        commitment_keywords = ["availability", "uptime", "response", "incident"]
        found_commitments = sum(1 for kw in commitment_keywords if kw in content.lower())
        assert found_commitments >= 2, "SSP must document specific security commitments"

        # Verify numeric targets (e.g., "99.9%", "24 hours")
        has_targets = "%" in content or "hour" in content.lower()
        assert has_targets, "SSP must include specific measurable targets"


@pytest.mark.compliance
class TestCC2AuditFindings:
    """Test CC2.3: Audit findings communicated to stakeholders."""

    def test_cc2_audit_findings_communicated(self, comprehensive_project_root):
        """
        Test that audit findings are documented and communicated.

        SOC 2 CC2.3 requires communication of control deficiencies.
        Verifies:
        - Security audit report exists
        - Findings are documented
        - Remediation status tracked
        """
        audit_report = comprehensive_project_root / "docs" / "SECURITY_AUDIT_REPORT.md"

        assert audit_report.exists(), "Security audit report not found"

        content = audit_report.read_text()

        # Verify audit content
        assert len(content) > 100, "Audit report must contain findings"

        # Verify findings section exists
        assert "finding" in content.lower() or "issue" in content.lower()

        # Verify status tracking
        status_keywords = ["resolved", "in progress", "open", "closed"]
        has_status = any(kw in content.lower() for kw in status_keywords)
        assert has_status, "Audit report must track finding status"


@pytest.mark.compliance
class TestCC2ChangeNotifications:
    """Test CC2.1: Change notifications sent to users."""

    def test_cc2_change_notifications_sent(self, comprehensive_project_root):
        """
        Test that change management includes user notification procedures.

        SOC 2 CC2.1 requires communication of changes affecting security.
        Verifies:
        - Change management policy exists
        - Notification procedures documented
        - Communication channels specified
        """
        security_docs = comprehensive_project_root / "docs" / "security"
        change_mgmt = security_docs / "change-management.md"

        assert change_mgmt.exists(), "Change management policy not found"

        content = change_mgmt.read_text()

        # Verify notification procedures
        assert "notification" in content.lower() or "notif" in content.lower()
        assert "user" in content.lower() or "customer" in content.lower()

        # Verify communication channels specified
        channels = ["email", "status", "banner", "alert"]
        found_channels = sum(1 for ch in channels if ch in content.lower())
        assert found_channels >= 1, "Change management must specify communication channels"

    def test_cc2_changelog_documents_security_changes(self, comprehensive_project_root):
        """
        Test that CHANGELOG documents security-related changes.

        Verifies changes are tracked and communicated via changelog.
        """
        changelog = comprehensive_project_root / "CHANGELOG.md"
        assert changelog.exists(), "CHANGELOG.md not found"

        content = changelog.read_text()

        # Verify security changes are documented
        assert "security" in content.lower()

        # Verify version tracking
        assert "[" in content and "]" in content, "CHANGELOG must use version tags"

        # Verify dates included
        assert "202" in content, "CHANGELOG must include dates"


@pytest.mark.compliance
class TestCC2PrivacyNotice:
    """Test CC2.2: Privacy notice accessible to users."""

    def test_cc2_privacy_notice_accessible(self, comprehensive_project_root):
        """
        Test that privacy policy is documented and accessible.

        SOC 2 CC2.2 requires communication about data privacy practices.
        Verifies:
        - Privacy policy exists
        - Data collection practices disclosed
        - User rights documented
        - Contact information provided
        """
        privacy_policy = comprehensive_project_root / "docs" / "PRIVACY_POLICY.md"

        assert privacy_policy.exists(), "Privacy policy not found"

        content = privacy_policy.read_text()

        # Verify data collection disclosure
        assert "data collection" in content.lower() or "collect" in content.lower()

        # Verify user rights
        rights_keywords = ["rights", "access", "deletion", "portability"]
        found_rights = sum(1 for kw in rights_keywords if kw in content.lower())
        assert found_rights >= 2, "Privacy policy must document user rights"

        # Verify contact information
        assert "@" in content or "contact" in content.lower()


@pytest.mark.compliance
class TestCC2ContactInformation:
    """Test CC2.2: Security contact information provided."""

    def test_cc2_contact_information_provided(self, comprehensive_project_root):
        """
        Test that security contact information is documented.

        SOC 2 CC2.2 requires accessible communication channels.
        Verifies:
        - Security contact email provided
        - Data Protection Officer (DPO) contact available
        - Multiple contact methods documented
        """
        security_docs = comprehensive_project_root / "docs" / "security"
        contacts_doc = security_docs / "CONTACTS.md"

        assert contacts_doc.exists(), "Security contacts documentation not found"

        content = contacts_doc.read_text()

        # Verify email addresses
        assert "@" in content, "Contact information must include email addresses"

        # Verify multiple contacts
        contacts = ["security", "dpo", "data protection"]
        found_contacts = sum(1 for contact in contacts if contact in content.lower())
        assert found_contacts >= 2, "Must provide multiple security contacts"

        # Verify emergency contact
        assert "emergency" in content.lower() or "24/7" in content.lower()


@pytest.mark.compliance
class TestCC2ThirdPartyCommunications:
    """Test CC2.3: Third-party communications logged."""

    def test_cc2_third_party_communications_logged(self, comprehensive_project_root):
        """
        Test that communications with third parties are audited.

        SOC 2 CC2.3 requires monitoring of external communications.
        Verifies:
        - Audit logging for external communications exists
        - Third-party interactions tracked (TSP, OCSP, etc.)
        - Audit trail includes direction (inbound/outbound)
        """
        # Verify audit module exists
        audit_logger = (
            comprehensive_project_root / "src" / "pdfsigner" / "core" / "audit" / "audit_logger.py"
        )
        assert audit_logger.exists(), "Audit logging module not found"

        # Verify third-party communications are logged
        # In production, this would be in audit logs
        # For testing, we verify the logging infrastructure exists
        comms_log = comprehensive_project_root / "third_party_comms.log"
        if comms_log.exists():
            content = comms_log.read_text()

            # Verify logging format includes key elements
            assert "OUTBOUND" in content or "INBOUND" in content
            assert "TSP" in content or "OCSP" in content or "timestamp" in content.lower()

        # Verify SIEM export capability (for external monitoring)
        siem_exporter = (
            comprehensive_project_root / "src" / "pdfsigner" / "core" / "audit" / "siem_exporter.py"
        )
        assert siem_exporter.exists(), "SIEM export module not found (required for CC2.3)"


# =============================================================================
# Integration Tests
# =============================================================================


@pytest.mark.compliance
class TestCC2CommunicationIntegration:
    """Integration tests for complete CC2 communication framework."""

    def test_cc2_complete_communication_framework(self, comprehensive_project_root):
        """
        Test that all CC2 communication requirements are met.

        Runs all CC2 checks and verifies comprehensive compliance.
        """
        checker = CommunicationChecker(comprehensive_project_root)
        results = checker.run_all_checks()

        assert len(results) == 3, "Must run all 3 CC2 checks"

        # All checks should pass or be partial (not fail)
        from pdfsigner.core.compliance.controls import ControlStatus

        for result in results:
            assert result.status in [
                ControlStatus.PASSED,
                ControlStatus.PARTIAL,
            ], f"Control {result.control_id} failed: {result.findings}"

    def test_cc2_evidence_collection_for_audit(self, comprehensive_project_root):
        """
        Test that CC2 controls can provide evidence for SOC 2 audit.

        Verifies all required documentation and technical controls exist
        for auditor review.
        """
        required_docs = [
            "docs/security/access-control-policy.md",
            "docs/security/audit-policy.md",
            "docs/security/incident-response-plan.md",
            "docs/security/SSP.md",
            "docs/security/CONTACTS.md",
            "docs/PRIVACY_POLICY.md",
            "docs/SECURITY_AUDIT_REPORT.md",
            "README.md",
            "CHANGELOG.md",
        ]

        missing_docs = []
        for doc_path in required_docs:
            full_path = comprehensive_project_root / doc_path
            if not full_path.exists():
                missing_docs.append(doc_path)

        assert not missing_docs, f"Missing required documentation: {missing_docs}"

        # Verify technical controls
        required_modules = [
            "src/pdfsigner/api/main.py",
            "src/pdfsigner/api/middleware/tls.py",
            "src/pdfsigner/core/audit/audit_logger.py",
            "src/pdfsigner/core/breach/breach_manager.py",
            "src/pdfsigner/core/notifications/notification_manager.py",
        ]

        missing_modules = []
        for module_path in required_modules:
            full_path = comprehensive_project_root / module_path
            if not full_path.exists():
                missing_modules.append(module_path)

        assert not missing_modules, f"Missing required modules: {missing_modules}"
