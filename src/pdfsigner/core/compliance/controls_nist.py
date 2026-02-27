"""
controls_nist.py - NIST 800-53 Rev 5 and FedRAMP Moderate control definitions

NIST families included:
- AC: Access Control
- AU: Audit and Accountability
- IA: Identification and Authentication
- SC: System and Communications Protection

FedRAMP Moderate controls are derived from NIST 800-53.
"""

from pdfsigner.core.compliance.controls import ComplianceStandard, ControlDefinition

# ============================================================================
# NIST 800-53 Rev 5 - Moderate Baseline
# ============================================================================

NIST_800_53_CONTROLS = [
    # ========================================================================
    # Access Control (AC) Family
    # ========================================================================
    ControlDefinition(
        control_id="AC-2",
        name="Account Management",
        description=(
            "Manage system accounts including creation, activation, "
            "modification, review, and removal"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_account_management",
        weight=1.5,
        tags=["user_management", "accounts"],
    ),
    ControlDefinition(
        control_id="AC-3",
        name="Access Enforcement",
        description=(
            "Enforce approved authorizations for logical access to information and system resources"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_access_enforcement",
        weight=2.0,
        tags=["rbac", "authorization"],
    ),
    ControlDefinition(
        control_id="AC-5",
        name="Separation of Duties",
        description=(
            "Separate duties of individuals to prevent malicious activity without collusion"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_separation_of_duties",
        weight=1.5,
        tags=["rbac", "segregation"],
    ),
    ControlDefinition(
        control_id="AC-6",
        name="Least Privilege",
        description="Employ the principle of least privilege, allowing only authorized access",
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_least_privilege",
        weight=2.0,
        tags=["rbac", "privilege"],
    ),
    ControlDefinition(
        control_id="AC-7",
        name="Unsuccessful Logon Attempts",
        description=(
            "Enforce limit on consecutive invalid logon attempts "
            "and take action when limit is exceeded"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_failed_logon",
        weight=1.5,
        tags=["authentication", "brute_force"],
    ),
    ControlDefinition(
        control_id="AC-8",
        name="System Use Notification",
        description="Display system use notification message or banner before granting access",
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_system_use_notification",
        weight=1.0,
        tags=["notification", "consent"],
    ),
    ControlDefinition(
        control_id="AC-11",
        name="Session Lock",
        description=(
            "Prevent further access to the system by initiating "
            "a session lock after period of inactivity"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_session_lock",
        weight=2.0,
        tags=["session", "timeout"],
    ),
    ControlDefinition(
        control_id="AC-12",
        name="Session Termination",
        description="Automatically terminate a user session after a defined condition",
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_session_termination",
        weight=2.0,
        tags=["session", "timeout"],
    ),
    ControlDefinition(
        control_id="AC-17",
        name="Remote Access",
        description="Establish and document usage restrictions for remote access to the system",
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_remote_access",
        weight=1.5,
        required=False,  # Only applicable if API is exposed
        tags=["remote", "api"],
    ),
    ControlDefinition(
        control_id="AC-20",
        name="Use of External Systems",
        description="Establish terms and conditions for authorized use of external systems",
        standard=ComplianceStandard.NIST_800_53,
        category="Access Control",
        check_func="_check_nist_external_systems",
        weight=1.0,
        required=False,
        tags=["external", "integration"],
    ),
    # ========================================================================
    # Audit and Accountability (AU) Family
    # ========================================================================
    ControlDefinition(
        control_id="AU-2",
        name="Audit Events",
        description="Identify types of events that the system is capable of logging",
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_events",
        weight=2.0,
        tags=["audit", "logging"],
    ),
    ControlDefinition(
        control_id="AU-3",
        name="Content of Audit Records",
        description="Generate audit records containing information that establishes context",
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_content",
        weight=2.0,
        tags=["audit", "records"],
    ),
    ControlDefinition(
        control_id="AU-4",
        name="Audit Storage Capacity",
        description="Allocate audit log storage capacity to accommodate requirements",
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_storage",
        weight=1.5,
        tags=["audit", "storage"],
    ),
    ControlDefinition(
        control_id="AU-6",
        name="Audit Review, Analysis, and Reporting",
        description=(
            "Review and analyze system audit records for indications of inappropriate activity"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_review",
        weight=1.5,
        tags=["audit", "analysis"],
    ),
    ControlDefinition(
        control_id="AU-8",
        name="Time Stamps",
        description="Use internal system clocks to generate time stamps for audit records",
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_timestamps",
        weight=1.5,
        tags=["audit", "time"],
    ),
    ControlDefinition(
        control_id="AU-9",
        name="Protection of Audit Information",
        description=(
            "Protect audit information and audit logging tools from "
            "unauthorized access, modification, and deletion"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_protection",
        weight=2.0,
        tags=["audit", "integrity"],
    ),
    ControlDefinition(
        control_id="AU-11",
        name="Audit Record Retention",
        description=(
            "Retain audit records for defined time period consistent with records retention policy"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_retention",
        weight=1.5,
        tags=["audit", "retention"],
    ),
    ControlDefinition(
        control_id="AU-12",
        name="Audit Generation",
        description="Provide audit record generation capability for auditable events",
        standard=ComplianceStandard.NIST_800_53,
        category="Audit and Accountability",
        check_func="_check_nist_audit_generation",
        weight=2.0,
        tags=["audit", "logging"],
    ),
    # ========================================================================
    # Identification and Authentication (IA) Family
    # ========================================================================
    ControlDefinition(
        control_id="IA-2",
        name="Identification and Authentication (Organizational Users)",
        description="Uniquely identify and authenticate organizational users",
        standard=ComplianceStandard.NIST_800_53,
        category="Identification and Authentication",
        check_func="_check_nist_user_auth",
        weight=2.0,
        tags=["authentication", "identity"],
    ),
    ControlDefinition(
        control_id="IA-5",
        name="Authenticator Management",
        description=(
            "Manage system authenticators by verifying identity, "
            "establishing initial content, and ensuring strength"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="Identification and Authentication",
        check_func="_check_nist_authenticator_mgmt",
        weight=1.5,
        tags=["passwords", "credentials"],
    ),
    # ========================================================================
    # System and Communications Protection (SC) Family
    # ========================================================================
    ControlDefinition(
        control_id="SC-8",
        name="Transmission Confidentiality and Integrity",
        description="Protect confidentiality and integrity of transmitted information",
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_transmission_protection",
        weight=1.5,
        required=False,  # Only applicable if API is exposed
        tags=["tls", "encryption"],
    ),
    ControlDefinition(
        control_id="SC-12",
        name="Cryptographic Key Establishment and Management",
        description="Establish and manage cryptographic keys for required cryptography",
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_key_management",
        weight=2.0,
        tags=["crypto", "keys"],
    ),
    ControlDefinition(
        control_id="SC-13",
        name="Cryptographic Protection",
        description="Implement FIPS-validated or NSA-approved cryptography",
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_crypto_protection",
        weight=2.0,
        tags=["fips", "cryptography"],
    ),
    ControlDefinition(
        control_id="SC-17",
        name="Public Key Infrastructure Certificates",
        description=(
            "Issue public key certificates or obtain public key certificates from approved source"
        ),
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_pki_certificates",
        weight=1.5,
        tags=["pki", "certificates"],
    ),
    ControlDefinition(
        control_id="SC-23",
        name="Session Authenticity",
        description="Protect the authenticity of communications sessions",
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_session_authenticity",
        weight=1.5,
        tags=["session", "integrity"],
    ),
    ControlDefinition(
        control_id="SC-28",
        name="Protection of Information at Rest",
        description="Protect the confidentiality and integrity of information at rest",
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_data_at_rest",
        weight=2.0,
        tags=["encryption", "storage"],
    ),
]

# ============================================================================
# FedRAMP Moderate (derived from NIST 800-53)
# ============================================================================

FEDRAMP_CONTROLS = [
    ControlDefinition(
        control_id="FR-AC-2",
        name="Account Management",
        description="FedRAMP account management requirements including automated mechanisms",
        standard=ComplianceStandard.FEDRAMP,
        category="Access Control",
        check_func="_check_fedramp_account_management",
        weight=1.5,
        tags=["user_management", "accounts"],
    ),
    ControlDefinition(
        control_id="FR-AU-2",
        name="Audit Events",
        description="FedRAMP audit logging requirements with centralized management",
        standard=ComplianceStandard.FEDRAMP,
        category="Audit and Accountability",
        check_func="_check_fedramp_audit",
        weight=2.0,
        tags=["audit", "logging"],
    ),
    ControlDefinition(
        control_id="FR-IA-2",
        name="Multi-Factor Authentication",
        description="FedRAMP requires MFA for privileged and non-privileged accounts",
        standard=ComplianceStandard.FEDRAMP,
        category="Identification and Authentication",
        check_func="_check_fedramp_mfa",
        weight=2.0,
        tags=["mfa", "authentication"],
    ),
    ControlDefinition(
        control_id="FR-SC-13",
        name="FIPS 140-2 Cryptography",
        description="Use only FIPS 140-2 validated cryptographic modules",
        standard=ComplianceStandard.FEDRAMP,
        category="System and Communications Protection",
        check_func="_check_fedramp_fips",
        weight=2.0,
        tags=["fips", "cryptography"],
    ),
]
