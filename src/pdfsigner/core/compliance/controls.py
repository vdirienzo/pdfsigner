"""
controls.py - Compliance control definitions

Defines control checks for various standards:
- HIPAA Security Rule (§164.312)
- NIST 800-53 Rev 5
- FedRAMP Moderate
- eIDAS Regulation
- GDPR Data Protection
- SOC 2 Type II

Each control maps to specific settings/features in PDFSigner.
"""

from dataclasses import dataclass, field
from enum import Enum


class ComplianceStandard(str, Enum):
    """Supported compliance standards."""

    HIPAA = "hipaa"
    NIST_800_53 = "nist_800_53"
    FEDRAMP = "fedramp"
    EIDAS = "eidas"
    GDPR = "gdpr"
    SOC2 = "soc2"
    LEY_25506 = "ley_25506"  # Argentina Digital Signature Law


class ControlStatus(str, Enum):
    """Status of a control check."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    PARTIAL = "partial"


@dataclass
class ControlDefinition:
    """
    Definition of a compliance control.

    Includes metadata about the control and a check function.
    """

    control_id: str
    name: str
    description: str
    standard: ComplianceStandard
    category: str
    check_func: str  # Name of method to call on ComplianceChecker
    weight: float = 1.0  # Weight for scoring (0.5 = less critical, 2.0 = critical)
    required: bool = True  # If False, control is optional
    tags: list[str] = field(default_factory=list)


# ============================================================================
# HIPAA Security Rule (§164.312) - Technical Safeguards
# ============================================================================

HIPAA_CONTROLS = [
    ControlDefinition(
        control_id="HIPAA-164.312(a)(1)",
        name="Access Control - Unique User Identification",
        description="System must assign unique identifiers to track individual user activity",
        standard=ComplianceStandard.HIPAA,
        category="Access Control",
        check_func="_check_hipaa_unique_user_id",
        weight=2.0,
        tags=["authentication", "user_management"],
    ),
    ControlDefinition(
        control_id="HIPAA-164.312(a)(2)(i)",
        name="Access Control - Emergency Access Procedure",
        description="Establish procedures for obtaining access to ePHI during an emergency",
        standard=ComplianceStandard.HIPAA,
        category="Access Control",
        check_func="_check_hipaa_emergency_access",
        weight=1.5,
        tags=["emergency", "availability"],
    ),
    ControlDefinition(
        control_id="HIPAA-164.312(a)(2)(iii)",
        name="Access Control - Automatic Logoff",
        description="Implement electronic procedures to terminate session after predetermined time",
        standard=ComplianceStandard.HIPAA,
        category="Access Control",
        check_func="_check_hipaa_automatic_logoff",
        weight=2.0,
        tags=["session", "timeout"],
    ),
    ControlDefinition(
        control_id="HIPAA-164.312(a)(2)(iv)",
        name="Access Control - Encryption and Decryption",
        description="Implement mechanism to encrypt and decrypt ePHI",
        standard=ComplianceStandard.HIPAA,
        category="Access Control",
        check_func="_check_hipaa_encryption",
        weight=2.0,
        tags=["encryption", "confidentiality"],
    ),
    ControlDefinition(
        control_id="HIPAA-164.312(b)",
        name="Audit Controls",
        description=(
            "Implement hardware, software, and/or procedural mechanisms "
            "to record and examine activity"
        ),
        standard=ComplianceStandard.HIPAA,
        category="Audit",
        check_func="_check_hipaa_audit_controls",
        weight=2.0,
        tags=["audit", "logging"],
    ),
    ControlDefinition(
        control_id="HIPAA-164.312(c)(1)",
        name="Integrity - Mechanism to Authenticate ePHI",
        description=(
            "Implement electronic mechanisms to corroborate that ePHI "
            "has not been altered or destroyed"
        ),
        standard=ComplianceStandard.HIPAA,
        category="Integrity",
        check_func="_check_hipaa_integrity",
        weight=2.0,
        tags=["signatures", "integrity"],
    ),
    ControlDefinition(
        control_id="HIPAA-164.312(d)",
        name="Person or Entity Authentication",
        description=(
            "Implement procedures to verify that a person or entity "
            "seeking access is the one claimed"
        ),
        standard=ComplianceStandard.HIPAA,
        category="Authentication",
        check_func="_check_hipaa_authentication",
        weight=2.0,
        tags=["authentication", "mfa"],
    ),
]

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
# FedRAMP Moderate
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

# ============================================================================
# eIDAS Regulation (EU 910/2014)
# ============================================================================

EIDAS_CONTROLS = [
    ControlDefinition(
        control_id="eIDAS-Art.32",
        name="Qualified Electronic Signatures",
        description=(
            "Support for qualified electronic signatures with equivalent "
            "legal effect to handwritten signatures"
        ),
        standard=ComplianceStandard.EIDAS,
        category="Electronic Signatures",
        check_func="_check_eidas_qualified_signatures",
        weight=2.0,
        tags=["signatures", "qes"],
    ),
    ControlDefinition(
        control_id="eIDAS-Art.34",
        name="Technical Standards for Electronic Signatures",
        description="Compliance with technical standards (PAdES, XAdES, CAdES)",
        standard=ComplianceStandard.EIDAS,
        category="Electronic Signatures",
        check_func="_check_eidas_technical_standards",
        weight=2.0,
        tags=["pades", "lta"],
    ),
    ControlDefinition(
        control_id="eIDAS-Art.41",
        name="Qualified Electronic Time Stamps",
        description="Use of qualified electronic time stamps for long-term validity",
        standard=ComplianceStandard.EIDAS,
        category="Time Stamping",
        check_func="_check_eidas_timestamps",
        weight=1.5,
        tags=["timestamps", "tsa"],
    ),
    ControlDefinition(
        control_id="eIDAS-Art.24",
        name="Validation of Electronic Signatures",
        description="Certificate validation including revocation checking",
        standard=ComplianceStandard.EIDAS,
        category="Validation",
        check_func="_check_eidas_validation",
        weight=1.5,
        tags=["validation", "revocation"],
    ),
]

# ============================================================================
# GDPR (General Data Protection Regulation)
# ============================================================================

GDPR_CONTROLS = [
    ControlDefinition(
        control_id="GDPR-Art.17",
        name="Right to Erasure (Right to be Forgotten)",
        description="Ability to erase personal data and anonymize audit logs",
        standard=ComplianceStandard.GDPR,
        category="Data Subject Rights",
        check_func="_check_gdpr_right_to_erasure",
        weight=2.0,
        tags=["privacy", "deletion"],
    ),
    ControlDefinition(
        control_id="GDPR-Art.20",
        name="Right to Data Portability",
        description="Ability to export data in machine-readable format",
        standard=ComplianceStandard.GDPR,
        category="Data Subject Rights",
        check_func="_check_gdpr_data_portability",
        weight=1.5,
        tags=["privacy", "export"],
    ),
    ControlDefinition(
        control_id="GDPR-Art.5(1)(e)",
        name="Storage Limitation",
        description="Data retention policies and automatic cleanup",
        standard=ComplianceStandard.GDPR,
        category="Data Protection Principles",
        check_func="_check_gdpr_retention",
        weight=1.5,
        tags=["retention", "cleanup"],
    ),
    ControlDefinition(
        control_id="GDPR-Art.32",
        name="Security of Processing",
        description="Encryption and pseudonymization of personal data",
        standard=ComplianceStandard.GDPR,
        category="Security",
        check_func="_check_gdpr_encryption",
        weight=2.0,
        tags=["encryption", "security"],
    ),
    ControlDefinition(
        control_id="GDPR-Art.9",
        name="Processing of Special Categories of Personal Data",
        description="PHI/PII detection and protection mechanisms",
        standard=ComplianceStandard.GDPR,
        category="Special Data",
        check_func="_check_gdpr_phi_detection",
        weight=1.5,
        required=False,
        tags=["phi", "pii"],
    ),
]

# ============================================================================
# SOC 2 Type II - Trust Services Criteria
# ============================================================================

SOC2_CONTROLS = [
    # CC1: Control Environment
    ControlDefinition(
        control_id="CC1.1",
        name="Organization Structure",
        description="Define organizational structure with security responsibilities",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=1.5,
        tags=["governance", "rbac", "roles"],
    ),
    ControlDefinition(
        control_id="CC1.2",
        name="Management Philosophy",
        description="Demonstrate commitment to integrity and ethical values",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=1.5,
        tags=["governance", "policies", "documentation"],
    ),
    ControlDefinition(
        control_id="CC1.3",
        name="Board Oversight",
        description="Establish oversight responsibilities for security and compliance",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=1.5,
        tags=["governance", "audit", "oversight"],
    ),
    ControlDefinition(
        control_id="CC1.4",
        name="Competence and Separation of Duties",
        description="Demonstrate commitment to competence and enforce separation of duties",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=2.0,
        tags=["governance", "rbac", "permissions"],
    ),
    ControlDefinition(
        control_id="CC1.5",
        name="Accountability",
        description="Hold individuals accountable for internal control responsibilities",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=2.0,
        tags=["governance", "audit", "accountability"],
    ),
    # CC2: Communication and Information
    ControlDefinition(
        control_id="CC2.1",
        name="Internal Communication",
        description="Communicate information internally to support internal control",
        standard=ComplianceStandard.SOC2,
        category="Communication",
        check_func="_check_soc2_communication",
        weight=1.0,
        tags=["communication", "policies", "documentation"],
    ),
    ControlDefinition(
        control_id="CC2.2",
        name="External Communication",
        description="Communicate with external parties regarding security matters",
        standard=ComplianceStandard.SOC2,
        category="Communication",
        check_func="_check_soc2_communication",
        weight=1.0,
        tags=["communication", "documentation", "api"],
    ),
    ControlDefinition(
        control_id="CC2.3",
        name="Communication Channels",
        description="Select and develop communication channels for security information",
        standard=ComplianceStandard.SOC2,
        category="Communication",
        check_func="_check_soc2_communication",
        weight=1.5,
        tags=["communication", "tls", "audit"],
    ),
    # CC3: Risk Assessment
    ControlDefinition(
        control_id="CC3.1",
        name="Risk Identification",
        description="Identify and assess changes that could impact the control system",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=1.5,
        tags=["risk", "threats", "documentation"],
    ),
    ControlDefinition(
        control_id="CC3.2",
        name="Risk Analysis",
        description="Analyze identified risks to determine their impact",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=1.5,
        tags=["risk", "vulnerabilities", "analysis"],
    ),
    ControlDefinition(
        control_id="CC3.3",
        name="Risk Mitigation",
        description="Manage risks through response and mitigation activities",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=2.0,
        tags=["risk", "remediation", "sla"],
    ),
    ControlDefinition(
        control_id="CC3.4",
        name="Risk Monitoring",
        description="Continuously monitor risk factors and control effectiveness",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=2.0,
        tags=["risk", "monitoring", "breach_detection"],
    ),
    # CC4: Monitoring Activities
    ControlDefinition(
        control_id="CC4.1",
        name="Monitoring Controls",
        description="Establish baseline comparisons and evaluate monitoring results",
        standard=ComplianceStandard.SOC2,
        category="Monitoring",
        check_func="_check_soc2_monitoring_activities",
        weight=2.0,
        tags=["monitoring", "audit", "siem"],
    ),
    ControlDefinition(
        control_id="CC4.2",
        name="Reporting Deficiencies",
        description="Report control deficiencies to appropriate personnel",
        standard=ComplianceStandard.SOC2,
        category="Monitoring",
        check_func="_check_soc2_monitoring_activities",
        weight=1.5,
        tags=["monitoring", "reporting", "compliance"],
    ),
    # CC6: Logical and Physical Access Controls
    ControlDefinition(
        control_id="CC6.1",
        name="Logical Access Controls",
        description="Restrict logical access through use of access control software",
        standard=ComplianceStandard.SOC2,
        category="Security",
        check_func="_check_soc2_access_controls",
        weight=2.0,
        tags=["access", "authentication"],
    ),
    ControlDefinition(
        control_id="CC6.6",
        name="System Operations Monitoring",
        description="Implement detective controls through use of monitoring tools",
        standard=ComplianceStandard.SOC2,
        category="Security",
        check_func="_check_soc2_monitoring",
        weight=1.5,
        tags=["audit", "monitoring"],
    ),
    ControlDefinition(
        control_id="CC6.7",
        name="Encryption of Data in Transit and at Rest",
        description="Encrypt data transmissions and data at rest",
        standard=ComplianceStandard.SOC2,
        category="Security",
        check_func="_check_soc2_encryption",
        weight=2.0,
        tags=["encryption", "confidentiality"],
    ),
    # CC7: System Operations
    ControlDefinition(
        control_id="CC7.2",
        name="System Monitoring",
        description="Monitor system components and operation of those components",
        standard=ComplianceStandard.SOC2,
        category="System Operations",
        check_func="_check_soc2_system_monitoring",
        weight=1.5,
        tags=["audit", "logging"],
    ),
    # CC8: Change Management
    ControlDefinition(
        control_id="CC8.1",
        name="Change Detection",
        description="Detect changes to system components",
        standard=ComplianceStandard.SOC2,
        category="Change Management",
        check_func="_check_soc2_change_detection",
        weight=1.0,
        required=False,
        tags=["integrity", "audit"],
    ),
    # CC9: Risk Mitigation
    ControlDefinition(
        control_id="CC9.1",
        name="Vulnerability Management",
        description="Identify, prioritize, and remediate security vulnerabilities",
        standard=ComplianceStandard.SOC2,
        category="Risk Mitigation",
        check_func="_check_soc2_risk_mitigation",
        weight=1.5,
        tags=["vulnerabilities", "remediation", "scanning"],
    ),
    ControlDefinition(
        control_id="CC9.2",
        name="Vendor Risk Management",
        description="Assess and manage third-party vendor security risks",
        standard=ComplianceStandard.SOC2,
        category="Risk Mitigation",
        check_func="_check_soc2_risk_mitigation",
        weight=1.0,
        required=False,
        tags=["vendors", "dependencies", "supply_chain"],
    ),
]

# ============================================================================
# Argentine Ley 25.506 Controls
# ============================================================================

LEY_25506_CONTROLS: list[ControlDefinition] = [
    ControlDefinition(
        control_id="LEY25506-Art.2",
        name="Digital Signature Definition",
        description=(
            "Digital signature must be created using a procedure that requires "
            "information exclusively known to the signer, under their absolute control."
        ),
        standard=ComplianceStandard.LEY_25506,
        category="Signature",
        check_func="_check_ley25506_signature_control",
        weight=2.0,
        required=True,
        tags=["signature", "argentina", "legal"],
    ),
    ControlDefinition(
        control_id="LEY25506-Art.9.1",
        name="Certificate Validity Period",
        description=(
            "Signature must be created during the validity period of the digital certificate."
        ),
        standard=ComplianceStandard.LEY_25506,
        category="Certificate",
        check_func="_check_ley25506_cert_validity",
        weight=2.0,
        required=True,
        tags=["certificate", "validity", "argentina"],
    ),
    ControlDefinition(
        control_id="LEY25506-Art.9.2",
        name="Certificate Verification",
        description=("Signature must be verifiable using data contained in the certificate."),
        standard=ComplianceStandard.LEY_25506,
        category="Verification",
        check_func="_check_ley25506_verifiable",
        weight=1.5,
        required=True,
        tags=["verification", "argentina"],
    ),
    ControlDefinition(
        control_id="LEY25506-Art.9.3",
        name="Licensed Certifier",
        description=(
            "Certificate must be issued by a certifier licensed by the competent authority (AAIP)."
        ),
        standard=ComplianceStandard.LEY_25506,
        category="Certifier",
        check_func="_check_ley25506_licensed_certifier",
        weight=2.0,
        required=True,
        tags=["certifier", "aaip", "argentina", "critical"],
    ),
    ControlDefinition(
        control_id="LEY25506-CRYPTO-RSA",
        name="RSA Key Size",
        description=("RSA keys must be at least 2048 bits. 3072+ bits recommended."),
        standard=ComplianceStandard.LEY_25506,
        category="Cryptography",
        check_func="_check_ley25506_rsa_keysize",
        weight=1.5,
        required=True,
        tags=["cryptography", "rsa", "argentina"],
    ),
    ControlDefinition(
        control_id="LEY25506-CRYPTO-HASH",
        name="Hash Algorithm",
        description=("Must use SHA-256, SHA-384, or SHA-512. MD5 and SHA-1 are prohibited."),
        standard=ComplianceStandard.LEY_25506,
        category="Cryptography",
        check_func="_check_ley25506_hash_algorithm",
        weight=1.5,
        required=True,
        tags=["cryptography", "hash", "argentina"],
    ),
    ControlDefinition(
        control_id="LEY25506-FORMAT-PADES",
        name="PAdES Format",
        description=(
            "PDF signatures should use PAdES B-LT or B-LTA format for long-term validity."
        ),
        standard=ComplianceStandard.LEY_25506,
        category="Format",
        check_func="_check_ley25506_pades_format",
        weight=1.0,
        required=False,  # Recomendado pero no obligatorio
        tags=["format", "pades", "argentina"],
    ),
    ControlDefinition(
        control_id="LEY25506-TSA",
        name="Timestamp Authority",
        description=("Timestamps must comply with RFC 3161 from a trusted TSA."),
        standard=ComplianceStandard.LEY_25506,
        category="Timestamp",
        check_func="_check_ley25506_tsa",
        weight=1.0,
        required=False,
        tags=["timestamp", "tsa", "argentina"],
    ),
]

# ============================================================================
# Control Registry
# ============================================================================

CONTROL_REGISTRY = {
    ComplianceStandard.HIPAA: HIPAA_CONTROLS,
    ComplianceStandard.NIST_800_53: NIST_800_53_CONTROLS,
    ComplianceStandard.FEDRAMP: FEDRAMP_CONTROLS,
    ComplianceStandard.EIDAS: EIDAS_CONTROLS,
    ComplianceStandard.GDPR: GDPR_CONTROLS,
    ComplianceStandard.SOC2: SOC2_CONTROLS,
    ComplianceStandard.LEY_25506: LEY_25506_CONTROLS,
}


def get_controls_for_standard(standard: ComplianceStandard) -> list[ControlDefinition]:
    """
    Get all control definitions for a standard.

    Args:
        standard: Compliance standard

    Returns:
        List of control definitions
    """
    return CONTROL_REGISTRY.get(standard, [])


def get_all_controls() -> dict[ComplianceStandard, list[ControlDefinition]]:
    """
    Get all control definitions for all standards.

    Returns:
        Dictionary mapping standard to list of controls
    """
    return CONTROL_REGISTRY
