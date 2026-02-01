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
        control_id="SC-13",
        name="Cryptographic Protection",
        description="Implement FIPS-validated or NSA-approved cryptography",
        standard=ComplianceStandard.NIST_800_53,
        category="System and Communications Protection",
        check_func="_check_nist_crypto_protection",
        weight=2.0,
        tags=["fips", "cryptography"],
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
