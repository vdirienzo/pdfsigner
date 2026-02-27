"""
controls_hipaa.py - HIPAA Security Rule (164.312) control definitions

Technical Safeguards for protecting electronic Protected Health Information (ePHI).
"""

from pdfsigner.core.compliance.controls import ComplianceStandard, ControlDefinition

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
