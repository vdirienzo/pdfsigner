"""
controls_international.py - International regulation control definitions

Includes:
- eIDAS Regulation (EU 910/2014)
- GDPR (General Data Protection Regulation)
- Argentine Ley 25.506 (Digital Signature Law)
"""

from pdfsigner.core.compliance.controls import ComplianceStandard, ControlDefinition

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
