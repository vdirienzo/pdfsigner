"""
qeaa_handler.py - Qualified Electronic Attestation of Attributes handler

Handles QEAA (Qualified Electronic Attestation of Attributes) from
the EU Digital Identity Wallet ecosystem.

Standards:
- CIR (EU) 2025/1569 (QEAAs and EAAs from authentic sources)
- eIDAS 2 Regulation (EU) 2024/1183

QEAA types:
- Professional qualifications (medical license, law degree)
- Academic qualifications (university degrees)
- Public permits and licenses
- Corporate roles and mandates
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class QEAAType(str, Enum):
    """Types of Qualified Electronic Attestation of Attributes."""

    PROFESSIONAL = "professional"  # Professional qualifications
    ACADEMIC = "academic"  # Academic qualifications
    LICENSE = "license"  # Public permits and licenses
    CORPORATE = "corporate"  # Corporate roles and mandates
    IDENTITY = "identity"  # Identity attributes (age, nationality)
    CUSTOM = "custom"  # Other attributes


@dataclass
class QEAAAttribute:
    """A single QEAA attribute."""

    name: str
    value: Any
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    verified: bool = False


@dataclass
class QEAAResult:
    """Parsed QEAA information."""

    qeaa_type: QEAAType = QEAAType.CUSTOM
    issuer: str = ""
    issuer_country: str = ""
    subject_name: str = ""
    attributes: list[QEAAAttribute] = field(default_factory=list)
    is_qualified: bool = False  # True if issued by a QTSP
    credential_type: str = ""
    issues: list[str] = field(default_factory=list)


# Mapping of credential types to QEAA types
CREDENTIAL_TYPE_MAP: dict[str, QEAAType] = {
    "ProfessionalQualification": QEAAType.PROFESSIONAL,
    "MedicalLicense": QEAAType.PROFESSIONAL,
    "LawDegree": QEAAType.ACADEMIC,
    "UniversityDegree": QEAAType.ACADEMIC,
    "DrivingLicense": QEAAType.LICENSE,
    "PublicPermit": QEAAType.LICENSE,
    "CorporateRole": QEAAType.CORPORATE,
    "PowerOfAttorney": QEAAType.CORPORATE,
}

# Professional attribute names
PROFESSIONAL_ATTRS = {
    "profession",
    "specialization",
    "license_number",
    "licensing_authority",
    "practice_country",
    "qualification_level",
    "registration_number",
}

# Academic attribute names
ACADEMIC_ATTRS = {
    "degree_name",
    "degree_level",
    "institution",
    "graduation_date",
    "field_of_study",
    "grade",
}


def parse_qeaa_from_claims(
    claims: dict[str, Any],
    credential_type: str = "",
    issuer: str = "",
) -> QEAAResult:
    """Parse QEAA attributes from SD-JWT VC claims.

    Args:
        claims: Dictionary of claims from SD-JWT VC
        credential_type: The vct (verifiable credential type) value
        issuer: Credential issuer

    Returns:
        QEAAResult with parsed attributes
    """
    result = QEAAResult(
        issuer=issuer,
        credential_type=credential_type,
    )

    # Determine QEAA type
    result.qeaa_type = CREDENTIAL_TYPE_MAP.get(credential_type, QEAAType.CUSTOM)

    # Extract subject name
    given_name = claims.get("given_name", "")
    family_name = claims.get("family_name", "")
    if given_name or family_name:
        result.subject_name = f"{given_name} {family_name}".strip()

    # Extract attributes based on type
    for key, value in claims.items():
        if key in PROFESSIONAL_ATTRS or key in ACADEMIC_ATTRS:
            result.attributes.append(
                QEAAAttribute(
                    name=key,
                    value=value,
                    issuer=issuer,
                    verified=True,  # Comes from SD-JWT VC
                )
            )

    # Also include any custom attributes not in known sets
    known_attrs = (
        PROFESSIONAL_ATTRS
        | ACADEMIC_ATTRS
        | {
            "given_name",
            "family_name",
            "birth_date",
            "iss",
            "sub",
            "iat",
            "exp",
            "vct",
            "type",
        }
    )
    for key, value in claims.items():
        if key not in known_attrs and not key.startswith("_"):
            result.attributes.append(
                QEAAAttribute(
                    name=key,
                    value=value,
                    issuer=issuer,
                )
            )

    logger.debug(
        "Parsed QEAA: type=%s, subject=%s, attributes=%d",
        result.qeaa_type.value,
        result.subject_name,
        len(result.attributes),
    )

    return result


def format_qeaa_for_signature_metadata(result: QEAAResult) -> dict[str, Any]:
    """Format QEAA result for inclusion in signature metadata.

    Creates a metadata dictionary that can be embedded in the
    PDF signature's signed attributes to record the signer's
    professional qualifications or other attested attributes.

    Args:
        result: Parsed QEAA result

    Returns:
        Dictionary for signature metadata
    """
    metadata: dict[str, Any] = {
        "qeaa_type": result.qeaa_type.value,
        "issuer": result.issuer,
        "is_qualified": result.is_qualified,
    }

    if result.subject_name:
        metadata["subject"] = result.subject_name

    if result.attributes:
        metadata["attributes"] = {
            attr.name: attr.value for attr in result.attributes if attr.verified
        }

    return metadata
