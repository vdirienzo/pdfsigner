"""
patterns.py - PHI detection patterns for HIPAA compliance

Defines detection patterns for the 18 HIPAA identifiers per §164.514.
These patterns enable automated detection of Protected Health Information
in PDF documents.

Author: Homero Thompson del Lago del Terror
"""

from dataclasses import dataclass
from enum import Enum


class PHIType(str, Enum):
    """
    Types of Protected Health Information per HIPAA §164.514.

    18 identifiers that must be removed for de-identification.
    """

    SSN = "ssn"  # Social Security Number
    MRN = "mrn"  # Medical Record Number
    DOB = "dob"  # Date of Birth
    PHONE = "phone"  # Phone numbers
    EMAIL = "email"  # Email addresses
    ADDRESS = "address"  # Street addresses
    INSURANCE_ID = "insurance_id"  # Insurance/policy numbers
    ICD10 = "icd10"  # ICD-10 diagnosis codes
    CPT = "cpt"  # CPT procedure codes
    NAME = "name"  # Patient names (harder to detect)
    ACCOUNT_NUMBER = "account_number"  # Account numbers
    LICENSE_NUMBER = "license_number"  # License/certificate numbers
    IP_ADDRESS = "ip_address"  # IP addresses
    URL = "url"  # URLs (may contain identifiers)
    DEVICE_ID = "device_id"  # Device identifiers/serial numbers
    FAX = "fax"  # Fax numbers
    VIN = "vin"  # Vehicle identification numbers
    ZIP_CODE = "zip_code"  # ZIP codes (more than 3 digits)


@dataclass
class PHIPattern:
    """
    Detection pattern for a specific PHI type.

    Attributes:
        phi_type: Type of PHI this pattern detects
        pattern: Regular expression pattern
        description: Human-readable description
        confidence_weight: Base confidence score (0.0-1.0)
        enabled: Whether this pattern is active
        requires_context: Whether pattern needs context validation
    """

    phi_type: PHIType
    pattern: str
    description: str
    confidence_weight: float  # 0.0-1.0
    enabled: bool = True
    requires_context: bool = False

    def __post_init__(self) -> None:
        """Validate pattern configuration."""
        if not 0.0 <= self.confidence_weight <= 1.0:
            msg = f"confidence_weight must be 0.0-1.0, got {self.confidence_weight}"
            raise ValueError(msg)


# HIPAA PHI Detection Patterns
# Based on 18 identifiers per §164.514(b)(2)

HIPAA_PATTERNS: list[PHIPattern] = [
    # 1. Social Security Numbers
    PHIPattern(
        phi_type=PHIType.SSN,
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        description="SSN with dashes (123-45-6789)",
        confidence_weight=0.95,
    ),
    PHIPattern(
        phi_type=PHIType.SSN,
        pattern=r"\b(?:SSN|Social Security)\s*[:#]?\s*(\d{3}-?\d{2}-?\d{4})\b",
        description="SSN with label",
        confidence_weight=0.98,
    ),
    PHIPattern(
        phi_type=PHIType.SSN,
        pattern=r"\b\d{9}\b",
        description="SSN without dashes (9 consecutive digits)",
        confidence_weight=0.70,  # Lower confidence - could be other numbers
        requires_context=True,
    ),
    # 2. Medical Record Numbers
    PHIPattern(
        phi_type=PHIType.MRN,
        pattern=r"\b(?:MRN|MR#?|Medical Record|Chart)\s*[:#]?\s*[A-Z0-9]{6,12}\b",
        description="Medical Record Number with label",
        confidence_weight=0.95,
    ),
    PHIPattern(
        phi_type=PHIType.MRN,
        pattern=r"\b(?:Patient|Record)\s+(?:ID|Number)\s*[:#]?\s*[A-Z0-9]{6,12}\b",
        description="Patient ID/Record Number",
        confidence_weight=0.90,
    ),
    # 3. Date of Birth
    PHIPattern(
        phi_type=PHIType.DOB,
        pattern=r"\b(?:DOB|Date of Birth|Born)\s*[:#]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
        description="Date of birth with label",
        confidence_weight=0.95,
    ),
    PHIPattern(
        phi_type=PHIType.DOB,
        pattern=(
            r"\b(?:DOB|Date of Birth|Born)\s*[:#]?\s*"
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b"
        ),
        description="DOB in text format (January 15, 1980)",
        confidence_weight=0.95,
    ),
    # 4. Phone Numbers
    PHIPattern(
        phi_type=PHIType.PHONE,
        pattern=r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
        description="US phone number (various formats)",
        confidence_weight=0.85,
    ),
    PHIPattern(
        phi_type=PHIType.PHONE,
        pattern=(
            r"\b(?:Phone|Tel|Mobile|Cell)\s*[:#]?\s*"
            r"(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"
        ),
        description="Phone number with label",
        confidence_weight=0.92,
    ),
    # 5. Fax Numbers
    PHIPattern(
        phi_type=PHIType.FAX,
        pattern=r"\b(?:Fax|Facsimile)\s*[:#]?\s*(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
        description="Fax number with label",
        confidence_weight=0.92,
    ),
    # 6. Email Addresses
    PHIPattern(
        phi_type=PHIType.EMAIL,
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        description="Email address",
        confidence_weight=0.90,
    ),
    # 7. Street Addresses
    PHIPattern(
        phi_type=PHIType.ADDRESS,
        pattern=r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir)\b",
        description="Street address",
        confidence_weight=0.85,
    ),
    PHIPattern(
        phi_type=PHIType.ADDRESS,
        pattern=r"\b(?:Address|Residence)\s*[:#]?\s*\d{1,6}\s+[A-Za-z0-9\s,]+(?:Street|St|Avenue|Ave|Road|Rd)\b",
        description="Address with label",
        confidence_weight=0.90,
    ),
    # 8. ZIP Codes (last 4+ digits)
    PHIPattern(
        phi_type=PHIType.ZIP_CODE,
        pattern=r"\b\d{5}-\d{4}\b",
        description="ZIP+4 code",
        confidence_weight=0.88,
    ),
    # 9. Insurance/Policy Numbers
    PHIPattern(
        phi_type=PHIType.INSURANCE_ID,
        pattern=r"\b(?:Insurance|Policy|Member|Subscriber)\s*(?:ID|#|No\.?|Number)\s*[:#]?\s*[A-Z0-9]{8,20}\b",
        description="Insurance ID with label",
        confidence_weight=0.93,
    ),
    PHIPattern(
        phi_type=PHIType.INSURANCE_ID,
        pattern=r"\b(?:Group|Plan)\s*(?:#|No\.?|Number)\s*[:#]?\s*[A-Z0-9]{6,15}\b",
        description="Group/plan number",
        confidence_weight=0.88,
    ),
    # 10. ICD-10 Diagnosis Codes
    PHIPattern(
        phi_type=PHIType.ICD10,
        pattern=r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b",
        description="ICD-10 code (e.g., J06.9, E11.9)",
        confidence_weight=0.75,
        requires_context=True,
    ),
    PHIPattern(
        phi_type=PHIType.ICD10,
        pattern=r"\b(?:ICD|Diagnosis)\s*[:#]?\s*([A-Z]\d{2}(?:\.\d{1,4})?)\b",
        description="ICD-10 with label",
        confidence_weight=0.92,
    ),
    # 11. CPT Procedure Codes
    PHIPattern(
        phi_type=PHIType.CPT,
        pattern=r"\b(?:CPT|Procedure)\s*[:#]?\s*(\d{5})\b",
        description="CPT code with label",
        confidence_weight=0.92,
    ),
    PHIPattern(
        phi_type=PHIType.CPT,
        pattern=r"\b\d{5}\b",
        description="5-digit number (possible CPT)",
        confidence_weight=0.60,
        requires_context=True,
    ),
    # 12. Account Numbers
    PHIPattern(
        phi_type=PHIType.ACCOUNT_NUMBER,
        pattern=r"\b(?:Account|Acct)\s*(?:#|No\.?|Number)\s*[:#]?\s*[A-Z0-9]{6,20}\b",
        description="Account number with label",
        confidence_weight=0.90,
    ),
    # 13. License/Certificate Numbers
    PHIPattern(
        phi_type=PHIType.LICENSE_NUMBER,
        pattern=r"\b(?:License|Cert|Certificate)\s*(?:#|No\.?|Number)\s*[:#]?\s*[A-Z0-9]{6,20}\b",
        description="License/certificate number",
        confidence_weight=0.88,
    ),
    # 14. IP Addresses
    PHIPattern(
        phi_type=PHIType.IP_ADDRESS,
        pattern=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        description="IPv4 address",
        confidence_weight=0.85,
    ),
    PHIPattern(
        phi_type=PHIType.IP_ADDRESS,
        pattern=r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
        description="IPv6 address",
        confidence_weight=0.90,
    ),
    # 15. URLs
    PHIPattern(
        phi_type=PHIType.URL,
        pattern=r"\b(?:https?://|www\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s]*)?\b",
        description="Web URL",
        confidence_weight=0.75,
    ),
    # 16. Device Identifiers
    PHIPattern(
        phi_type=PHIType.DEVICE_ID,
        pattern=r"\b(?:Serial|Device|Equipment)\s*(?:#|No\.?|ID)\s*[:#]?\s*[A-Z0-9]{8,20}\b",
        description="Device/equipment serial number",
        confidence_weight=0.85,
    ),
    # 17. Vehicle Identification Numbers
    PHIPattern(
        phi_type=PHIType.VIN,
        pattern=r"\b[A-HJ-NPR-Z0-9]{17}\b",
        description="Vehicle Identification Number",
        confidence_weight=0.88,
        requires_context=True,
    ),
    # 18. Patient Names (pattern-based, less reliable)
    PHIPattern(
        phi_type=PHIType.NAME,
        pattern=r"\b(?:Patient|Name)\s*[:#]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b",
        description="Patient name with label",
        confidence_weight=0.85,
    ),
]


def get_enabled_patterns() -> list[PHIPattern]:
    """
    Get list of enabled PHI patterns.

    Returns:
        List of patterns where enabled=True
    """
    return [p for p in HIPAA_PATTERNS if p.enabled]


def get_patterns_by_type(phi_type: PHIType) -> list[PHIPattern]:
    """
    Get all patterns for a specific PHI type.

    Args:
        phi_type: Type of PHI to get patterns for

    Returns:
        List of patterns matching the type
    """
    return [p for p in HIPAA_PATTERNS if p.phi_type == phi_type]


def get_high_confidence_patterns() -> list[PHIPattern]:
    """
    Get patterns with high confidence scores (>= 0.85).

    Returns:
        List of high-confidence patterns
    """
    return [p for p in HIPAA_PATTERNS if p.confidence_weight >= 0.85]
