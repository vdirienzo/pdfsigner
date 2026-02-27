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

Control data is split by standard family:
- controls_hipaa.py: HIPAA controls
- controls_nist.py: NIST 800-53 + FedRAMP controls
- controls_international.py: eIDAS, GDPR, Ley 25.506 controls
- controls_soc2.py: SOC 2 Type II controls
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
# Import control definitions from family modules
# ============================================================================

from pdfsigner.core.compliance.controls_hipaa import HIPAA_CONTROLS  # noqa: E402
from pdfsigner.core.compliance.controls_international import (  # noqa: E402
    EIDAS_CONTROLS,
    GDPR_CONTROLS,
    LEY_25506_CONTROLS,
)
from pdfsigner.core.compliance.controls_nist import (  # noqa: E402
    FEDRAMP_CONTROLS,
    NIST_800_53_CONTROLS,
)
from pdfsigner.core.compliance.controls_soc2 import SOC2_CONTROLS  # noqa: E402

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
