"""
soc2_types.py - SOC 2 report type definitions

Defines ControlStatus enum and ControlAssessment dataclass used by
soc2_report.py and soc2_export.py.

Extracted from soc2_report.py to keep modules under 400 lines.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pdfsigner.core.compliance.evidence_types import EvidenceCategory


class ControlStatus(str, Enum):
    """Status of a SOC 2 control."""

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ControlAssessment:
    """
    Assessment of a single SOC 2 control.

    Attributes:
        control_id: Control identifier (e.g., "CC6.1")
        control_name: Human-readable control name
        category: SOC 2 category
        status: Implementation status
        description: What the control requires
        implementation: How PDFSigner implements this control
        evidence_ids: List of evidence IDs supporting this control
        gaps: List of identified gaps (if status is PARTIAL)
        notes: Additional assessment notes
    """

    control_id: str
    control_name: str
    category: EvidenceCategory
    status: ControlStatus
    description: str
    implementation: str
    evidence_ids: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "category": self.category.value,
            "status": self.status.value,
            "description": self.description,
            "implementation": self.implementation,
            "evidence_ids": self.evidence_ids,
            "gaps": self.gaps,
            "notes": self.notes,
        }


__all__ = [
    "ControlStatus",
    "ControlAssessment",
]
