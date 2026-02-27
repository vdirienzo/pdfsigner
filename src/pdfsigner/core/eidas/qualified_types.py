"""
qualified_types.py - Data types for Qualified Electronic Signature validation

Author: Homero Thompson del Lago del Terror

Contains SignatureValidation and QESValidationResult dataclasses used by
QualifiedSignatureValidator. Extracted from qualified_validator.py to keep
each module under 400 lines.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class SignatureValidation:
    """Validation result for a single signature."""

    field_name: str = ""
    signer_name: str = ""
    signing_time: datetime | None = None
    certificate_qualified: bool = False
    qscd_used: bool = False
    tsp_granted: bool = False
    not_revoked: bool = False
    signature_valid: bool = False
    timestamp_present: bool = False
    tsp_name: str | None = None
    tsp_country: str | None = None
    qualification_level: str = "Basic"  # "QES", "AdES-QC", "AdES", "Basic"
    issues: list[str] = field(default_factory=list)


@dataclass
class QESValidationResult:
    """Result of Qualified Electronic Signature validation."""

    overall_status: str  # "TOTAL-PASSED", "TOTAL-FAILED", "INDETERMINATE"
    qualification_level: str  # "QES", "AdES", "Basic"
    signature_validations: list[SignatureValidation] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    validation_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Legacy compatibility properties
    @property
    def is_qualified(self) -> bool:
        """Check if all signatures are QES qualified."""
        return self.qualification_level == "QES" and self.overall_status == "TOTAL-PASSED"

    @property
    def certificate_qualified(self) -> bool:
        """Check if at least one certificate is qualified."""
        return any(v.certificate_qualified for v in self.signature_validations)

    @property
    def device_qualified(self) -> bool:
        """Check if at least one signature used QSCD."""
        return any(v.qscd_used for v in self.signature_validations)

    @property
    def tsp_qualified(self) -> bool:
        """Check if at least one TSP is qualified."""
        return any(v.tsp_granted for v in self.signature_validations)

    @property
    def timestamp_qualified(self) -> bool:
        """Check if at least one signature has timestamp."""
        return any(v.timestamp_present for v in self.signature_validations)
