"""
redaction_types.py - Data types for PDF redaction operations.

Author: Homero Thompson del Lago del Terror
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RedactionResult:
    """
    Result of a redaction operation.

    Attributes:
        success: Whether redaction completed successfully
        output_path: Path to redacted PDF file
        redaction_count: Number of regions redacted
        pages_affected: List of page numbers with redactions
        errors: List of error messages encountered
        input_path: Original PDF path
        redacted_at: Timestamp of redaction
    """

    success: bool
    output_path: str | None
    redaction_count: int
    pages_affected: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    input_path: str | None = None
    redacted_at: datetime | None = None

    def __str__(self) -> str:
        if self.success:
            return (
                f"✓ Redacted: {self.input_path} → {self.output_path} "
                f"({self.redaction_count} regions on {len(self.pages_affected)} pages)"
            )
        return f"✗ Redaction failed: {self.input_path} - {', '.join(self.errors)}"
