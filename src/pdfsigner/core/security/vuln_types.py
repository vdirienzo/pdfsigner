"""
vuln_types.py - Vulnerability data types

Defines core vulnerability types, severities, and statuses for
NIST RA-5 Vulnerability Management compliance.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import uuid4


class VulnSeverity(str, Enum):
    """Vulnerability severity levels (CVSS-based)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def _get_order(self):
        """Get numeric order for comparison."""
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value)

    def __lt__(self, other):
        """Compare severities for sorting."""
        if not isinstance(other, VulnSeverity):
            return NotImplemented
        return self._get_order() < other._get_order()

    def __le__(self, other):
        """Less than or equal comparison."""
        if not isinstance(other, VulnSeverity):
            return NotImplemented
        return self._get_order() <= other._get_order()

    def __gt__(self, other):
        """Greater than comparison."""
        if not isinstance(other, VulnSeverity):
            return NotImplemented
        return self._get_order() > other._get_order()

    def __ge__(self, other):
        """Greater than or equal comparison."""
        if not isinstance(other, VulnSeverity):
            return NotImplemented
        return self._get_order() >= other._get_order()


class VulnStatus(str, Enum):
    """Vulnerability lifecycle status."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"  # Risk accepted
    FALSE_POSITIVE = "false_positive"


class VulnSource(str, Enum):
    """Vulnerability discovery source."""

    SEMGREP = "semgrep"
    PIP_AUDIT = "pip_audit"
    MANUAL = "manual"
    PENTEST = "pentest"


@dataclass
class Vulnerability:
    """
    Vulnerability record for tracking security issues.

    Supports NIST RA-5 vulnerability management requirements:
    - Unique identification
    - Severity classification
    - Status tracking
    - Remediation guidance
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: VulnSeverity = VulnSeverity.INFO
    status: VulnStatus = VulnStatus.OPEN
    source: VulnSource = VulnSource.MANUAL
    file_path: str | None = None
    line_number: int | None = None
    cwe_id: str | None = None  # CWE-ID (e.g., "CWE-79")
    cvss_score: float | None = None  # CVSS v3 score (0.0-10.0)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None
    assignee: str | None = None
    remediation: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "source": self.source.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "discovered_at": self.discovered_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assignee": self.assignee,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Vulnerability":
        """Create from dictionary."""
        data = data.copy()
        # Parse enums
        data["severity"] = VulnSeverity(data["severity"])
        data["status"] = VulnStatus(data["status"])
        data["source"] = VulnSource(data["source"])
        # Parse datetimes
        data["discovered_at"] = datetime.fromisoformat(data["discovered_at"])
        if data.get("resolved_at"):
            data["resolved_at"] = datetime.fromisoformat(data["resolved_at"])
        return cls(**data)

    def is_open(self) -> bool:
        """Check if vulnerability is still open."""
        return self.status in {VulnStatus.OPEN, VulnStatus.IN_PROGRESS}

    def is_high_severity(self) -> bool:
        """Check if vulnerability is high or critical severity."""
        return self.severity in {VulnSeverity.HIGH, VulnSeverity.CRITICAL}

    def days_open(self) -> int:
        """Calculate days since discovery."""
        end_time = self.resolved_at or datetime.utcnow()
        return (end_time - self.discovered_at).days


__all__ = [
    "VulnSeverity",
    "VulnStatus",
    "VulnSource",
    "Vulnerability",
]
