"""
policy_types.py - Data types for encryption policy engine

Defines the core data structures used by the policy engine:
- PolicyTrigger: What triggers an encryption policy
- PolicyAction: What action to take when triggered
- EncryptionPolicy: A complete encryption policy definition
- PolicyResult: Result of policy evaluation

Author: PDFSigner Team
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class PolicyTrigger(str, Enum):
    """What triggers the encryption policy."""

    ALWAYS = "always"  # Encrypt all documents
    PHI_DETECTED = "phi_detected"  # Encrypt if PHI found
    DEPARTMENT = "department"  # Encrypt for specific departments
    FILE_TYPE = "file_type"  # Based on file characteristics
    MANUAL = "manual"  # User explicitly requested


class PolicyAction(str, Enum):
    """What action to take when policy triggers."""

    ENCRYPT = "encrypt"  # Enforce encryption
    WARN = "warn"  # Just warn, don't enforce
    BLOCK = "block"  # Block operation until encrypted


@dataclass
class EncryptionPolicy:
    """
    Defines an encryption policy with trigger conditions and actions.

    Policies are evaluated in priority order (highest first).
    The first triggered policy determines the action to take.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    trigger: PolicyTrigger = PolicyTrigger.MANUAL
    action: PolicyAction = PolicyAction.WARN

    # Trigger-specific config
    departments: list[str] = field(default_factory=list)  # For DEPARTMENT trigger
    phi_types: list[str] = field(default_factory=list)  # For PHI_DETECTED trigger
    min_confidence: str = "medium"  # low, medium, high

    # Encryption config
    encryption_method: str = "aes256"  # aes128, aes256

    enabled: bool = True
    priority: int = 0  # Higher = evaluated first
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert policy to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "trigger": self.trigger.value,
            "action": self.action.value,
            "departments": self.departments,
            "phi_types": self.phi_types,
            "min_confidence": self.min_confidence,
            "encryption_method": self.encryption_method,
            "enabled": self.enabled,
            "priority": self.priority,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EncryptionPolicy":
        """Create policy from dictionary."""
        # Convert string enums back to enum types
        if isinstance(data.get("trigger"), str):
            data["trigger"] = PolicyTrigger(data["trigger"])
        if isinstance(data.get("action"), str):
            data["action"] = PolicyAction(data["action"])

        # Convert ISO timestamp back to datetime
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])

        return cls(**data)


@dataclass
class PolicyResult:
    """Result of policy evaluation against a document."""

    triggered: bool
    policy: EncryptionPolicy | None
    action: PolicyAction
    reason: str
    phi_scan_result: Any | None = None  # PHIScanResult if PHI scanner was used

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "triggered": self.triggered,
            "policy": self.policy.to_dict() if self.policy else None,
            "action": self.action.value,
            "reason": self.reason,
            "phi_detected": self.phi_scan_result is not None
            and getattr(self.phi_scan_result, "has_phi", False),
        }
