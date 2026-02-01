"""
Retention management schemas.

This module contains data models for retention policy operations:
- Retention policy CRUD
- Cleanup execution
- History tracking

All schemas are based on Pydantic BaseModel for validation and serialization.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from pdfsigner.core.retention import RetentionAction, RetentionPolicy, RetentionTarget


class RetentionPolicyResponse(BaseModel):
    """Retention policy response."""

    id: str = Field(..., description="Policy ID")
    name: str = Field(..., description="Policy name")
    description: str = Field(..., description="Policy description")
    target: RetentionTarget = Field(..., description="Data target")
    retention_days: int = Field(..., description="Retention period in days", ge=1)
    action: RetentionAction = Field(..., description="Action to take when expired")
    enabled: bool = Field(..., description="Whether policy is enabled")
    hipaa_reference: str = Field(..., description="HIPAA regulation reference")
    created_at: datetime = Field(..., description="Creation timestamp")

    @classmethod
    def from_policy(cls, policy: RetentionPolicy) -> "RetentionPolicyResponse":
        """
        Create response from RetentionPolicy.

        Args:
            policy: RetentionPolicy object

        Returns:
            RetentionPolicyResponse
        """
        return cls(
            id=policy.id,
            name=policy.name,
            description=policy.description,
            target=policy.target,
            retention_days=policy.retention_days,
            action=policy.action,
            enabled=policy.enabled,
            hipaa_reference=policy.hipaa_reference,
            created_at=policy.created_at,
        )

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "HIPAA Audit Log Retention",
                "description": "Retain audit logs for 6 years per HIPAA requirements",
                "target": "audit_logs",
                "retention_days": 2190,
                "action": "archive",
                "enabled": True,
                "hipaa_reference": "§164.530(j)",
                "created_at": "2026-02-01T10:00:00",
            }
        }
    }


class RetentionPolicyCreate(BaseModel):
    """Request to create retention policy."""

    name: str = Field(..., description="Policy name", min_length=1, max_length=255)
    description: str = Field(default="", description="Policy description", max_length=1000)
    target: RetentionTarget = Field(..., description="Data target")
    retention_days: int = Field(..., description="Retention period in days", ge=1, le=3650)
    action: RetentionAction = Field(..., description="Action to take when expired")
    enabled: bool = Field(default=True, description="Whether policy is enabled")
    hipaa_reference: str = Field(default="", description="HIPAA regulation reference")

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "Custom Log Retention",
                "description": "Retain custom logs for 90 days",
                "target": "reports",
                "retention_days": 90,
                "action": "delete",
                "enabled": True,
                "hipaa_reference": "",
            }
        }
    }


class RetentionPolicyUpdate(BaseModel):
    """Request to update retention policy."""

    name: str | None = Field(None, description="Policy name", min_length=1, max_length=255)
    description: str | None = Field(None, description="Policy description", max_length=1000)
    retention_days: int | None = Field(None, description="Retention period in days", ge=1, le=3650)
    action: RetentionAction | None = Field(None, description="Action to take when expired")
    enabled: bool | None = Field(None, description="Whether policy is enabled")


class RetentionResultResponse(BaseModel):
    """Retention cleanup result response."""

    policy_id: str = Field(..., description="Policy ID")
    policy_name: str = Field(..., description="Policy name")
    target: RetentionTarget = Field(..., description="Data target")
    action: RetentionAction = Field(..., description="Action taken")
    items_processed: int = Field(..., description="Number of items processed", ge=0)
    items_deleted: int = Field(..., description="Number of items deleted", ge=0)
    items_archived: int = Field(..., description="Number of items archived", ge=0)
    items_failed: int = Field(..., description="Number of items failed", ge=0)
    started_at: datetime = Field(..., description="Start timestamp")
    completed_at: datetime = Field(..., description="Completion timestamp")
    duration_seconds: float = Field(..., description="Operation duration in seconds", ge=0)
    errors: list[str] = Field(..., description="Error messages")

    model_config = {
        "json_schema_extra": {
            "example": {
                "policy_id": "550e8400-e29b-41d4-a716-446655440000",
                "policy_name": "HIPAA Audit Log Retention",
                "target": "audit_logs",
                "action": "archive",
                "items_processed": 150,
                "items_deleted": 0,
                "items_archived": 150,
                "items_failed": 0,
                "started_at": "2026-02-01T10:00:00",
                "completed_at": "2026-02-01T10:00:05",
                "duration_seconds": 5.0,
                "errors": [],
            }
        }
    }


class RetentionRunRequest(BaseModel):
    """Request to run retention cleanup."""

    policy_id: str | None = Field(None, description="Specific policy ID or None for all policies")

    model_config = {
        "json_schema_extra": {
            "example": {
                "policy_id": "550e8400-e29b-41d4-a716-446655440000",
            }
        }
    }


class RetentionHistoryResponse(BaseModel):
    """Retention history record response."""

    id: int = Field(..., description="History record ID")
    policy_id: str = Field(..., description="Policy ID")
    items_processed: int = Field(..., description="Number of items processed", ge=0)
    items_deleted: int = Field(..., description="Number of items deleted", ge=0)
    items_archived: int = Field(..., description="Number of items archived", ge=0)
    items_failed: int = Field(..., description="Number of items failed", ge=0)
    started_at: str = Field(..., description="Start timestamp (ISO format)")
    completed_at: str = Field(..., description="Completion timestamp (ISO format)")
    errors: str | None = Field(None, description="Comma-separated error messages")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "policy_id": "550e8400-e29b-41d4-a716-446655440000",
                "items_processed": 150,
                "items_deleted": 0,
                "items_archived": 150,
                "items_failed": 0,
                "started_at": "2026-02-01T10:00:00",
                "completed_at": "2026-02-01T10:00:05",
                "errors": None,
            }
        }
    }
