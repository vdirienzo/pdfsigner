"""
GDPR API schemas.

Request/response models for GDPR endpoints:
- Data export (Article 20)
- User anonymization (Article 17)
- Deletion scheduling and cancellation
- Retention status queries
"""

from datetime import datetime

from pydantic import BaseModel, Field


class AnonymizeUserRequest(BaseModel):
    """Request to anonymize a user (admin only)."""

    user_id: str = Field(..., max_length=64, description="User ID to anonymize")

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
            }
        }
    }


class AnonymizeUserResponse(BaseModel):
    """Response from user anonymization."""

    success: bool = Field(..., description="Whether anonymization succeeded")
    user_id: str = Field(..., max_length=64, description="User ID that was anonymized")
    fields_anonymized: list[str] = Field(..., description="Fields that were anonymized")
    audit_records_anonymized: int = Field(..., description="Number of audit records anonymized")
    error_message: str | None = Field(None, max_length=4096, description="Error message if failed")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "fields_anonymized": [
                    "username",
                    "display_name",
                    "email",
                    "status",
                    "metadata",
                ],
                "audit_records_anonymized": 42,
                "error_message": None,
            }
        }
    }


class ScheduleDeletionRequest(BaseModel):
    """Request to schedule user deletion."""

    grace_days: int = Field(30, ge=1, le=365, description="Days until deletion (grace period)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "grace_days": 30,
            }
        }
    }


class ScheduleDeletionResponse(BaseModel):
    """Response from deletion scheduling."""

    success: bool = Field(..., description="Whether scheduling succeeded")
    user_id: str = Field(..., max_length=64, description="User ID scheduled for deletion")
    deletion_date: datetime = Field(..., description="Date when deletion will occur")
    grace_days: int = Field(..., description="Grace period before deletion")
    message: str = Field(..., max_length=4096, description="Human-readable message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "deletion_date": "2024-02-28T00:00:00Z",
                "grace_days": 30,
                "message": "User deletion scheduled for 2024-02-28. "
                "You can cancel before this date.",
            }
        }
    }


class CancelDeletionResponse(BaseModel):
    """Response from deletion cancellation."""

    success: bool = Field(..., description="Whether cancellation succeeded")
    user_id: str = Field(..., max_length=64, description="User ID")
    message: str = Field(..., max_length=4096, description="Human-readable message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "message": "Scheduled deletion cancelled successfully",
            }
        }
    }


class RetentionStatusResponse(BaseModel):
    """User data retention status."""

    user_id: str = Field(..., max_length=64, description="User ID")
    is_anonymized: bool = Field(..., description="Whether user is anonymized")
    deletion_scheduled: bool = Field(..., description="Whether deletion is scheduled")
    deletion_scheduled_at: datetime | None = Field(None, description="When deletion was scheduled")
    deletion_date: datetime | None = Field(None, description="When deletion will occur")
    days_until_deletion: int | None = Field(None, description="Days remaining until deletion")

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "is_anonymized": False,
                "deletion_scheduled": True,
                "deletion_scheduled_at": "2024-01-29T10:00:00Z",
                "deletion_date": "2024-02-28T00:00:00Z",
                "days_until_deletion": 30,
            }
        }
    }


class DataExportResponse(BaseModel):
    """Response containing exported user data."""

    user_id: str = Field(..., max_length=64, description="User ID")
    format: str = Field(..., max_length=64, description="Export format (json)")
    generated_at: datetime = Field(..., description="Export generation timestamp")
    data: dict = Field(..., description="Exported data (user_info, certificates, etc.)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "format": "json",
                "generated_at": "2024-01-29T10:00:00Z",
                "data": {
                    "user_info": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "username": "john.doe",
                        "email": "john.doe@example.com",
                    },
                    "certificates": [],
                    "audit_events": [],
                    "sessions": [],
                },
            }
        }
    }


class PurgeExpiredDataResponse(BaseModel):
    """Response from purge operation (admin only)."""

    success: bool = Field(..., description="Whether purge succeeded")
    users_deleted: int = Field(..., description="Number of users deleted")
    audit_records_purged: int = Field(..., description="Number of audit records purged")
    documents_deleted: int = Field(..., description="Number of documents deleted")
    error_message: str | None = Field(None, max_length=4096, description="Error message if failed")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "users_deleted": 3,
                "audit_records_purged": 127,
                "documents_deleted": 0,
                "error_message": None,
            }
        }
    }
