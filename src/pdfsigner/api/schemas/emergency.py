"""Emergency access (break-glass) schemas for API.

This module contains Pydantic models for emergency access operations:
- Request creation
- Status checking
- Approval/denial workflows

HIPAA Compliance:
    - §164.312(a)(2)(ii) - Emergency access procedure
"""

from datetime import datetime

from pydantic import BaseModel, Field


class EmergencyRequestCreate(BaseModel):
    """Request body for creating emergency access request.

    Attributes:
        reason: Justification for emergency access (required for audit trail)
    """

    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Justification for emergency access",
        examples=["Patient critical care access required for immediate treatment"],
    )


class EmergencyRequestResponse(BaseModel):
    """Response containing emergency access request details.

    Attributes:
        id: Unique request identifier
        requester_id: User ID who requested access
        reason: Justification for emergency access
        status: Current status (pending, approved, denied, expired, revoked)
        requested_at: Timestamp when request was created
        approved_by: User ID who approved/denied the request
        approved_at: Timestamp when decision was made
        expires_at: Timestamp when access expires (if approved)
        revoked_by: User ID who revoked the access
        revoked_at: Timestamp when access was revoked
    """

    id: str = Field(..., description="Unique request identifier")
    requester_id: str = Field(..., description="User ID who requested access")
    reason: str = Field(..., description="Justification for emergency access")
    status: str = Field(..., description="Request status")
    requested_at: datetime = Field(..., description="Request creation timestamp")
    approved_by: str | None = Field(None, description="User ID who made the decision")
    approved_at: datetime | None = Field(None, description="Decision timestamp")
    expires_at: datetime | None = Field(None, description="Access expiration timestamp")
    revoked_by: str | None = Field(None, description="User ID who revoked access")
    revoked_at: datetime | None = Field(None, description="Revocation timestamp")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "a1b2c3d4-e5f6-4789-a012-b34c56d78e90",
                "requester_id": "user123",
                "reason": "Patient critical care access required",
                "status": "approved",
                "requested_at": "2026-02-01T10:30:00",
                "approved_by": "admin",
                "approved_at": "2026-02-01T10:32:00",
                "expires_at": "2026-02-01T22:32:00",
                "revoked_by": None,
                "revoked_at": None,
            }
        }
    }


class EmergencyDenyRequest(BaseModel):
    """Request body for denying emergency access.

    Attributes:
        reason: Optional reason for denial
    """

    reason: str | None = Field(
        None,
        max_length=500,
        description="Optional reason for denial",
        examples=["Insufficient justification provided"],
    )


class EmergencyStatusResponse(BaseModel):
    """Response indicating if user has active emergency access.

    Attributes:
        has_active_access: Whether user currently has active emergency access
        active_request_id: ID of active request if access is granted
        expires_at: Expiration timestamp if access is active
    """

    has_active_access: bool = Field(..., description="Has active emergency access")
    active_request_id: str | None = Field(None, description="Active request ID")
    expires_at: datetime | None = Field(None, description="Access expiration time")

    model_config = {
        "json_schema_extra": {
            "example": {
                "has_active_access": True,
                "active_request_id": "a1b2c3d4-e5f6-4789-a012-b34c56d78e90",
                "expires_at": "2026-02-01T22:32:00",
            }
        }
    }
