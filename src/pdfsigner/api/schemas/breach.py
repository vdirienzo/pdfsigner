"""
Breach notification API schemas.

Pydantic models for breach incident endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class BreachIncidentCreate(BaseModel):
    """Request model for manual breach reporting."""

    breach_type: str = Field(
        ..., max_length=64, description="Type of breach (mass_data_export, etc.)"
    )
    severity: str = Field(
        ..., max_length=64, description="Severity level (low, medium, high, critical)"
    )
    description: str = Field(
        ..., max_length=4096, description="Detailed description of the incident"
    )
    affected_users: int = Field(default=0, description="Number of affected users")
    affected_records: int = Field(default=0, description="Number of affected records")
    source_ip: str | None = Field(
        default=None, max_length=64, description="Source IP address if known"
    )
    user_id: str | None = Field(
        default=None, max_length=64, description="User ID associated with breach"
    )
    metadata: dict = Field(default_factory=dict, description="Additional context")


class BreachIncidentResponse(BaseModel):
    """Response model for breach incident."""

    id: str = Field(..., max_length=64)
    breach_type: str = Field(..., max_length=64)
    severity: str = Field(..., max_length=64)
    status: str = Field(..., max_length=64)
    detected_at: datetime
    resolved_at: datetime | None
    notified_at: datetime | None
    description: str = Field(..., max_length=4096)
    affected_users: int
    affected_records: int
    source_ip: str | None = Field(None, max_length=64)
    user_id: str | None = Field(None, max_length=64)
    metadata: dict
    status_history: list[dict]


class BreachStatusUpdate(BaseModel):
    """Request model for updating breach status."""

    status: str = Field(
        ..., max_length=64, description="New status (investigating, contained, resolved, notified)"
    )
    note: str = Field(default="", max_length=4096, description="Optional note about status change")


class BreachNotificationRequest(BaseModel):
    """Request model for sending notifications."""

    channels: list[str] = Field(..., description="Notification channels (email, webhook, sms)")
    recipients: list[str] = Field(..., description="Recipient addresses/endpoints")
    message: str | None = Field(
        default=None,
        max_length=4096,
        description="Optional custom message (default: auto-generated)",
    )


class BreachNotificationResponse(BaseModel):
    """Response model for notification delivery."""

    incident_id: str = Field(..., max_length=64)
    results: dict = Field(..., description="Delivery results per channel")
    sent_at: datetime


class BreachListResponse(BaseModel):
    """Response model for list of breaches."""

    incidents: list[BreachIncidentResponse]
    total: int
    limit: int
    offset: int


class BreachSummaryResponse(BaseModel):
    """Response model for breach summary report."""

    report_type: str = Field(..., max_length=64)
    start_date: datetime
    end_date: datetime
    generated_at: datetime
    total_incidents: int
    total_affected_users: int
    total_affected_records: int
    by_severity: dict
    by_status: dict
    by_type: dict
    avg_resolution_hours: float | None
    resolved_count: int
    unresolved_count: int
    top_users: list[dict]
    top_source_ips: list[dict]
    recent_incidents: list[dict]
