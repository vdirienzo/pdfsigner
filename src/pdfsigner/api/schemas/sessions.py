"""Session management schemas.

This module contains data models for session management operations:
- Session information and metadata
- Session listing and filtering

All schemas are based on Pydantic BaseModel for validation and serialization.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from pdfsigner.core.session.session_manager import Session


class SessionResponse(BaseModel):
    """Session information response.

    Attributes:
        id: Unique session identifier (UUID)
        user_id: User ID associated with this session
        created_at: Timestamp when session was created
        last_activity: Timestamp of last session activity
        expires_at: Timestamp when session will expire
        is_active: Whether session is still active (not expired)
        ip_address: Client IP address (if available)
        user_agent: Client user agent string (if available)
    """

    id: str = Field(..., max_length=64, description="Session ID")
    user_id: str = Field(..., max_length=64, description="User ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_activity: datetime = Field(..., description="Last activity timestamp")
    expires_at: datetime = Field(..., description="Expiration timestamp")
    is_active: bool = Field(..., description="Whether session is active")
    ip_address: str | None = Field(None, max_length=64, description="Client IP address")
    user_agent: str | None = Field(None, max_length=1024, description="Client user agent")

    @classmethod
    def from_session(cls, session: Session) -> "SessionResponse":
        """
        Create SessionResponse from Session object.

        Args:
            session: Session object from SessionManager

        Returns:
            SessionResponse with all session details
        """
        return cls(
            id=session.id,
            user_id=session.user_id,
            created_at=session.created_at,
            last_activity=session.last_activity,
            expires_at=session.expires_at,
            is_active=session.is_active,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
        )

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "user123",
                "created_at": "2026-02-01T10:00:00",
                "last_activity": "2026-02-01T10:30:00",
                "expires_at": "2026-02-01T11:00:00",
                "is_active": True,
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0",
            }
        }
    }


class SessionListResponse(BaseModel):
    """Response for listing multiple sessions.

    Attributes:
        sessions: List of active sessions
        total: Total number of sessions
    """

    sessions: list[SessionResponse] = Field(..., description="List of sessions")
    total: int = Field(..., description="Total session count")


class SessionDeleteResponse(BaseModel):
    """Response for session deletion.

    Attributes:
        message: Success message
        session_id: ID of deleted session (optional for single delete)
        sessions_terminated: Number of sessions terminated (for bulk delete)
    """

    message: str = Field(..., max_length=4096, description="Success message")
    session_id: str | None = Field(default=None, max_length=64, description="Deleted session ID")
    sessions_terminated: int | None = Field(
        default=None, description="Number of sessions terminated"
    )
