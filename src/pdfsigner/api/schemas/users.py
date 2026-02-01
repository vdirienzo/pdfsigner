"""User management schemas.

This module contains request/response models for user management endpoints:
- User information display
- User updates (display name, email, role)
- User listing with pagination

All schemas are based on Pydantic BaseModel for validation and serialization.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class UserResponse(BaseModel):
    """User information response.

    Attributes:
        id: Unique user ID (UUID)
        username: Unique username
        display_name: Human-readable display name
        email: User email address
        role: User role (viewer, signer, admin, auditor, emergency)
        status: User account status (active, inactive, locked, pending)
        created_at: When user was created
        last_login_at: Last successful login timestamp
    """

    id: str = Field(..., description="Unique user ID")
    username: str = Field(..., description="Unique username")
    display_name: str = Field(..., description="Display name")
    email: str = Field(..., description="Email address")
    role: str = Field(..., description="User role")
    status: str = Field(..., description="Account status")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_login_at: datetime | None = Field(None, description="Last login timestamp")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "john.doe",
                "display_name": "John Doe",
                "email": "john.doe@example.com",
                "role": "signer",
                "status": "active",
                "created_at": "2024-01-15T10:30:00Z",
                "last_login_at": "2024-01-20T14:22:00Z",
            }
        }
    }


class UserUpdate(BaseModel):
    """User update request.

    All fields are optional. Only provided fields will be updated.

    Attributes:
        display_name: New display name
        email: New email address
        role: New user role (viewer, signer, admin, auditor, emergency)
    """

    display_name: str | None = Field(None, min_length=1, description="Display name")
    email: str | None = Field(None, min_length=1, description="Email address")
    role: str | None = Field(
        None,
        description="User role",
        pattern="^(viewer|signer|admin|auditor|emergency)$",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "display_name": "John Doe",
                "email": "john.doe@example.com",
                "role": "signer",
            }
        }
    }


class UserListResponse(BaseModel):
    """User list response with pagination.

    Attributes:
        users: List of users matching query filters
        total: Total number of users matching filters (without pagination)
    """

    users: list[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total users matching filters")

    model_config = {
        "json_schema_extra": {
            "example": {
                "users": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "username": "john.doe",
                        "display_name": "John Doe",
                        "email": "john.doe@example.com",
                        "role": "signer",
                        "status": "active",
                        "created_at": "2024-01-15T10:30:00Z",
                        "last_login_at": "2024-01-20T14:22:00Z",
                    },
                    {
                        "id": "660e8400-e29b-41d4-a716-446655440001",
                        "username": "jane.admin",
                        "display_name": "Jane Admin",
                        "email": "jane.admin@example.com",
                        "role": "admin",
                        "status": "active",
                        "created_at": "2024-01-10T09:00:00Z",
                        "last_login_at": "2024-01-21T08:15:00Z",
                    },
                ],
                "total": 2,
            }
        }
    }
