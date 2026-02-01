"""
Consent management schemas.

Request/response models for GDPR Article 7 consent management endpoints.
All schemas use Pydantic BaseModel for validation and serialization.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class ConsentRequest(BaseModel):
    """
    Request to grant consent.

    Attributes:
        consent_type: Type of consent to grant (processing, analytics, marketing, etc.)
        policy_version: Version of privacy policy being accepted
    """

    consent_type: str = Field(
        ...,
        description="Type of consent",
        pattern="^(processing|analytics|marketing|third_party|research)$",
    )
    policy_version: str | None = Field(
        None, max_length=64, description="Version of privacy policy accepted"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "consent_type": "analytics",
                "policy_version": "1.0.0",
            }
        }
    }


class ConsentResponse(BaseModel):
    """
    Consent record response.

    Attributes:
        id: Unique consent record ID
        user_id: User ID who gave/withdrew consent
        consent_type: Type of consent
        granted: Whether consent is currently granted
        granted_at: When consent was granted
        withdrawn_at: When consent was withdrawn (None if active)
        ip_address: IP address when consent was recorded
        policy_version: Version of privacy policy accepted
    """

    id: str = Field(..., max_length=64, description="Consent record ID")
    user_id: str = Field(..., max_length=64, description="User ID")
    consent_type: str = Field(..., max_length=64, description="Consent type")
    granted: bool = Field(..., description="Whether consent is granted")
    granted_at: datetime = Field(..., description="Timestamp when granted")
    withdrawn_at: datetime | None = Field(None, description="Timestamp when withdrawn")
    ip_address: str | None = Field(None, max_length=64, description="IP address")
    policy_version: str | None = Field(None, max_length=64, description="Policy version")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "user123",
                "consent_type": "analytics",
                "granted": True,
                "granted_at": "2024-01-15T10:30:00Z",
                "withdrawn_at": None,
                "ip_address": "192.168.1.100",
                "policy_version": "1.0.0",
            }
        }
    }


class ConsentAuditResponse(BaseModel):
    """
    Consent audit trail response.

    Attributes:
        consents: List of all consent records (grants and withdrawals)
        total_records: Total number of consent records
    """

    consents: list[ConsentResponse] = Field(..., description="Consent records")
    total_records: int = Field(..., description="Total number of records")

    model_config = {
        "json_schema_extra": {
            "example": {
                "consents": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "user_id": "user123",
                        "consent_type": "analytics",
                        "granted": True,
                        "granted_at": "2024-01-15T10:30:00Z",
                        "withdrawn_at": None,
                        "ip_address": "192.168.1.100",
                        "policy_version": "1.0.0",
                    },
                    {
                        "id": "660e8400-e29b-41d4-a716-446655440001",
                        "user_id": "user123",
                        "consent_type": "marketing",
                        "granted": False,
                        "granted_at": "2024-01-14T09:00:00Z",
                        "withdrawn_at": "2024-01-14T09:00:00Z",
                        "ip_address": "192.168.1.100",
                        "policy_version": None,
                    },
                ],
                "total_records": 2,
            }
        }
    }


class ConsentSummaryResponse(BaseModel):
    """
    Summary of user's consent status.

    Attributes:
        user_id: User ID
        consents: Dictionary mapping consent types to their active status
        last_updated: Timestamp of most recent consent action
    """

    user_id: str = Field(..., max_length=64, description="User ID")
    consents: dict[str, bool] = Field(..., description="Consent type status map")
    last_updated: datetime | None = Field(None, description="Last consent update")

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "user123",
                "consents": {
                    "processing": True,
                    "analytics": True,
                    "marketing": False,
                    "third_party": False,
                    "research": True,
                },
                "last_updated": "2024-01-15T10:30:00Z",
            }
        }
    }


__all__ = [
    "ConsentRequest",
    "ConsentResponse",
    "ConsentAuditResponse",
    "ConsentSummaryResponse",
]
