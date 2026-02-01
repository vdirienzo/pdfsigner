"""
MFA API schemas.

Request and response models for MFA endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class MFAEnrollRequest(BaseModel):
    """Request to start MFA enrollment."""

    pass  # No body needed, user from auth token


class MFAEnrollResponse(BaseModel):
    """Response with MFA enrollment data."""

    qr_code_base64: str = Field(..., description="Base64-encoded QR code PNG image")
    provisioning_uri: str = Field(..., description="otpauth:// URI for manual entry")
    secret: str = Field(..., description="Base32-encoded secret for manual entry")
    backup_codes: list[str] = Field(..., description="One-time use backup codes")

    model_config = {
        "json_schema_extra": {
            "example": {
                "qr_code_base64": "iVBORw0KGgoAAAANSUhEUgAA...",
                "provisioning_uri": "otpauth://totp/PDFSigner:user@example.com?secret=JBSWY3DP...",
                "secret": "JBSWY3DPEHPK3PXP",
                "backup_codes": [
                    "1234-5678",
                    "9012-3456",
                    "7890-1234",
                    "5678-9012",
                    "3456-7890",
                ],
            }
        }
    }


class MFAVerifyRequest(BaseModel):
    """Request to verify TOTP code."""

    code: str = Field(..., min_length=6, max_length=8, description="TOTP code from authenticator")

    model_config = {"json_schema_extra": {"example": {"code": "123456"}}}


class MFAVerifyResponse(BaseModel):
    """Response from MFA verification."""

    success: bool = Field(..., description="Whether verification succeeded")
    message: str = Field(..., description="Status message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "message": "MFA activated successfully",
            }
        }
    }


class MFABackupCodeRequest(BaseModel):
    """Request to verify backup code."""

    code: str = Field(..., description="Backup code (XXXX-XXXX format)")

    model_config = {"json_schema_extra": {"example": {"code": "1234-5678"}}}


class MFABackupCodeResponse(BaseModel):
    """Response from backup code verification."""

    success: bool = Field(..., description="Whether verification succeeded")
    message: str = Field(..., description="Status message")
    remaining_codes: int | None = Field(None, description="Number of remaining backup codes")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "message": "Backup code verified",
                "remaining_codes": 9,
            }
        }
    }


class MFAStatusResponse(BaseModel):
    """MFA status for current user."""

    enabled: bool = Field(..., description="Whether MFA is enabled")
    enrolled_at: datetime | None = Field(None, description="When MFA was enrolled")
    last_used_at: datetime | None = Field(None, description="When MFA was last used")
    backup_codes_remaining: int = Field(..., description="Number of unused backup codes")

    model_config = {
        "json_schema_extra": {
            "example": {
                "enabled": True,
                "enrolled_at": "2024-01-15T10:30:00Z",
                "last_used_at": "2024-01-20T14:15:00Z",
                "backup_codes_remaining": 8,
            }
        }
    }


class MFADisableRequest(BaseModel):
    """Request to disable MFA."""

    password: str | None = Field(None, description="User password for confirmation")

    model_config = {"json_schema_extra": {"example": {"password": "user_password"}}}


class MFADisableResponse(BaseModel):
    """Response from MFA disable."""

    success: bool = Field(..., description="Whether MFA was disabled")
    message: str = Field(..., description="Status message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "success": True,
                "message": "MFA disabled successfully",
            }
        }
    }


class MFARegenerateBackupCodesResponse(BaseModel):
    """Response with regenerated backup codes."""

    backup_codes: list[str] = Field(..., description="New backup codes")
    message: str = Field(..., description="Status message")

    model_config = {
        "json_schema_extra": {
            "example": {
                "backup_codes": [
                    "1111-2222",
                    "3333-4444",
                    "5555-6666",
                    "7777-8888",
                    "9999-0000",
                ],
                "message": "Backup codes regenerated successfully. Previous codes are now invalid.",
            }
        }
    }


# Public exports
__all__ = [
    "MFAEnrollRequest",
    "MFAEnrollResponse",
    "MFAVerifyRequest",
    "MFAVerifyResponse",
    "MFABackupCodeRequest",
    "MFABackupCodeResponse",
    "MFAStatusResponse",
    "MFADisableRequest",
    "MFADisableResponse",
    "MFARegenerateBackupCodesResponse",
]
