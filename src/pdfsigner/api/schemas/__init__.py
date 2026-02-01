"""API request/response schemas using Pydantic.

This package contains data models for:
- Request validation
- Response serialization
- OpenAPI documentation

All schemas inherit from pydantic.BaseModel and provide:
- Automatic validation with type checking
- JSON serialization/deserialization
- OpenAPI schema generation for FastAPI

Modules:
    common: Shared enums and base models (StatusEnum, ErrorResponse, JobStatus)
    sign: Signing operation schemas (SignRequest, SignResponse, SignJobStatus)
    validate: Validation operation schemas (ValidateResponse, BatchValidateResponse)
    certificates: Certificate inspection schemas (CertificateInfo, CertificateChain)
"""

from pdfsigner.api.schemas.certificates import CertificateChain, CertificateInfo
from pdfsigner.api.schemas.common import ErrorResponse, JobStatus, PAdESLevel, StatusEnum
from pdfsigner.api.schemas.sign import SignJobStatus, SignRequest, SignResponse
from pdfsigner.api.schemas.validate import (
    BatchValidateResponse,
    LTVInfo,
    SignatureInfo,
    ValidateResponse,
)

__all__ = [
    # Common
    "StatusEnum",
    "PAdESLevel",
    "ErrorResponse",
    "JobStatus",
    # Sign
    "SignRequest",
    "SignResponse",
    "SignJobStatus",
    # Validate
    "SignatureInfo",
    "LTVInfo",
    "ValidateResponse",
    "BatchValidateResponse",
    # Certificates
    "CertificateInfo",
    "CertificateChain",
]
