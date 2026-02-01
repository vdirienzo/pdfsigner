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
    emergency: Emergency access schemas (EmergencyRequestCreate, EmergencyRequestResponse)
    compliance: Compliance monitoring schemas (ComplianceCheckResponse, ComplianceReportResponse)
    retention: Data retention schemas (RetentionPolicyResponse, RetentionResultResponse)
"""

from pdfsigner.api.schemas.certificates import CertificateChain, CertificateInfo
from pdfsigner.api.schemas.common import ErrorResponse, JobStatus, PAdESLevel, StatusEnum
from pdfsigner.api.schemas.compliance import ComplianceCheckResponse, ComplianceReportResponse
from pdfsigner.api.schemas.emergency import (
    EmergencyDenyRequest,
    EmergencyRequestCreate,
    EmergencyRequestResponse,
    EmergencyStatusResponse,
)
from pdfsigner.api.schemas.phi import PHIMatchResponse, PHIScanResponse
from pdfsigner.api.schemas.redact import (
    PreviewRequest,
    RedactByPatternRequest,
    RedactionRegionSchema,
    RedactionResponse,
    RedactRegionsRequest,
)
from pdfsigner.api.schemas.retention import (
    RetentionHistoryResponse,
    RetentionPolicyCreate,
    RetentionPolicyResponse,
    RetentionPolicyUpdate,
    RetentionResultResponse,
    RetentionRunRequest,
)
from pdfsigner.api.schemas.seal import (
    OrganizationInfoSchema,
    SealJobStatus,
    SealRequest,
    SealResponse,
    SealValidationResponse,
)
from pdfsigner.api.schemas.sessions import SessionDeleteResponse, SessionResponse
from pdfsigner.api.schemas.sign import SignJobStatus, SignRequest, SignResponse
from pdfsigner.api.schemas.users import UserListResponse, UserResponse, UserUpdate
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
    # Seal
    "OrganizationInfoSchema",
    "SealRequest",
    "SealResponse",
    "SealJobStatus",
    "SealValidationResponse",
    # Validate
    "SignatureInfo",
    "LTVInfo",
    "ValidateResponse",
    "BatchValidateResponse",
    # Certificates
    "CertificateInfo",
    "CertificateChain",
    # Users
    "UserResponse",
    "UserUpdate",
    "UserListResponse",
    # Sessions
    "SessionResponse",
    "SessionDeleteResponse",
    # Emergency
    "EmergencyRequestCreate",
    "EmergencyRequestResponse",
    "EmergencyDenyRequest",
    "EmergencyStatusResponse",
    # PHI
    "PHIMatchResponse",
    "PHIScanResponse",
    # Redaction
    "RedactionRegionSchema",
    "RedactRegionsRequest",
    "RedactByPatternRequest",
    "RedactionResponse",
    "PreviewRequest",
    # Compliance
    "ComplianceCheckResponse",
    "ComplianceReportResponse",
    # Retention
    "RetentionPolicyResponse",
    "RetentionPolicyCreate",
    "RetentionPolicyUpdate",
    "RetentionResultResponse",
    "RetentionRunRequest",
    "RetentionHistoryResponse",
]
