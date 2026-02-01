"""Common schemas used across API.

This module contains shared data models for:
- Status enumerations (job status, PAdES levels)
- Error responses
- Job status tracking

All schemas are based on Pydantic BaseModel for validation and serialization.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class StatusEnum(str, Enum):
    """Job execution status enumeration.

    Attributes:
        PENDING: Job is queued and waiting to be processed
        PROCESSING: Job is currently being executed
        COMPLETED: Job finished successfully
        FAILED: Job execution failed with error
    """

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class PAdESLevel(str, Enum):
    """PAdES (PDF Advanced Electronic Signatures) conformance levels.

    Attributes:
        B_B: Basic signature (baseline)
        B_T: Signature with timestamp
        B_LT: Long-term validation with revocation info
        B_LTA: Long-term archival with archive timestamps
    """

    B_B = "B-B"
    B_T = "B-T"
    B_LT = "B-LT"
    B_LTA = "B-LTA"


class ErrorResponse(BaseModel):
    """Standard error response format.

    Attributes:
        detail: Human-readable error message
        code: Optional machine-readable error code for client handling
    """

    detail: str = Field(..., max_length=4096)
    code: str | None = Field(None, max_length=64)


class JobStatus(BaseModel):
    """Status information for an asynchronous job.

    Attributes:
        job_id: Unique identifier for the job
        status: Current execution status
        created_at: Timestamp when job was created
        completed_at: Timestamp when job finished (success or failure)
        message: Optional informational message about job progress
        error: Optional error message if status is FAILED
    """

    job_id: str = Field(..., max_length=64)
    status: StatusEnum
    created_at: datetime
    completed_at: datetime | None = None
    message: str | None = Field(None, max_length=4096)
    error: str | None = Field(None, max_length=4096)
