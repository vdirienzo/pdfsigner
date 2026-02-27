"""
Seal service for electronic seal operations.

Business logic for PDF sealing, job management, and seal validation.
eIDAS Article 35-40.
"""

import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.api.schemas.seal import (
    OrganizationInfoSchema,
    SealJobStatus,
    SealResponse,
)
from pdfsigner.core.eidas.seal_manager import (
    OrganizationInfo,
    SealAppearance,
    SealConfig,
    SealManager,
    SealType,
)

# In-memory job storage (production would use database)
_seal_jobs: dict[str, dict] = {}
_seal_job_timestamps: dict[str, float] = {}
_seal_lock = threading.Lock()
_MAX_SEAL_JOBS = 1000
_SEAL_JOB_TTL_SECONDS = 86400  # 24 hours


def cleanup_seal_jobs() -> None:
    """Remove expired seal job entries."""
    now = time.time()
    with _seal_lock:
        expired = [k for k, t in _seal_job_timestamps.items() if now - t > _SEAL_JOB_TTL_SECONDS]
        for k in expired:
            _seal_jobs.pop(k, None)
            _seal_job_timestamps.pop(k, None)


def pydantic_to_org_info(schema: OrganizationInfoSchema) -> OrganizationInfo:
    """Convert Pydantic schema to OrganizationInfo dataclass."""
    return OrganizationInfo(
        name=schema.name,
        country=schema.country,
        organization_id=schema.organization_id,
        department=schema.department,
        address=schema.address,
        email=schema.email,
        website=schema.website,
    )


def org_info_to_pydantic(org: OrganizationInfo) -> OrganizationInfoSchema:
    """Convert OrganizationInfo dataclass to Pydantic schema."""
    country = org.country.upper() if org.country and len(org.country) == 2 else "XX"
    return OrganizationInfoSchema(
        name=org.name or "Unknown",
        country=country,
        organization_id=org.organization_id,
        department=org.department,
        address=org.address,
        email=org.email,
        website=org.website,
    )


def parse_seal_enums(seal_type: str, appearance: str) -> tuple[SealType, SealAppearance]:
    """Parse and validate seal type and appearance enums.

    Args:
        seal_type: Seal type string
        appearance: Appearance string

    Returns:
        Tuple of (SealType, SealAppearance)

    Raises:
        ValueError: If any value is invalid
    """
    try:
        seal_type_enum = SealType(seal_type)
    except ValueError:
        raise ValueError(
            f"Invalid seal_type: {seal_type}. Must be one of: {[e.value for e in SealType]}"
        )

    try:
        appearance_enum = SealAppearance(appearance)
    except ValueError:
        raise ValueError(
            f"Invalid appearance: {appearance}. Must be one of: {[e.value for e in SealAppearance]}"
        )

    return seal_type_enum, appearance_enum


def build_seal_config(
    organization_name: str,
    organization_country: str,
    organization_id: str,
    seal_type_enum: SealType,
    appearance_enum: SealAppearance,
    reason: str,
    location: str,
    page: int,
    include_timestamp: bool,
    tsa_url: str,
) -> SealConfig:
    """Build SealConfig from parameters.

    Args:
        organization_name: Organization legal name
        organization_country: ISO 3166-1 alpha-2 country code
        organization_id: Organization identifier (VAT, LEI, etc.)
        seal_type_enum: Parsed SealType enum
        appearance_enum: Parsed SealAppearance enum
        reason: Reason for sealing
        location: Geographic location
        page: Page number for seal
        include_timestamp: Include trusted timestamp
        tsa_url: TSA URL

    Returns:
        SealConfig object
    """
    org_info = OrganizationInfo(
        name=organization_name,
        country=organization_country.upper(),
        organization_id=organization_id,
    )

    return SealConfig(
        organization=org_info,
        seal_type=seal_type_enum,
        appearance=appearance_enum,
        reason=reason,
        location=location,
        page=page,
        include_timestamp=include_timestamp,
        tsa_url=tsa_url,
    )


def create_seal_job(
    user_id: str,
    filename: str,
    organization_name: str,
    seal_type: str,
    input_path: Path,
) -> str:
    """Create a new seal job entry.

    Args:
        user_id: User ID
        filename: Original filename
        organization_name: Organization name
        seal_type: Seal type string
        input_path: Path to input PDF

    Returns:
        Job ID string

    Raises:
        RuntimeError: If too many pending jobs
    """
    cleanup_seal_jobs()

    job_id = f"seal_{uuid.uuid4().hex[:12]}"

    with _seal_lock:
        if len(_seal_jobs) >= _MAX_SEAL_JOBS:
            raise RuntimeError("Too many pending seal jobs. Please try again later.")

        _seal_job_timestamps[job_id] = time.time()
        _seal_jobs[job_id] = {
            "job_id": job_id,
            "user_id": user_id,
            "status": "pending",
            "filename": filename,
            "organization": organization_name,
            "seal_type": seal_type,
            "created_at": datetime.now(UTC).isoformat(),
            "input_path": str(input_path),
            "completed_at": None,
            "error": None,
            "download_url": None,
            "signature_id": None,
        }

    return job_id


async def process_seal_job(
    job_id: str, pdf_path: Path, seal_config: SealConfig, seal_manager: SealManager
) -> None:
    """Background task to process seal job.

    Args:
        job_id: Job identifier
        pdf_path: Path to PDF file
        seal_config: Seal configuration
        seal_manager: SealManager instance
    """
    try:
        logger.info(f"Processing seal job {job_id}")
        with _seal_lock:
            _seal_jobs[job_id]["status"] = "processing"

        result = seal_manager.create_seal(pdf_path=pdf_path, config=seal_config, dry_run=False)

        if result.success:
            with _seal_lock:
                _seal_jobs[job_id].update(
                    {
                        "status": "completed",
                        "completed_at": datetime.now(UTC).isoformat(),
                        "output_path": str(result.output_path),
                        "signature_id": result.signature_id,
                        "download_url": f"/api/v1/seal/{job_id}/download",
                    }
                )
            logger.info(f"Seal job {job_id} completed successfully")
        else:
            with _seal_lock:
                _seal_jobs[job_id].update(
                    {
                        "status": "failed",
                        "completed_at": datetime.now(UTC).isoformat(),
                        "error": "; ".join(result.errors),
                    }
                )
            logger.error(f"Seal job {job_id} failed: {result.errors}")

    except Exception as e:
        logger.exception(f"Error processing seal job {job_id}: {e}")
        with _seal_lock:
            _seal_jobs[job_id].update(
                {
                    "status": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "error": str(e),
                }
            )


def get_seal_job(job_id: str, user_id: str) -> dict:
    """Get seal job data for user.

    Args:
        job_id: Job identifier
        user_id: User ID for ownership check

    Returns:
        Job data dict

    Raises:
        LookupError: If job not found or not owned by user
    """
    with _seal_lock:
        if job_id not in _seal_jobs:
            raise LookupError("Job not found")

        if _seal_jobs[job_id].get("user_id") != user_id:
            raise LookupError("Job not found")

        return _seal_jobs[job_id].copy()


def build_job_status_response(job: dict) -> SealJobStatus:
    """Build SealJobStatus from job data dict.

    Args:
        job: Job data dictionary

    Returns:
        SealJobStatus response
    """
    return SealJobStatus(
        job_id=job["job_id"],
        status=job["status"],
        filename=job["filename"],
        organization=job["organization"],
        seal_type=job["seal_type"],
        created_at=job["created_at"],
        completed_at=job["completed_at"],
        error=job["error"],
        download_url=job["download_url"],
        signature_id=job["signature_id"],
    )


def get_download_info(job: dict) -> tuple[Path, str]:
    """Get download path and filename from job data.

    Args:
        job: Job data dictionary

    Returns:
        Tuple of (output_path, sealed_filename)

    Raises:
        ValueError: If job failed or not completed
        FileNotFoundError: If output file missing
    """
    if job["status"] == "failed":
        raise ValueError(f"Seal job failed: {job['error']}")

    if job["status"] != "completed":
        raise ValueError(f"Seal job not completed yet (status: {job['status']})")

    output_path = Path(job["output_path"])
    if not output_path.exists():
        raise FileNotFoundError("Sealed PDF file not found (may have been cleaned up)")

    original_name = job["filename"]
    sealed_name = original_name.replace(".pdf", "_sealed.pdf")

    return output_path, sealed_name


def build_seal_response(
    job_id: str, organization_name: str, seal_type: str, safe_filename: str
) -> SealResponse:
    """Build SealResponse for a new job.

    Args:
        job_id: Job identifier
        organization_name: Organization name
        seal_type: Seal type string
        safe_filename: Sanitized filename

    Returns:
        SealResponse object
    """
    return SealResponse(
        job_id=job_id,
        status="pending",
        organization=organization_name,
        seal_type=seal_type,
        message=f"Seal job created for {safe_filename}",
        download_url=f"/api/v1/seal/{job_id}/download",
    )


__all__ = [
    "build_job_status_response",
    "build_seal_config",
    "build_seal_response",
    "cleanup_seal_jobs",
    "create_seal_job",
    "get_download_info",
    "get_seal_job",
    "org_info_to_pydantic",
    "parse_seal_enums",
    "process_seal_job",
    "pydantic_to_org_info",
]
