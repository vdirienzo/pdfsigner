"""
validator_types.py - Data types for PDF signature validation

Author: Homero Thompson del Lago del Terror

Contains the data types (enums, dataclasses) used by PDFValidator.
Extracted from pdf_validator.py to keep each module under 400 lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from pdfsigner.core.certificate import ChainValidationResult

if TYPE_CHECKING:
    from pdfsigner.core.signer.archive_ts_manager import ArchiveTimestampInfo

# Argentine compliance validator (optional import)
try:
    from pdfsigner.core.argentina import ArgentineValidationResult

    _ARGENTINE_AVAILABLE = True
except ImportError:
    _ARGENTINE_AVAILABLE = False
    ArgentineValidationResult = None  # type: ignore


class SignatureStatus(Enum):
    """Signature validation status."""

    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    INDETERMINATE = "indeterminate"


class PAdESLevel(str, Enum):
    """PAdES compliance level."""

    B_B = "B-B"  # Basic signature
    B_T = "B-T"  # With timestamp
    B_LT = "B-LT"  # With LTV info (DSS)
    B_LTA = "B-LTA"  # With archive timestamp
    UNKNOWN = "unknown"


@dataclass
class LTVInfo:
    """LTV validation information for a signature."""

    has_dss: bool = False
    has_ocsp_in_dss: bool = False
    has_crl_in_dss: bool = False
    has_archive_timestamp: bool = False
    pades_level: PAdESLevel = PAdESLevel.UNKNOWN
    archive_timestamps: list[ArchiveTimestampInfo] = field(default_factory=list)


@dataclass
class SignatureInfo:
    """Signature information in PDF."""

    signer_name: str
    signer_email: str | None
    signing_time: datetime | None
    is_timestamp_valid: bool
    certificate_issuer: str
    certificate_serial: str
    certificate_valid_from: datetime | None
    certificate_valid_to: datetime | None
    status: SignatureStatus
    status_message: str
    field_name: str
    covers_whole_document: bool
    is_modification_allowed: bool
    page_number: int | None  # Page where visible signature is located (if applicable)
    certificate_bytes: bytes | None = None  # DER-encoded certificate for viewing
    chain_validation_result: ChainValidationResult | None = None
    revocation_status: str | None = None  # "valid", "revoked", "unknown", "error"
    revocation_message: str | None = None  # Human-readable message
    ltv_info: LTVInfo | None = None  # PAdES-LTV information
    argentine_compliance_result: ArgentineValidationResult | None = None  # Argentine Ley 25.506
    eidas_level: str | None = None  # "QES", "AdES-QC", "AdES", "Basic" or None
    eidas_tsp_name: str | None = None  # Qualified TSP name from EUTL


@dataclass
class ValidationResult:
    """PDF validation result."""

    file_path: Path
    is_signed: bool
    signature_count: int
    all_valid: bool
    signatures: list[SignatureInfo]
    error: str | None = None
