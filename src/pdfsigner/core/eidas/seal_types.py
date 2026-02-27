"""seal_types.py - Type definitions for Electronic Seals (eIDAS Article 35-40)

Shared type definitions used by both seal_manager.py and seal_validator.py.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class SealType(str, Enum):
    """Types of electronic seals per eIDAS."""

    BASIC = "basic"  # Basic electronic seal
    ADVANCED = "advanced"  # Advanced electronic seal (AdESeal)
    QUALIFIED = "qualified"  # Qualified electronic seal (QESeal)


class SealAppearance(str, Enum):
    """Visual appearance types for seals."""

    INVISIBLE = "invisible"  # No visible mark
    STAMP = "stamp"  # Circular seal appearance
    BANNER = "banner"  # Rectangular banner
    LOGO = "logo"  # Organization logo


class SealQualificationLevel(str, Enum):
    """eIDAS seal qualification level."""

    QESEAL = "QESeal"  # Qualified Electronic Seal
    ADESEAL_QC = "AdESeal-QC"  # Advanced with Qualified Certificate
    ADESEAL = "AdESeal"  # Advanced Electronic Seal
    BASIC = "Basic"  # Basic seal


@dataclass
class OrganizationInfo:
    """Organization information for seal."""

    name: str
    country: str  # ISO 3166-1 alpha-2
    organization_id: str = ""  # VAT, LEI, or other identifier
    department: str = ""
    address: str = ""
    email: str = ""
    website: str = ""


@dataclass
class SealConfig:
    """Configuration for creating an electronic seal."""

    organization: OrganizationInfo
    seal_type: SealType = SealType.ADVANCED
    appearance: SealAppearance = SealAppearance.STAMP
    reason: str = "Organization seal"
    location: str = ""
    # Visual appearance
    page: int = 1  # 1-indexed, -1 for last page
    position: tuple[float, float] = (50, 50)  # mm from bottom-left
    size: tuple[float, float] = (40, 40)  # mm width x height
    logo_path: Path | None = None
    background_color: str = "#1a365d"  # Navy blue
    text_color: str = "#ffffff"
    border_width: float = 2.0
    # Timestamp
    include_timestamp: bool = True
    tsa_url: str = ""


@dataclass
class SealResult:
    """Result of seal operation."""

    success: bool
    output_path: Path
    seal_type: SealType
    organization: str
    timestamp: datetime | None = None
    signature_id: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass
class SealValidationResult:
    """Result of seal validation."""

    valid: bool
    seal_type: SealType
    organization: OrganizationInfo
    sealed_at: datetime
    certificate_valid: bool
    timestamp_valid: bool
    integrity_intact: bool
    issues: list[str] = field(default_factory=list)
