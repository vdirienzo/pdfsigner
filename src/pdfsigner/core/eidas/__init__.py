"""
eIDAS Compliance Module - Qualified Trust Service Provider Integration

Author: Homero Thompson del Lago del Terror

Provides eIDAS-compliant validation for Qualified Electronic Signatures (QES)
based on EU Regulation 910/2014.

Modules:
- tsp_registry: EU Trusted List of Trust Service Providers (TSPs)
- qualified_validator: Qualified Electronic Signature (QES) validation
- seal_manager: Electronic seal implementation (eIDAS Article 35-40)

Usage:
    from pdfsigner.core.eidas import get_tsp_registry, QualifiedSignatureValidator

    registry = get_tsp_registry()
    validator = QualifiedSignatureValidator(registry)
    result = validator.validate_qes("signed.pdf")
"""

from pdfsigner.core.eidas.qualified_validator import (
    QESValidationResult,
    QualifiedSignatureValidator,
)
from pdfsigner.core.eidas.seal_manager import (
    OrganizationInfo,
    SealAppearance,
    SealConfig,
    SealManager,
    SealResult,
    SealType,
    SealValidationResult,
    get_seal_manager,
)
from pdfsigner.core.eidas.tsp_registry import (
    EUTSPRegistry,
    QualificationStatus,
    ServiceType,
    TrustedListInfo,
    TSPInfo,
    get_tsp_registry,
)

__all__ = [
    # Registry
    "EUTSPRegistry",
    "QualificationStatus",
    "ServiceType",
    "TSPInfo",
    "TrustedListInfo",
    "get_tsp_registry",
    # Validator
    "QESValidationResult",
    "QualifiedSignatureValidator",
    # Seal
    "SealType",
    "SealAppearance",
    "OrganizationInfo",
    "SealConfig",
    "SealResult",
    "SealValidationResult",
    "SealManager",
    "get_seal_manager",
]
