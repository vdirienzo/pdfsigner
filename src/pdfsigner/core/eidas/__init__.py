"""
eIDAS Compliance Module - Qualified Trust Service Provider Integration

Author: Homero Thompson del Lago del Terror

Provides eIDAS-compliant validation for Qualified Electronic Signatures (QES)
based on EU Regulation 910/2014 with production-ready integration.

Modules:
- tsp_registry: EU Trusted List of Trust Service Providers (TSPs)
- qualified_validator: Qualified Electronic Signature (QES) validation
- seal_manager: Electronic seal implementation (eIDAS Article 35-40)
- lotl_fetcher: EU List of Trusted Lists fetcher
- tsl_parser: Country TSL parser
- pdf_signature_extractor: PDF signature extraction using pyHanko

Usage:
    from pdfsigner.core.eidas import get_tsp_registry, QualifiedSignatureValidator

    registry = get_tsp_registry()
    validator = QualifiedSignatureValidator(registry)
    result = validator.validate_qes("signed.pdf")
"""

from pdfsigner.core.eidas.lotl_fetcher import (
    LOTLData,
    LOTLFetcher,
    TSLPointer,
    get_lotl_fetcher,
)
from pdfsigner.core.eidas.pdf_signature_extractor import (
    ExtractedSignature,
    PDFSignatureExtractor,
    get_signature_extractor,
)
from pdfsigner.core.eidas.qualified_tsa_selector import (
    QualifiedTSA,
    TSASelectionResult,
    get_qualified_tsa_urls,
    get_qualified_tsas_from_registry,
    select_best_tsa,
)
from pdfsigner.core.eidas.qualified_validator import (
    QESValidationResult,
    QualifiedSignatureValidator,
    SignatureValidation,
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
from pdfsigner.core.eidas.tsl_parser import TSLParser
from pdfsigner.core.eidas.tsl_types import (
    ServiceInfo,
    ServiceStatus,
)
from pdfsigner.core.eidas.tsl_types import (
    ServiceType as TSLServiceType,
)
from pdfsigner.core.eidas.tsl_types import (
    TSPInfo as TSLTSPInfo,
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
    "SignatureValidation",
    # Seal
    "SealType",
    "SealAppearance",
    "OrganizationInfo",
    "SealConfig",
    "SealResult",
    "SealValidationResult",
    "SealManager",
    "get_seal_manager",
    # LOTL Fetcher
    "LOTLFetcher",
    "LOTLData",
    "TSLPointer",
    "get_lotl_fetcher",
    # TSL Parser
    "TSLParser",
    "ServiceStatus",
    "TSLServiceType",
    "ServiceInfo",
    "TSLTSPInfo",
    # Qualified TSA Selector
    "QualifiedTSA",
    "TSASelectionResult",
    "get_qualified_tsas_from_registry",
    "select_best_tsa",
    "get_qualified_tsa_urls",
    # Signature Extractor
    "PDFSignatureExtractor",
    "ExtractedSignature",
    "get_signature_extractor",
]
