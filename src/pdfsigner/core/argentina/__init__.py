"""
Argentine compliance module for PDFSigner.

Implements Ley 25.506 (Digital Signature Law) compliance checking:
- Registry of licensed Argentine Certification Authorities
- Certificate validation against technical requirements
- Legal validity assessment

Author: Homero Thompson del Lago del Terror
"""

from pdfsigner.core.argentina.ca_registry import (
    ARGENTINE_CERTIFIERS,
    ArgentineCARegistry,
    ArgentineCertifier,
    CertifierStatus,
    CertifierType,
    get_argentine_ca_registry,
)
from pdfsigner.core.argentina.certificate_validator import (
    ArgentineCertificateValidator,
    ArgentineValidationResult,
    ArgentineValidationStatus,
    get_argentine_validator,
)

__all__ = [
    # CA Registry
    "ArgentineCARegistry",
    "ArgentineCertifier",
    "CertifierType",
    "CertifierStatus",
    "ARGENTINE_CERTIFIERS",
    "get_argentine_ca_registry",
    # Certificate Validator
    "ArgentineCertificateValidator",
    "ArgentineValidationResult",
    "ArgentineValidationStatus",
    "get_argentine_validator",
]
