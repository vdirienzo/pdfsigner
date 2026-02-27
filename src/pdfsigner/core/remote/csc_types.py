"""
csc_types.py - Type definitions for CSC API v2 remote signing

Contains enums, dataclasses, and exception classes used by the CSC client
and other remote signing modules.

Standards:
- CSC API V2.2 (Cloud Signature Consortium, Nov 2025)
- ETSI TS 119 432 (Protocols for remote digital signature creation)
"""

from dataclasses import dataclass, field
from enum import Enum


class CSCAuthMethod(str, Enum):
    """CSC API authentication methods."""

    OAUTH2 = "oauth2"
    BASIC = "basic"
    EXTERNAL = "external"


class CSCSignAlgo(str, Enum):
    """CSC API signature algorithms."""

    RSA_SHA256 = "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption
    RSA_SHA384 = "1.2.840.113549.1.1.12"  # sha384WithRSAEncryption
    RSA_SHA512 = "1.2.840.113549.1.1.13"  # sha512WithRSAEncryption
    RSA_PSS = "1.2.840.113549.1.1.10"  # rsaPSS
    ECDSA_SHA256 = "1.2.840.10045.4.3.2"  # ecdsaWithSHA256
    ECDSA_SHA384 = "1.2.840.10045.4.3.3"  # ecdsaWithSHA384
    ECDSA_SHA512 = "1.2.840.10045.4.3.4"  # ecdsaWithSHA512


@dataclass
class CSCServiceInfo:
    """CSC service information from /info endpoint."""

    name: str = ""
    lang: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    auth_type: list[str] = field(default_factory=list)
    signature_formats: list[str] = field(default_factory=list)
    description: str = ""
    region: str = ""
    logo: str = ""


@dataclass
class CSCCredentialInfo:
    """CSC credential information from /credentials/info."""

    credential_id: str = ""
    description: str = ""
    key_algo: str = ""
    key_len: int = 0
    sign_algos: list[str] = field(default_factory=list)
    certificates: list[str] = field(default_factory=list)  # Base64 DER certs
    certificate_chain: list[str] = field(default_factory=list)
    issuer_dn: str = ""
    subject_dn: str = ""
    valid_from: str = ""
    valid_to: str = ""
    status: str = ""  # "enabled", "disabled"
    multisign: int = 1  # Max hashes per authorization
    scal: str = "1"  # Sole Control Assurance Level


@dataclass
class CSCAuthorizationResult:
    """Result of credential authorization."""

    sad: str = ""  # Signature Activation Data
    expires_in: int = 0  # SAD validity in seconds


@dataclass
class CSCSignHashResult:
    """Result of hash signing."""

    signatures: list[str] = field(default_factory=list)  # Base64 signatures


class CSCError(Exception):
    """CSC API error."""

    def __init__(
        self,
        message: str,
        status_code: int = 0,
        error_code: str = "",
        error_description: str = "",
    ):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.error_description = error_description


__all__ = [
    "CSCAuthMethod",
    "CSCAuthorizationResult",
    "CSCCredentialInfo",
    "CSCError",
    "CSCServiceInfo",
    "CSCSignAlgo",
    "CSCSignHashResult",
]
