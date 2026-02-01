"""
certificate_validator.py - Argentine certificate validator (Ley 25.506)

Author: Homero Thompson del Lago del Terror

Validates X.509 certificates against Argentine Law 25.506 requirements.

Technical requirements from Ley 25.506 and ONTI regulations:
- RSA key size >= 2048 bits
- Hash algorithms: SHA-256, SHA-384, or SHA-512 (SHA-1 and MD5 prohibited)
- Certificate must be issued by a licensed Argentine CA for legal validity
- PKCS#11 token support (SafeNet eToken certified by ONTI)

Key features:
- Algorithm compliance checking (FIPS-aligned)
- Key size validation
- Licensed CA verification
- Legal validity assessment
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from pdfsigner.core.argentina.ca_registry import (
    ArgentineCARegistry,
    ArgentineCertifier,
    get_argentine_ca_registry,
)

logger = logging.getLogger(__name__)


class ArgentineValidationStatus(str, Enum):
    """Certificate validation status per Argentine Law 25.506."""

    VALID = "valid"  # Licensed certifier, compliant algorithms
    VALID_UNKNOWN_CA = "valid_unknown_ca"  # Valid signature but CA not in registry
    INVALID_ALGORITHM = "invalid_algorithm"  # Prohibited algorithm
    INVALID_KEY_SIZE = "invalid_key_size"  # Key too small
    EXPIRED = "expired"  # Certificate expired
    NOT_YET_VALID = "not_yet_valid"  # Certificate not yet valid
    ERROR = "error"  # Validation error


@dataclass
class ArgentineValidationResult:
    """Result of Argentine certificate validation."""

    status: ArgentineValidationStatus
    certifier: ArgentineCertifier | None
    has_legal_validity: bool  # True if signature has full legal validity
    algorithm_compliant: bool  # RSA >=2048, SHA-256+
    issues: list[str]
    recommendations: list[str]
    certificate_subject: str = ""
    certificate_issuer: str = ""
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    key_algorithm: str = ""
    key_size: int = 0
    hash_algorithm: str = ""


class ArgentineCertificateValidator:
    """Validates certificates against Argentine Ley 25.506 requirements.

    Checks:
    - Certificate issued by licensed Argentine CA
    - RSA key size >= 2048 bits (DSA/EC also supported with appropriate sizes)
    - Hash algorithm in {SHA-256, SHA-384, SHA-512}
    - No prohibited algorithms (MD5, SHA-1)
    - Certificate validity period
    """

    # Technical requirements from Ley 25.506 and ONTI
    MINIMUM_RSA_BITS = 2048
    MINIMUM_DSA_BITS = 2048
    MINIMUM_EC_BITS = 224  # EC curves (P-224 minimum)

    ALLOWED_HASH_ALGORITHMS = {"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}
    PROHIBITED_ALGORITHMS = {"md5", "sha1"}

    def __init__(self, registry: ArgentineCARegistry | None = None):
        """Initialize validator with optional CA registry.

        Args:
            registry: ArgentineCARegistry instance (uses singleton if None)
        """
        self.registry = registry or get_argentine_ca_registry()

    def validate(self, cert_der: bytes) -> ArgentineValidationResult:
        """Validate certificate against Ley 25.506 requirements.

        Args:
            cert_der: DER-encoded X.509 certificate

        Returns:
            ArgentineValidationResult with detailed validation information
        """
        issues: list[str] = []
        recommendations: list[str] = []

        try:
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Extract basic information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            valid_from = cert.not_valid_before_utc
            valid_until = cert.not_valid_after_utc

            # Check validity period
            now = datetime.now(UTC)
            if now < valid_from:
                return ArgentineValidationResult(
                    status=ArgentineValidationStatus.NOT_YET_VALID,
                    certifier=None,
                    has_legal_validity=False,
                    algorithm_compliant=False,
                    issues=["Certificate is not yet valid"],
                    recommendations=["Wait until certificate validity period starts"],
                    certificate_subject=subject,
                    certificate_issuer=issuer,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            elif now > valid_until:
                return ArgentineValidationResult(
                    status=ArgentineValidationStatus.EXPIRED,
                    certifier=None,
                    has_legal_validity=False,
                    algorithm_compliant=False,
                    issues=["Certificate has expired"],
                    recommendations=["Renew certificate from issuing CA"],
                    certificate_subject=subject,
                    certificate_issuer=issuer,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )

            # Check algorithm compliance
            algo_compliant, algo_issues = self._check_algorithm_compliance(cert)
            issues.extend(algo_issues)

            # Check key size
            key_compliant, key_issues = self._check_key_size(cert)
            issues.extend(key_issues)

            # Get key information
            key_algo, key_size = self._get_key_info(cert)

            # Get hash algorithm
            hash_algo = self._get_hash_algorithm(cert)

            # Overall algorithm compliance
            algorithm_compliant = algo_compliant and key_compliant

            # Check if issued by licensed Argentine CA
            certifier = self.registry.find_certifier_by_issuer(issuer)

            # Determine validation status
            if not algorithm_compliant:
                status = ArgentineValidationStatus.INVALID_ALGORITHM
                if not algo_compliant:
                    recommendations.append(
                        "Use certificate with SHA-256 or stronger hash algorithm"
                    )
                if not key_compliant:
                    recommendations.append(
                        f"Use certificate with RSA >= {self.MINIMUM_RSA_BITS} bits"
                    )
            elif certifier is None:
                status = ArgentineValidationStatus.VALID_UNKNOWN_CA
                issues.append("Certificate issuer is not a recognized Argentine CA")
                recommendations.append(
                    "For legal validity in Argentina, obtain certificate from licensed CA "
                    "(AFIP, RENAPER, FDR, or private certifiers)"
                )
            else:
                status = ArgentineValidationStatus.VALID
                recommendations.append(
                    f"Certificate is compliant with Ley 25.506 (issued by {certifier.name})"
                )

            # Legal validity requires licensed CA + compliant algorithms
            has_legal_validity = algorithm_compliant and certifier is not None

            return ArgentineValidationResult(
                status=status,
                certifier=certifier,
                has_legal_validity=has_legal_validity,
                algorithm_compliant=algorithm_compliant,
                issues=issues,
                recommendations=recommendations,
                certificate_subject=subject,
                certificate_issuer=issuer,
                valid_from=valid_from,
                valid_until=valid_until,
                key_algorithm=key_algo,
                key_size=key_size,
                hash_algorithm=hash_algo,
            )

        except Exception as e:
            logger.error("Certificate validation error: %s", e)
            return ArgentineValidationResult(
                status=ArgentineValidationStatus.ERROR,
                certifier=None,
                has_legal_validity=False,
                algorithm_compliant=False,
                issues=[f"Validation error: {str(e)}"],
                recommendations=["Check certificate format (must be valid X.509 DER)"],
            )

    def _check_algorithm_compliance(self, cert: x509.Certificate) -> tuple[bool, list[str]]:
        """Check if certificate uses allowed hash algorithms.

        Args:
            cert: X.509 certificate

        Returns:
            Tuple of (is_compliant, list_of_issues)
        """
        issues: list[str] = []

        try:
            # Get signature hash algorithm
            sig_algo_oid = cert.signature_algorithm_oid
            algo_name = sig_algo_oid._name.lower()

            # Check for prohibited algorithms
            for prohibited in self.PROHIBITED_ALGORITHMS:
                if prohibited in algo_name:
                    issues.append(
                        f"Prohibited algorithm detected: {prohibited.upper()} "
                        "(not compliant with Ley 25.506)"
                    )
                    return False, issues

            # Check for allowed algorithms
            is_allowed = any(allowed in algo_name for allowed in self.ALLOWED_HASH_ALGORITHMS)

            if not is_allowed:
                issues.append(
                    f"Hash algorithm {algo_name} is not in recommended list "
                    "(SHA-256, SHA-384, SHA-512)"
                )
                return False, issues

            return True, issues

        except Exception as e:
            logger.warning("Failed to check algorithm compliance: %s", e)
            issues.append(f"Could not verify algorithm compliance: {str(e)}")
            return False, issues

    def _check_key_size(self, cert: x509.Certificate) -> tuple[bool, list[str]]:
        """Check minimum key size requirements.

        Args:
            cert: X.509 certificate

        Returns:
            Tuple of (is_compliant, list_of_issues)
        """
        issues: list[str] = []

        try:
            public_key = cert.public_key()

            # RSA
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size < self.MINIMUM_RSA_BITS:
                    issues.append(
                        f"RSA key size {key_size} bits is below minimum "
                        f"{self.MINIMUM_RSA_BITS} bits required by Ley 25.506"
                    )
                    return False, issues
                return True, issues

            # DSA
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_size = public_key.key_size
                if key_size < self.MINIMUM_DSA_BITS:
                    issues.append(
                        f"DSA key size {key_size} bits is below minimum "
                        f"{self.MINIMUM_DSA_BITS} bits"
                    )
                    return False, issues
                return True, issues

            # Elliptic Curve
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_size = public_key.key_size
                if key_size < self.MINIMUM_EC_BITS:
                    issues.append(
                        f"EC key size {key_size} bits is below minimum {self.MINIMUM_EC_BITS} bits"
                    )
                    return False, issues
                return True, issues

            else:
                issues.append(f"Unknown key type: {type(public_key).__name__}")
                return False, issues

        except Exception as e:
            logger.warning("Failed to check key size: %s", e)
            issues.append(f"Could not verify key size: {str(e)}")
            return False, issues

    def _get_key_info(self, cert: x509.Certificate) -> tuple[str, int]:
        """Get key algorithm and size from certificate.

        Args:
            cert: X.509 certificate

        Returns:
            Tuple of (algorithm_name, key_size_bits)
        """
        try:
            public_key = cert.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                return "RSA", public_key.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                return "DSA", public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return "EC", public_key.key_size
            else:
                return "Unknown", 0

        except Exception as e:
            logger.warning("Failed to get key info: %s", e)
            return "Unknown", 0

    def _get_hash_algorithm(self, cert: x509.Certificate) -> str:
        """Get hash algorithm from certificate signature.

        Args:
            cert: X.509 certificate

        Returns:
            Hash algorithm name
        """
        try:
            sig_algo_oid = cert.signature_algorithm_oid
            return sig_algo_oid._name
        except Exception as e:
            logger.warning("Failed to get hash algorithm: %s", e)
            return "Unknown"


# --- Singleton access ---

_validator: ArgentineCertificateValidator | None = None


def get_argentine_validator() -> ArgentineCertificateValidator:
    """Get or create the singleton Argentine certificate validator instance.

    Returns:
        ArgentineCertificateValidator singleton instance
    """
    global _validator
    if _validator is None:
        _validator = ArgentineCertificateValidator()
    return _validator
