"""
health_status.py - Certificate health status monitoring

Author: Homero Thompson del Lago del Terror

Provides health level classification for certificates based on
expiration date with color-coded status levels.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum

logger = logging.getLogger(__name__)


@dataclass
class AlgorithmHealth:
    """Algorithm strength assessment for a certificate."""

    hash_algorithm: str = ""
    signature_algorithm: str = ""
    key_size: int = 0
    strength: str = "unknown"  # "strong", "acceptable", "legacy", "weak"
    deprecation_date: date | None = None
    is_deprecated: bool = False
    message: str = ""


class HealthLevel(Enum):
    """Certificate health level based on days until expiry."""

    OK = "ok"  # >60 days - Green
    WARNING = "warning"  # 30-60 days - Yellow
    ALERT = "alert"  # 7-30 days - Orange
    CRITICAL = "critical"  # <7 days - Red
    EXPIRED = "expired"  # <=0 days - Dark red

    @classmethod
    def from_days(cls, days: int) -> HealthLevel:
        """Determine health level from days until expiry."""
        if days <= 0:
            return cls.EXPIRED
        elif days <= 7:
            return cls.CRITICAL
        elif days <= 30:
            return cls.ALERT
        elif days <= 60:
            return cls.WARNING
        else:
            return cls.OK


# Color mapping for each health level (GTK CSS class names)
HEALTH_COLORS = {
    HealthLevel.OK: "#10B981",  # Green
    HealthLevel.WARNING: "#F59E0B",  # Yellow
    HealthLevel.ALERT: "#F97316",  # Orange
    HealthLevel.CRITICAL: "#EF4444",  # Red
    HealthLevel.EXPIRED: "#991B1B",  # Dark red
}

# CSS class names for styling
HEALTH_CSS_CLASSES = {
    HealthLevel.OK: "cert-status-ok",
    HealthLevel.WARNING: "cert-status-warning",
    HealthLevel.ALERT: "cert-status-alert",
    HealthLevel.CRITICAL: "cert-status-critical",
    HealthLevel.EXPIRED: "cert-status-expired",
}


@dataclass
class CertificateHealth:
    """
    Certificate health status information.

    Provides a comprehensive view of certificate validity
    including days remaining, health level, and display info.
    """

    subject_cn: str
    issuer_cn: str
    not_before: datetime
    not_after: datetime
    serial_number: str = ""
    algorithm_health: AlgorithmHealth | None = None

    @property
    def days_remaining(self) -> int:
        """Days until certificate expires."""
        delta = self.not_after - datetime.now(self.not_after.tzinfo)
        return max(0, delta.days)

    @property
    def health_level(self) -> HealthLevel:
        """Current health level based on expiry."""
        return HealthLevel.from_days(self.days_remaining)

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return self.days_remaining <= 0

    @property
    def lifetime_progress(self) -> float:
        """
        Percentage of certificate lifetime consumed.

        Returns:
            Float between 0.0 and 1.0
        """
        total_days = (self.not_after - self.not_before).days
        if total_days <= 0:
            return 1.0
        elapsed = (datetime.now(self.not_after.tzinfo) - self.not_before).days
        return min(1.0, max(0.0, elapsed / total_days))

    @property
    def css_class(self) -> str:
        """CSS class name for styling."""
        return HEALTH_CSS_CLASSES.get(self.health_level, "cert-status-ok")

    @property
    def color(self) -> str:
        """Hex color for the health level."""
        return HEALTH_COLORS.get(self.health_level, "#10B981")

    @property
    def status_icon(self) -> str:
        """Emoji icon for the health level."""
        icons = {
            HealthLevel.OK: "✅",
            HealthLevel.WARNING: "⚠️",
            HealthLevel.ALERT: "🔶",
            HealthLevel.CRITICAL: "🚨",
            HealthLevel.EXPIRED: "❌",
        }
        return icons.get(self.health_level, "✅")

    @property
    def status_text(self) -> str:
        """Human-readable status text."""
        if self.is_expired:
            return "Certificate expired"
        elif self.days_remaining == 1:
            return "Expires tomorrow"
        else:
            return f"Expires in {self.days_remaining} days"


# ---------------------------------------------------------------------------
# Algorithm health assessment from DER-encoded certificates
# ---------------------------------------------------------------------------

# OID-to-name mappings for signature algorithms
_SIG_ALG_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.1.5": "rsa",  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11": "rsa",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "rsa",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "rsa",  # sha512WithRSAEncryption
    "1.2.840.113549.1.1.10": "rsapss",  # rsassa-pss
    "1.2.840.10045.2.1": "ecdsa",  # ecPublicKey
    "1.2.840.10045.4.3.2": "ecdsa",  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": "ecdsa",  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": "ecdsa",  # ecdsa-with-SHA512
    "1.3.101.112": "eddsa",  # Ed25519
    "1.3.101.113": "eddsa",  # Ed448
}

_HASH_ALG_NAMES: dict[str, str] = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "1.2.840.113549.2.5": "md5",
}


def assess_certificate_algorithms(cert_der: bytes) -> AlgorithmHealth:
    """Assess algorithm strength of a DER-encoded certificate.

    Uses the ``cryptography`` library to extract the public key type,
    key size, and signature hash algorithm, then maps them to a
    strength classification consistent with SOGIS v1.3.

    Args:
        cert_der: DER-encoded X.509 certificate bytes.

    Returns:
        AlgorithmHealth with strength classification and deprecation info.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.hashes import (
        MD5,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
    )
    from cryptography.x509 import load_der_x509_certificate

    from pdfsigner.core.crypto.algorithm_policy import (
        HASH_DEPRECATION,
        RSA_DEPRECATION,
        AlgorithmStrength,
        assess_algorithm,
    )

    try:
        cert = load_der_x509_certificate(cert_der)
    except Exception:
        logger.warning("Failed to parse DER certificate for algorithm assessment")
        return AlgorithmHealth(message="Failed to parse certificate")

    # Extract signature hash algorithm
    sig_hash = cert.signature_hash_algorithm
    hash_name = "unknown"
    if sig_hash is not None:
        _hash_map: dict[type, str] = {
            SHA256: "sha256",
            SHA384: "sha384",
            SHA512: "sha512",
            SHA224: "sha224",
            SHA1: "sha1",
            MD5: "md5",
        }
        hash_name = _hash_map.get(type(sig_hash), sig_hash.name)

    # Extract public key info
    pub_key = cert.public_key()
    key_size = 0
    sig_alg = "unknown"

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        sig_alg = "rsa"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_size = pub_key.key_size
        sig_alg = "ecdsa"
    else:
        # Ed25519/Ed448 or other
        sig_alg = "eddsa"
        key_size = getattr(pub_key, "key_size", 256)

    # Assess with existing policy engine
    assessment = assess_algorithm(
        hash_alg=hash_name,
        sig_alg=sig_alg,
        key_size=key_size,
    )
    strength = assessment.overall_strength.value

    # Determine deprecation date (worst case across hash + key)
    dep_date: date | None = None
    is_deprecated = False

    hash_dep = HASH_DEPRECATION.get(hash_name.lower())
    if hash_dep is not None:
        dep_date = hash_dep
        if hash_dep < date.today():
            is_deprecated = True

    if sig_alg == "rsa":
        # Map key size to deprecation key
        if key_size <= 1024:
            rsa_key = "rsa_1024"
        elif key_size <= 2048:
            rsa_key = "rsa_2048"
        elif key_size <= 3072:
            rsa_key = "rsa_3072"
        else:
            rsa_key = "rsa_4096"

        rsa_dep = RSA_DEPRECATION.get(rsa_key)
        if rsa_dep is not None:
            # Use the earliest deprecation date
            if dep_date is None or rsa_dep < dep_date:
                dep_date = rsa_dep
            if rsa_dep < date.today():
                is_deprecated = True

    # Build human-readable message
    if is_deprecated:
        message = f"{sig_alg.upper()}-{key_size}/{hash_name} is deprecated per SOGIS v1.3"
    elif strength == AlgorithmStrength.WEAK.value:
        message = f"{sig_alg.upper()}-{key_size}/{hash_name} uses weak algorithms"
    elif dep_date is not None:
        days_left = (dep_date - date.today()).days
        message = f"{sig_alg.upper()}-{key_size}/{hash_name} deprecation in {days_left} days"
    else:
        message = f"{sig_alg.upper()}-{key_size}/{hash_name} meets SOGIS v1.3 requirements"

    return AlgorithmHealth(
        hash_algorithm=hash_name,
        signature_algorithm=sig_alg,
        key_size=key_size,
        strength=strength,
        deprecation_date=dep_date,
        is_deprecated=is_deprecated,
        message=message,
    )
