"""
algorithm_policy.py - SOGIS-compliant algorithm strength verification

Validates cryptographic algorithms against SOGIS Agreed Cryptographic
Mechanisms as required by eIDAS 2 (CIR 2025/1945) for qualified
electronic signatures.

Algorithm requirements:
- Hash: SHA-256+ (SHA-1 only for legacy validation, NEVER for creation)
- RSA: >=2048 bits (>=3072 recommended for creation)
- ECDSA: P-256 (secp256r1), P-384, P-521
- EdDSA: Ed25519, Ed448
"""

import logging
from dataclasses import dataclass
from datetime import date
from enum import Enum

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SOGIS v1.3 deprecation timeline (official dates)
# ---------------------------------------------------------------------------

RSA_DEPRECATION: dict[str, date | None] = {
    "rsa_1024": date(2013, 12, 31),  # Long expired
    "rsa_2048": date(2025, 12, 31),  # EXPIRED per SOGIS v1.3
    "rsa_3072": None,  # No expiry date
    "rsa_4096": None,  # No expiry date
}

HASH_DEPRECATION: dict[str, date | None] = {
    "md5": date(2009, 12, 31),  # Long expired
    "sha1": date(2016, 12, 31),  # Expired for creation
    "sha224": date(2025, 12, 31),  # Legacy
    "sha256": None,  # No expiry date
    "sha384": None,  # No expiry date
    "sha512": None,  # No expiry date
}


class AlgorithmStrength(str, Enum):
    """Algorithm strength classification."""

    STRONG = "strong"  # Meets current SOGIS requirements
    ACCEPTABLE = "acceptable"  # Meets minimum requirements
    LEGACY = "legacy"  # Below recommended, still validates
    WEAK = "weak"  # Should be rejected


@dataclass
class AlgorithmAssessment:
    """Result of algorithm strength assessment."""

    hash_algorithm: str
    hash_strength: AlgorithmStrength
    signature_algorithm: str
    key_size: int
    key_strength: AlgorithmStrength
    overall_strength: AlgorithmStrength
    issues: list[str]
    recommendations: list[str]


# Hash algorithm classification
HASH_STRENGTH: dict[str, AlgorithmStrength] = {
    "sha256": AlgorithmStrength.STRONG,
    "sha384": AlgorithmStrength.STRONG,
    "sha512": AlgorithmStrength.STRONG,
    "sha224": AlgorithmStrength.LEGACY,
    "sha1": AlgorithmStrength.WEAK,
    "md5": AlgorithmStrength.WEAK,
    "md2": AlgorithmStrength.WEAK,
}

# Minimum RSA key sizes
RSA_MIN_CREATION = 3072  # Recommended for new signatures
RSA_MIN_VALIDATION = 2048  # Minimum for validation
RSA_STRONG = 4096  # Strong

# ECDSA curve classification
ECDSA_CURVES: dict[str, AlgorithmStrength] = {
    "secp256r1": AlgorithmStrength.STRONG,  # P-256
    "secp384r1": AlgorithmStrength.STRONG,  # P-384
    "secp521r1": AlgorithmStrength.STRONG,  # P-521
    "secp256k1": AlgorithmStrength.ACCEPTABLE,  # Bitcoin curve
    "secp224r1": AlgorithmStrength.LEGACY,
    "secp192r1": AlgorithmStrength.WEAK,
}


def assess_algorithm(
    hash_alg: str,
    sig_alg: str,
    key_size: int,
    curve_name: str | None = None,
    for_creation: bool = False,
) -> AlgorithmAssessment:
    """Assess cryptographic algorithm strength per SOGIS requirements.

    Args:
        hash_alg: Hash algorithm name (e.g., "sha256", "sha1")
        sig_alg: Signature algorithm (e.g., "rsa", "ecdsa", "eddsa")
        key_size: Key size in bits
        curve_name: ECDSA curve name (required for ECDSA)
        for_creation: If True, apply stricter creation requirements

    Returns:
        AlgorithmAssessment with strength classification and issues
    """
    issues: list[str] = []
    recommendations: list[str] = []

    # Assess hash algorithm
    hash_lower = hash_alg.lower().replace("-", "")
    hash_strength = HASH_STRENGTH.get(hash_lower, AlgorithmStrength.WEAK)

    if hash_strength == AlgorithmStrength.WEAK:
        issues.append(f"Weak hash algorithm: {hash_alg}")
        if for_creation:
            issues.append("SHA-1/MD5 MUST NOT be used for signature creation")
        recommendations.append("Use SHA-256 or stronger")

    # Assess signature algorithm and key size
    sig_lower = sig_alg.lower()
    key_strength = AlgorithmStrength.WEAK

    if "rsa" in sig_lower:
        if key_size >= RSA_STRONG:
            key_strength = AlgorithmStrength.STRONG
        elif key_size >= RSA_MIN_CREATION:
            key_strength = AlgorithmStrength.STRONG
        elif key_size >= RSA_MIN_VALIDATION:
            key_strength = AlgorithmStrength.ACCEPTABLE
            if for_creation:
                issues.append(
                    f"RSA {key_size}-bit below recommended {RSA_MIN_CREATION}-bit for creation"
                )
                recommendations.append(f"Use RSA >= {RSA_MIN_CREATION} bits for new signatures")
        else:
            key_strength = AlgorithmStrength.WEAK
            issues.append(f"RSA {key_size}-bit below minimum {RSA_MIN_VALIDATION}-bit")

        # PSS vs PKCS1v15
        if "pss" in sig_lower:
            pass  # PSS is preferred
        elif for_creation:
            recommendations.append("Consider RSA-PSS instead of PKCS#1 v1.5")

    elif "ecdsa" in sig_lower or "ec" in sig_lower:
        if curve_name:
            curve_lower = curve_name.lower()
            key_strength = ECDSA_CURVES.get(curve_lower, AlgorithmStrength.WEAK)
            if key_strength == AlgorithmStrength.WEAK:
                issues.append(f"Unsupported/weak ECDSA curve: {curve_name}")
        else:
            # Infer from key size
            if key_size >= 384:
                key_strength = AlgorithmStrength.STRONG
            elif key_size >= 256:
                key_strength = AlgorithmStrength.STRONG
            else:
                key_strength = AlgorithmStrength.WEAK
                issues.append(f"ECDSA key size {key_size}-bit too small")

    elif "eddsa" in sig_lower or "ed25519" in sig_lower or "ed448" in sig_lower:
        key_strength = AlgorithmStrength.STRONG

    else:
        key_strength = AlgorithmStrength.WEAK
        issues.append(f"Unknown signature algorithm: {sig_alg}")

    # Overall strength = weakest link
    strengths = [hash_strength, key_strength]
    if AlgorithmStrength.WEAK in strengths:
        overall = AlgorithmStrength.WEAK
    elif AlgorithmStrength.LEGACY in strengths:
        overall = AlgorithmStrength.LEGACY
    elif AlgorithmStrength.ACCEPTABLE in strengths:
        overall = AlgorithmStrength.ACCEPTABLE
    else:
        overall = AlgorithmStrength.STRONG

    return AlgorithmAssessment(
        hash_algorithm=hash_alg,
        hash_strength=hash_strength,
        signature_algorithm=sig_alg,
        key_size=key_size,
        key_strength=key_strength,
        overall_strength=overall,
        issues=issues,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# SOGIS Deprecation Detection
# ---------------------------------------------------------------------------


@dataclass
class AlgorithmDeprecationWarning:
    """Warning about an algorithm approaching or past deprecation."""

    algorithm: str
    key_size: int | None
    deprecation_date: date | None
    is_deprecated: bool
    days_until_deprecation: int | None  # None if no date, negative if past
    severity: str  # "critical", "warning", "info"
    message: str
    recommendation: str


def _rsa_deprecation_key(key_size: int) -> str:
    """Map RSA key size to its deprecation lookup key."""
    if key_size <= 1024:
        return "rsa_1024"
    elif key_size <= 2048:
        return "rsa_2048"
    elif key_size <= 3072:
        return "rsa_3072"
    else:
        return "rsa_4096"


def _classify_severity(
    dep_date: date | None,
    today: date,
) -> tuple[str, bool, int | None]:
    """Classify severity based on deprecation date distance.

    Returns:
        Tuple of (severity, is_deprecated, days_until_deprecation).
    """
    if dep_date is None:
        return "info", False, None

    delta_days = (dep_date - today).days

    if delta_days < 0:
        return "critical", True, delta_days
    elif delta_days <= 365:
        return "warning", False, delta_days
    else:
        return "info", False, delta_days


def check_algorithm_deprecation(
    hash_alg: str,
    sig_alg: str,
    key_size: int,
    reference_date: date | None = None,
) -> list[AlgorithmDeprecationWarning]:
    """Check algorithms against SOGIS v1.3 deprecation timeline.

    Args:
        hash_alg: Hash algorithm name (e.g., "sha256", "sha1")
        sig_alg: Signature algorithm (e.g., "rsa", "ecdsa", "eddsa")
        key_size: Key size in bits
        reference_date: Date to check against (default: today)

    Returns:
        List of deprecation warnings, ordered by severity
        (critical first, then warning, then info).
    """
    today = reference_date or date.today()
    warnings: list[AlgorithmDeprecationWarning] = []

    severity_order = {"critical": 0, "warning": 1, "info": 2}

    # Check hash algorithm deprecation
    hash_lower = hash_alg.lower().replace("-", "")
    hash_dep_date = HASH_DEPRECATION.get(hash_lower)

    # Only generate a warning if the algorithm has a deprecation date
    # (algorithms with None are considered safe indefinitely)
    if hash_dep_date is not None:
        severity, is_deprecated, days = _classify_severity(hash_dep_date, today)
        if is_deprecated:
            msg = (
                f"Hash algorithm {hash_alg} deprecated since "
                f"{hash_dep_date.isoformat()} (SOGIS v1.3)"
            )
            rec = "Migrate to SHA-256 or stronger and re-timestamp"
        elif days is not None and days <= 365:
            msg = (
                f"Hash algorithm {hash_alg} will be deprecated on "
                f"{hash_dep_date.isoformat()} ({days} days remaining)"
            )
            rec = "Plan migration to SHA-256 or stronger before deprecation"
        else:
            msg = (
                f"Hash algorithm {hash_alg} scheduled for deprecation on "
                f"{hash_dep_date.isoformat()}"
            )
            rec = "No immediate action needed"

        warnings.append(
            AlgorithmDeprecationWarning(
                algorithm=hash_alg,
                key_size=None,
                deprecation_date=hash_dep_date,
                is_deprecated=is_deprecated,
                days_until_deprecation=days,
                severity=severity,
                message=msg,
                recommendation=rec,
            )
        )
    elif hash_lower not in HASH_DEPRECATION:
        # Unknown hash algorithm - warn
        warnings.append(
            AlgorithmDeprecationWarning(
                algorithm=hash_alg,
                key_size=None,
                deprecation_date=None,
                is_deprecated=False,
                days_until_deprecation=None,
                severity="warning",
                message=f"Unknown hash algorithm: {hash_alg}",
                recommendation="Verify algorithm is approved per SOGIS v1.3",
            )
        )

    # Check RSA key size deprecation
    sig_lower = sig_alg.lower()
    if "rsa" in sig_lower:
        rsa_key = _rsa_deprecation_key(key_size)
        rsa_dep_date = RSA_DEPRECATION.get(rsa_key)

        if rsa_dep_date is not None:
            severity, is_deprecated, days = _classify_severity(rsa_dep_date, today)
            if is_deprecated:
                msg = f"RSA-{key_size} deprecated since {rsa_dep_date.isoformat()} (SOGIS v1.3)"
                rec = "Migrate to RSA-3072+ or ECDSA P-256+ and re-timestamp"
            elif days is not None and days <= 365:
                msg = (
                    f"RSA-{key_size} will be deprecated on "
                    f"{rsa_dep_date.isoformat()} ({days} days remaining)"
                )
                rec = "Plan migration to RSA-3072+ or ECDSA P-256+ before deprecation"
            else:
                msg = f"RSA-{key_size} scheduled for deprecation on {rsa_dep_date.isoformat()}"
                rec = "No immediate action needed"

            warnings.append(
                AlgorithmDeprecationWarning(
                    algorithm=sig_alg,
                    key_size=key_size,
                    deprecation_date=rsa_dep_date,
                    is_deprecated=is_deprecated,
                    days_until_deprecation=days,
                    severity=severity,
                    message=msg,
                    recommendation=rec,
                )
            )

    # Sort by severity: critical > warning > info
    warnings.sort(key=lambda w: severity_order.get(w.severity, 3))
    return warnings
