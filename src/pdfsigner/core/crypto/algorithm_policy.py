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
from enum import Enum

logger = logging.getLogger(__name__)


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
