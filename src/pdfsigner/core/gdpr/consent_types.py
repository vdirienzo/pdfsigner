"""
consent_types.py - Consent type enumerations

Defines consent types for GDPR Article 7 compliance.
"""

from enum import Enum


class ConsentType(str, Enum):
    """
    Types of user consent for GDPR compliance.

    GDPR Article 7 requires explicit consent for different data processing activities.
    Each consent type must be granular, freely given, and revocable.
    """

    PROCESSING = "processing"  # Basic data processing (required for service)
    ANALYTICS = "analytics"  # Usage analytics and telemetry
    MARKETING = "marketing"  # Marketing communications and newsletters
    THIRD_PARTY = "third_party"  # Third-party data sharing
    RESEARCH = "research"  # Anonymized research and improvement


__all__ = ["ConsentType"]
