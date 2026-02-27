"""
GDPR compliance module for data retention and erasure.

Provides:
- Data retention policies
- User anonymization (pseudonymization)
- Data export (right to portability)
- Consent management (Article 7)
- Scheduled deletion with grace period

GDPR Articles:
- Article 7: Conditions for consent
- Article 17: Right to erasure ("right to be forgotten")
- Article 20: Right to data portability
"""

from pdfsigner.core.gdpr.anonymization_service import AnonymizationService
from pdfsigner.core.gdpr.consent_manager import ConsentManager, get_consent_manager
from pdfsigner.core.gdpr.consent_repository import (
    ConsentRecord,
    ConsentRepository,
    get_consent_repository,
)
from pdfsigner.core.gdpr.consent_types import ConsentType
from pdfsigner.core.gdpr.data_export import UserDataExport, UserDataExporter
from pdfsigner.core.gdpr.data_retention import (
    DataRetentionService,
    get_data_retention_service,
)
from pdfsigner.core.gdpr.data_retention_types import (
    AnonymizationResult,
    PurgeResult,
    RetentionStatus,
)

__all__ = [
    # Data retention
    "DataRetentionService",
    "AnonymizationService",
    "AnonymizationResult",
    "PurgeResult",
    "RetentionStatus",
    "get_data_retention_service",
    # Data export
    "UserDataExporter",
    "UserDataExport",
    # Consent management
    "ConsentManager",
    "ConsentRepository",
    "ConsentRecord",
    "ConsentType",
    "get_consent_manager",
    "get_consent_repository",
]
