"""
data_retention_types.py - GDPR data retention dataclasses

Shared types used by data retention and anonymization services.

GDPR: Article 17 - Right to erasure ("right to be forgotten")
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class AnonymizationResult:
    """Result of user anonymization operation."""

    success: bool
    user_id: str
    fields_anonymized: list[str]
    audit_records_anonymized: int
    error_message: str | None = None


@dataclass
class PurgeResult:
    """Result of data purge operation."""

    success: bool
    users_deleted: int
    audit_records_purged: int
    documents_deleted: int
    error_message: str | None = None
    failed_users: list[str] | None = None


@dataclass
class RetentionStatus:
    """User data retention status."""

    user_id: str
    is_anonymized: bool
    deletion_scheduled: bool
    deletion_scheduled_at: datetime | None
    deletion_date: datetime | None
    days_until_deletion: int | None
