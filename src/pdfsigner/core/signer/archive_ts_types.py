"""Type definitions for archive timestamp scheduling.

Contains dataclasses used by the archive timestamp scheduler and storage.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class RegisteredPDF:
    """Information about a registered PDF for monitoring."""

    pdf_path: Path
    registered_at: datetime
    last_checked_at: datetime | None
    last_timestamp_at: datetime | None
    check_interval_days: int
    hash_sha256: str | None = None


@dataclass
class PendingPDF:
    """PDF that needs a new archive timestamp."""

    pdf_path: Path
    # Reason: "no_timestamp", "expired", "weak_algorithm",
    # "algorithm_approaching_deprecation", "not_found"
    reason: str


__all__ = [
    "PendingPDF",
    "RegisteredPDF",
]
