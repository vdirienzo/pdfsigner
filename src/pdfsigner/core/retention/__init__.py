"""
Data retention automation for HIPAA compliance.

This module provides automated data retention and cleanup capabilities:
- Policy-based retention management
- Automatic cleanup of expired data
- Audit log archiving (6-year HIPAA requirement)
- Scheduled retention runs

HIPAA Reference: SS164.530(j) - 6-year retention requirement for audit logs
"""

from pdfsigner.core.retention.retention_manager import (
    RetentionManager,
    get_retention_manager,
)
from pdfsigner.core.retention.retention_types import (
    RetentionAction,
    RetentionPolicy,
    RetentionResult,
    RetentionTarget,
)

__all__ = [
    "RetentionAction",
    "RetentionManager",
    "RetentionPolicy",
    "RetentionResult",
    "RetentionTarget",
    "get_retention_manager",
]
