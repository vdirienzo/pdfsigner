"""
Data retention automation for HIPAA compliance.

This module provides automated data retention and cleanup capabilities:
- Policy-based retention management
- Automatic cleanup of expired data
- Audit log archiving (6-year HIPAA requirement)
- Scheduled retention runs

HIPAA Reference: §164.530(j) - 6-year retention requirement for audit logs
"""

from pdfsigner.core.retention.retention_manager import (
    RetentionAction,
    RetentionManager,
    RetentionPolicy,
    RetentionResult,
    RetentionTarget,
    get_retention_manager,
)

__all__ = [
    "RetentionAction",
    "RetentionManager",
    "RetentionPolicy",
    "RetentionResult",
    "RetentionTarget",
    "get_retention_manager",
]
