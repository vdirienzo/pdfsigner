"""
evidence_access_collector.py - Access-related evidence collection for SOC 2

Handles CC6 (Logical Access) evidence collection:
- Access logs (CC6.1)
- User access reviews (CC6.3)
- Quarterly access reviews (CC6)
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.compliance.evidence_types import (
    Evidence,
    EvidenceCategory,
    EvidenceType,
)
from pdfsigner.core.users.user_repository import UserRepository

_COLLECTOR_METADATA = {"collector": "EvidenceCollector", "version": "1.0"}


def _build_access_summary(events: list) -> dict[str, Any]:
    """Build access event summary for CC6 evidence."""
    return {
        "total_events": len(events),
        "unique_users": len(set(e.user_id for e in events if e.user_id)),
        "success_count": sum(1 for e in events if e.status == "SUCCESS"),
        "failure_count": sum(1 for e in events if e.status == "FAILURE"),
        "event_types": _count_by_field(events, lambda e: e.event_type.value),
    }


def _count_by_field(items: list, field_getter) -> dict[str, int]:
    """Count items grouped by a field value extracted via field_getter."""
    counts: dict[str, int] = {}
    for item in items:
        key = field_getter(item)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _build_user_review_data(users: list) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build user data list and summary for CC6 user access review.

    Returns:
        Tuple of (user_data_list, summary_dict)
    """
    user_data = [
        {
            "user_id": user.id,
            "username": user.username,
            "role": user.role.value,
            "status": user.status.value,
            "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
            "created_at": user.created_at.isoformat(),
            "has_certificate": bool(user.certificate_serial),
        }
        for user in users
    ]

    summary: dict[str, Any] = {
        "total_users": len(users),
        "active_users": sum(1 for u in users if u.status.value == "active"),
        "inactive_users": sum(1 for u in users if u.status.value == "inactive"),
        "locked_users": sum(1 for u in users if u.status.value == "locked"),
        "users_with_certificates": sum(1 for u in users if u.certificate_serial),
        "roles": _count_by_field(users, lambda u: u.role.value),
    }

    return user_data, summary


def _get_quarter_dates(quarter: int, year: int) -> tuple[datetime, datetime]:
    """Calculate start and end dates for a fiscal quarter.

    Args:
        quarter: Quarter number (1-4)
        year: Year

    Returns:
        Tuple of (period_start, period_end)
    """
    quarter_start_months = {1: 1, 2: 4, 3: 7, 4: 10}
    start_month = quarter_start_months[quarter]
    end_month = start_month + 2

    period_start = datetime(year, start_month, 1)
    if end_month == 12:
        period_end = datetime(year, 12, 31, 23, 59, 59)
    else:
        period_end = datetime(year, end_month + 1, 1) - timedelta(seconds=1)

    return period_start, period_end


class EvidenceAccessCollector:
    """
    Collects access-related compliance evidence for SOC 2 Type II audits (CC6).

    Handles:
    - Access log collection (CC6.1)
    - User access reviews (CC6.3)
    - Quarterly access reviews
    """

    def __init__(
        self,
        audit_logger: AuditLogger,
        user_repository: UserRepository | None = None,
    ):
        self.audit_logger = audit_logger
        self.user_repository = user_repository

    def _load_events(self, start_date: datetime, end_date: datetime, events: list | None) -> list:
        """Load events from audit logger if not pre-loaded."""
        if events is not None:
            return events
        return self.audit_logger.get_events(start_date=start_date, end_date=end_date)

    def collect_access_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        events: list | None = None,
    ) -> Evidence:
        """
        Collect access logs for CC6.1 (Logical Access Controls).

        Args:
            start_date: Start of period
            end_date: End of period
            events: Pre-loaded events (avoids redundant audit queries)

        Returns:
            Evidence with access log data
        """
        events = self._load_events(start_date, end_date, events)
        access_summary = _build_access_summary(events)

        return Evidence(
            id=str(uuid.uuid4()),
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.ACCESS_LOG,
            title=f"Access Logs ({start_date.date()} to {end_date.date()})",
            description=(
                f"System access logs showing {len(events)} events from "
                f"{access_summary['unique_users']} users"
            ),
            collected_at=datetime.now(UTC),
            period_start=start_date,
            period_end=end_date,
            data={
                "summary": access_summary,
                "sample_events": [e.to_dict() for e in events[:10]],
            },
            metadata=_COLLECTOR_METADATA,
        )

    def collect_user_access_review(self) -> Evidence:
        """
        Collect user access review data for CC6.3 (User Access Provisioning).

        Returns:
            Evidence with user access review
        """
        now = datetime.now(UTC)

        if not self.user_repository:
            return Evidence(
                id=str(uuid.uuid4()),
                category=EvidenceCategory.CC6_LOGICAL_ACCESS,
                evidence_type=EvidenceType.USER_ACCESS_REVIEW,
                title=f"User Access Review ({now.date()})",
                description="User repository not configured",
                collected_at=now,
                period_start=now,
                period_end=now,
                data={"users": [], "summary": {"total_users": 0}},
                metadata=_COLLECTOR_METADATA,
            )

        users = self.user_repository.list_users(limit=1000)
        user_data, summary = _build_user_review_data(users)

        return Evidence(
            id=str(uuid.uuid4()),
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.USER_ACCESS_REVIEW,
            title=f"User Access Review ({now.date()})",
            description=f"Review of {len(users)} user accounts and access permissions",
            collected_at=now,
            period_start=now,
            period_end=now,
            data={"users": user_data, "summary": summary},
            metadata=_COLLECTOR_METADATA,
        )

    def generate_quarterly_access_review(
        self,
        quarter: int = 1,
        year: int | None = None,
    ) -> Evidence:
        """
        Generate quarterly user access review for CC6.

        Args:
            quarter: Quarter number (1-4)
            year: Year (default: current year)

        Returns:
            Evidence with quarterly access review
        """
        if year is None:
            year = datetime.now(UTC).year

        period_start, period_end = _get_quarter_dates(quarter, year)
        access_evidence = self.collect_access_logs(period_start, period_end)
        user_evidence = self.collect_user_access_review()

        return Evidence(
            id=str(uuid.uuid4()),
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.USER_ACCESS_REVIEW,
            title=f"Q{quarter} {year} User Access Review",
            description=f"Quarterly access review for Q{quarter} {year}",
            collected_at=datetime.now(UTC),
            period_start=period_start,
            period_end=period_end,
            data={
                "quarter": quarter,
                "year": year,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "access_logs": access_evidence.data,
                "user_review": user_evidence.data,
            },
            metadata={
                **_COLLECTOR_METADATA,
                "quarter": quarter,
                "year": year,
            },
        )


__all__ = [
    "EvidenceAccessCollector",
]
