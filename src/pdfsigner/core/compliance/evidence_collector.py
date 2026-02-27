"""
evidence_collector.py - SOC 2 evidence collection engine

Collects evidence from various sources (audit logs, user registry, config)
to support SOC 2 Type II compliance audits.

Evidence Sources:
- AuditLogger: Access and audit logs (CC6, CC7)
- UserRepository: User access reviews (CC6)
- Settings: Configuration snapshots (CC5, CC7)
- Incident tracking: Security incidents (CC9)
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from loguru import logger

from pdfsigner.config.settings import Settings, get_settings
from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.compliance.evidence_types import (
    Evidence,
    EvidenceCategory,
    EvidenceCollection,
    EvidenceType,
)
from pdfsigner.core.users.user_repository import UserRepository

_COLLECTOR_METADATA = {"collector": "EvidenceCollector", "version": "1.0"}


def _count_events_by_type(events: list, event_type: str) -> int:
    """Count events matching a specific event_type value."""
    return sum(1 for e in events if e.event_type.value == event_type)


def _count_events_by_types(events: list, event_types: set[str]) -> dict[str, int]:
    """Count events grouped by event_type for the specified types."""
    counts: dict[str, int] = {}
    for e in events:
        t = e.event_type.value
        if t in event_types:
            counts[t] = counts.get(t, 0) + 1
    return counts


def _count_by_field(items: list, field_getter) -> dict[str, int]:
    """Count items grouped by a field value extracted via field_getter."""
    counts: dict[str, int] = {}
    for item in items:
        key = field_getter(item)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _build_access_summary(events: list) -> dict[str, Any]:
    """Build access event summary for CC6 evidence."""
    return {
        "total_events": len(events),
        "unique_users": len(set(e.user_id for e in events if e.user_id)),
        "success_count": sum(1 for e in events if e.status == "SUCCESS"),
        "failure_count": sum(1 for e in events if e.status == "FAILURE"),
        "event_types": _count_by_field(events, lambda e: e.event_type.value),
    }


def _build_audit_analysis(events: list, start_date: datetime, end_date: datetime) -> dict[str, Any]:
    """Build audit completeness analysis for CC7 evidence."""
    days = max((end_date - start_date).days, 1)
    return {
        "total_events": len(events),
        "date_range_days": (end_date - start_date).days,
        "events_per_day": len(events) / days,
        "phi_access_events": sum(1 for e in events if e.phi_accessed),
        "encryption_events": sum(
            1
            for e in events
            if "encrypt" in e.event_type.value.lower() or "decrypt" in e.event_type.value.lower()
        ),
        "signature_events": sum(1 for e in events if "sign" in e.event_type.value.lower()),
    }


def _build_config_data(settings: Settings, audit_logger: AuditLogger) -> dict[str, Any]:
    """Extract compliance-relevant configuration settings."""
    return {
        "security": {
            "encryption_enabled": getattr(settings, "encryption_enabled", False),
            "encryption_strength": getattr(settings, "encryption_strength", "aes256"),
            "fips_mode_enabled": getattr(settings, "fips_mode_enabled", False),
            "tls_enabled": getattr(settings, "tls_enabled", False),
            "tls_min_version": getattr(settings, "tls_min_version", "TLSv1.2"),
        },
        "access_control": {
            "rbac_enabled": True,  # Always enabled in current implementation
            "mfa_enabled": getattr(settings, "mfa_enabled", False),
            "session_timeout_minutes": getattr(settings, "healthcare_session_timeout_minutes", 15),
            "max_sessions_per_user": getattr(settings, "healthcare_max_sessions", 3),
        },
        "audit": {
            "audit_enabled": True,  # Always enabled
            "audit_integrity_enabled": getattr(settings, "sign_events", False),
            "retention_days": getattr(audit_logger, "retention_days", 90),
        },
        "compliance_mode": {
            "healthcare_mode": getattr(settings, "healthcare_mode", False),
            "hipaa_compliant": getattr(settings, "encryption_hipaa_mode", False),
        },
    }


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


def _build_incident_data(events: list) -> tuple[list[dict], dict[str, Any]]:
    """Build incident list and summary for CC9 evidence.

    Returns:
        Tuple of (incidents_list, summary_dict)
    """
    incidents = [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "user_id": event.user_id,
            "error_message": event.error_message,
            "severity": "high" if event.phi_accessed else "medium",
        }
        for event in events
    ]

    summary: dict[str, Any] = {
        "total_incidents": len(incidents),
        "high_severity": sum(1 for i in incidents if i["severity"] == "high"),
        "medium_severity": sum(1 for i in incidents if i["severity"] == "medium"),
        "incident_types": _count_by_field(incidents, lambda i: i["event_type"]),
    }

    return incidents, summary


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


def _build_collection_summary(evidence_items: list[Evidence]) -> dict[str, Any]:
    """Build summary statistics for an evidence collection."""
    summary: dict[str, Any] = {
        "total_evidence": len(evidence_items),
        "by_category": {},
        "by_type": {},
    }

    for evidence in evidence_items:
        cat = evidence.category.value
        typ = evidence.evidence_type.value
        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
        summary["by_type"][typ] = summary["by_type"].get(typ, 0) + 1

    return summary


class EvidenceCollector:
    """
    Collects compliance evidence for SOC 2 Type II audits.

    Integrates with existing system components to gather evidence:
    - Audit logs for access and activity monitoring
    - User registry for access control reviews
    - System configuration for control verification
    """

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
        user_repository: UserRepository | None = None,
        settings: Settings | None = None,
    ):
        """
        Initialize evidence collector.

        Args:
            audit_logger: Audit logger instance (default: singleton)
            user_repository: User repository instance (default: singleton)
            settings: Settings instance (default: singleton)
        """
        self.audit_logger = audit_logger or AuditLogger.get_instance()
        self.user_repository = user_repository
        self.settings = settings or get_settings()

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

    def collect_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        events: list | None = None,
    ) -> Evidence:
        """
        Collect audit logs for CC7.2 (System Monitoring).

        Args:
            start_date: Start of period
            end_date: End of period
            events: Pre-loaded events (avoids redundant audit queries)

        Returns:
            Evidence with audit log data
        """
        events = self._load_events(start_date, end_date, events)
        audit_analysis = _build_audit_analysis(events, start_date, end_date)

        return Evidence(
            id=str(uuid.uuid4()),
            category=EvidenceCategory.CC7_SYSTEM_OPERATIONS,
            evidence_type=EvidenceType.AUDIT_LOG,
            title=f"Audit Trail ({start_date.date()} to {end_date.date()})",
            description=(
                f"Complete audit trail with {len(events)} events over "
                f"{audit_analysis['date_range_days']} days"
            ),
            collected_at=datetime.now(UTC),
            period_start=start_date,
            period_end=end_date,
            data={
                "analysis": audit_analysis,
                "sample_events": [e.to_dict() for e in events[:20]],
            },
            metadata=_COLLECTOR_METADATA,
        )

    def collect_config_snapshot(self) -> Evidence:
        """
        Collect current system configuration for CC5 (Control Activities).

        Returns:
            Evidence with configuration snapshot
        """
        config_data = _build_config_data(self.settings, self.audit_logger)
        config_json = json.dumps(config_data, sort_keys=True)
        checksum = hashlib.sha256(config_json.encode()).hexdigest()
        now = datetime.now(UTC)

        return Evidence(
            id=str(uuid.uuid4()),
            category=EvidenceCategory.CC5_CONTROL_ACTIVITIES,
            evidence_type=EvidenceType.CONFIG_SNAPSHOT,
            title=f"System Configuration Snapshot ({now.date()})",
            description="Current system security and compliance configuration settings",
            collected_at=now,
            period_start=now,
            period_end=now,
            data=config_data,
            checksum=checksum,
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

    def collect_incident_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        events: list | None = None,
    ) -> Evidence:
        """
        Collect security incident logs for CC9 (Risk Mitigation).

        Args:
            start_date: Start of period
            end_date: End of period
            events: Pre-loaded events (avoids redundant audit queries).
                    If provided, only FAILURE events will be used.

        Returns:
            Evidence with incident log data
        """
        if events is not None:
            events = [e for e in events if e.status == "FAILURE"]
        else:
            events = self.audit_logger.get_events_filtered(
                start_date=start_date,
                end_date=end_date,
                status="FAILURE",
            )

        incidents, summary = _build_incident_data(events)

        return Evidence(
            id=str(uuid.uuid4()),
            category=EvidenceCategory.CC9_RISK_MITIGATION,
            evidence_type=EvidenceType.INCIDENT_LOG,
            title=f"Security Incidents ({start_date.date()} to {end_date.date()})",
            description=f"Security incident log with {len(incidents)} incidents",
            collected_at=datetime.now(UTC),
            period_start=start_date,
            period_end=end_date,
            data={"incidents": incidents, "summary": summary},
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

    def collect_all_evidence(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> EvidenceCollection:
        """
        Collect all evidence for a period.

        Args:
            period_start: Start of observation period
            period_end: End of observation period

        Returns:
            EvidenceCollection with all collected evidence
        """
        logger.info(f"Collecting evidence from {period_start} to {period_end}")

        collection = EvidenceCollection(
            period_start=period_start,
            period_end=period_end,
            collected_at=datetime.now(UTC),
        )

        try:
            # Load events once to avoid redundant audit queries
            all_events = self.audit_logger.get_events(start_date=period_start, end_date=period_end)

            # CC6 - Logical Access
            logger.debug("Collecting access logs (CC6)")
            collection.add_evidence(
                self.collect_access_logs(period_start, period_end, events=all_events)
            )

            logger.debug("Collecting user access review (CC6)")
            collection.add_evidence(self.collect_user_access_review())

            # CC7 - System Operations
            logger.debug("Collecting audit logs (CC7)")
            collection.add_evidence(
                self.collect_audit_logs(period_start, period_end, events=all_events)
            )

            # CC5 - Control Activities
            logger.debug("Collecting config snapshot (CC5)")
            collection.add_evidence(self.collect_config_snapshot())

            # CC9 - Risk Mitigation
            logger.debug("Collecting incident logs (CC9)")
            collection.add_evidence(
                self.collect_incident_logs(period_start, period_end, events=all_events)
            )

            collection.summary = _build_collection_summary(collection.evidence_items)
            logger.info(f"Collected {len(collection.evidence_items)} evidence items")

        except Exception as e:
            logger.error(f"Error collecting evidence: {e}")
            raise

        return collection


# Singleton instance
_evidence_collector: EvidenceCollector | None = None


def get_evidence_collector() -> EvidenceCollector:
    """Get singleton evidence collector."""
    global _evidence_collector
    if _evidence_collector is None:
        _evidence_collector = EvidenceCollector()
    return _evidence_collector


__all__ = [
    "EvidenceCollector",
    "get_evidence_collector",
]
