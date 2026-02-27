"""
evidence_collector.py - SOC 2 evidence collection engine

Collects evidence from various sources (audit logs, user registry, config)
to support SOC 2 Type II compliance audits.

Evidence Sources:
- AuditLogger: Access and audit logs (CC6, CC7)
- UserRepository: User access reviews (CC6) -- delegated to EvidenceAccessCollector
- Settings: Configuration snapshots (CC5, CC7)
- Incident tracking: Security incidents (CC9)
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from loguru import logger

from pdfsigner.config.settings import Settings, get_settings
from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.compliance.evidence_access_collector import EvidenceAccessCollector
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

    Orchestrates evidence collection across multiple sources:
    - Access-related evidence (CC6) is delegated to EvidenceAccessCollector
    - Audit logs, config snapshots, and incident logs are handled directly
    """

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
        user_repository: UserRepository | None = None,
        settings: Settings | None = None,
    ):
        self.audit_logger = audit_logger or AuditLogger.get_instance()
        self.user_repository = user_repository
        self.settings = settings or get_settings()
        self._access_collector = EvidenceAccessCollector(
            audit_logger=self.audit_logger,
            user_repository=self.user_repository,
        )

    def _load_events(self, start_date: datetime, end_date: datetime, events: list | None) -> list:
        """Load events from audit logger if not pre-loaded."""
        if events is not None:
            return events
        return self.audit_logger.get_events(start_date=start_date, end_date=end_date)

    # -- CC6 access methods (delegated to EvidenceAccessCollector) --

    def collect_access_logs(
        self, start_date: datetime, end_date: datetime, events: list | None = None
    ) -> Evidence:
        """Collect access logs for CC6.1. Delegates to EvidenceAccessCollector."""
        return self._access_collector.collect_access_logs(start_date, end_date, events)

    def collect_user_access_review(self) -> Evidence:
        """Collect user access review for CC6.3. Delegates to EvidenceAccessCollector."""
        return self._access_collector.collect_user_access_review()

    def generate_quarterly_access_review(
        self, quarter: int = 1, year: int | None = None
    ) -> Evidence:
        """Generate quarterly access review for CC6. Delegates to EvidenceAccessCollector."""
        return self._access_collector.generate_quarterly_access_review(quarter, year)

    # -- CC7 audit logs --

    def collect_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        events: list | None = None,
    ) -> Evidence:
        """Collect audit logs for CC7.2 (System Monitoring)."""
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

    # -- CC5 config snapshot --

    def collect_config_snapshot(self) -> Evidence:
        """Collect current system configuration for CC5 (Control Activities)."""
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

    # -- CC9 incident logs --

    def collect_incident_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        events: list | None = None,
    ) -> Evidence:
        """Collect security incident logs for CC9 (Risk Mitigation)."""
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

    # -- Collect all --

    def collect_all_evidence(
        self, period_start: datetime, period_end: datetime
    ) -> EvidenceCollection:
        """Collect all evidence for a period."""
        logger.info(f"Collecting evidence from {period_start} to {period_end}")

        collection = EvidenceCollection(
            period_start=period_start,
            period_end=period_end,
            collected_at=datetime.now(UTC),
        )

        try:
            all_events = self.audit_logger.get_events(start_date=period_start, end_date=period_end)

            # CC6 - Logical Access (delegated)
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
