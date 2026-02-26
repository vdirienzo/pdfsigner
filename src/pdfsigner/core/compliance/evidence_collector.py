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

    def collect_access_logs(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Evidence:
        """
        Collect access logs for CC6.1 (Logical Access Controls).

        Args:
            start_date: Start of period
            end_date: End of period

        Returns:
            Evidence with access log data
        """
        events = self.audit_logger.get_events(start_date=start_date, end_date=end_date)

        # Summarize access events
        access_summary = {
            "total_events": len(events),
            "unique_users": len(set(e.user_id for e in events if e.user_id)),
            "success_count": sum(1 for e in events if e.status == "SUCCESS"),
            "failure_count": sum(1 for e in events if e.status == "FAILURE"),
            "event_types": {},
        }

        # Count by event type
        for event in events:
            event_type = event.event_type.value
            access_summary["event_types"][event_type] = (
                access_summary["event_types"].get(event_type, 0) + 1
            )

        # Create evidence
        evidence_id = str(uuid.uuid4())
        evidence_data = {
            "summary": access_summary,
            "sample_events": [e.to_dict() for e in events[:10]],  # First 10 as sample
        }

        return Evidence(
            id=evidence_id,
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
            data=evidence_data,
            metadata={"collector": "EvidenceCollector", "version": "1.0"},
        )

    def collect_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Evidence:
        """
        Collect audit logs for CC7.2 (System Monitoring).

        Args:
            start_date: Start of period
            end_date: End of period

        Returns:
            Evidence with audit log data
        """
        events = self.audit_logger.get_events(start_date=start_date, end_date=end_date)

        # Analyze audit completeness
        audit_analysis = {
            "total_events": len(events),
            "date_range_days": (end_date - start_date).days,
            "events_per_day": len(events) / max((end_date - start_date).days, 1),
            "phi_access_events": sum(1 for e in events if e.phi_accessed),
            "encryption_events": sum(
                1
                for e in events
                if "encrypt" in e.event_type.value.lower()
                or "decrypt" in e.event_type.value.lower()
            ),
            "signature_events": sum(1 for e in events if "sign" in e.event_type.value.lower()),
        }

        evidence_id = str(uuid.uuid4())
        evidence_data = {
            "analysis": audit_analysis,
            "sample_events": [e.to_dict() for e in events[:20]],
        }

        return Evidence(
            id=evidence_id,
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
            data=evidence_data,
            metadata={"collector": "EvidenceCollector", "version": "1.0"},
        )

    def collect_config_snapshot(self) -> Evidence:
        """
        Collect current system configuration for CC5 (Control Activities).

        Returns:
            Evidence with configuration snapshot
        """
        # Extract relevant settings for compliance
        config_data = {
            "security": {
                "encryption_enabled": getattr(self.settings, "encryption_enabled", False),
                "encryption_strength": getattr(self.settings, "encryption_strength", "aes256"),
                "fips_mode_enabled": getattr(self.settings, "fips_mode_enabled", False),
                "tls_enabled": getattr(self.settings, "tls_enabled", False),
                "tls_min_version": getattr(self.settings, "tls_min_version", "TLSv1.2"),
            },
            "access_control": {
                "rbac_enabled": True,  # Always enabled in current implementation
                "mfa_enabled": getattr(self.settings, "mfa_enabled", False),
                "session_timeout_minutes": getattr(
                    self.settings, "healthcare_session_timeout_minutes", 15
                ),
                "max_sessions_per_user": getattr(self.settings, "healthcare_max_sessions", 3),
            },
            "audit": {
                "audit_enabled": True,  # Always enabled
                "audit_integrity_enabled": getattr(self.settings, "sign_events", False),
                "retention_days": getattr(self.audit_logger, "retention_days", 90),
            },
            "compliance_mode": {
                "healthcare_mode": getattr(self.settings, "healthcare_mode", False),
                "hipaa_compliant": getattr(self.settings, "encryption_hipaa_mode", False),
            },
        }

        # Calculate config checksum
        config_json = json.dumps(config_data, sort_keys=True)
        checksum = hashlib.sha256(config_json.encode()).hexdigest()

        evidence_id = str(uuid.uuid4())
        now = datetime.now(UTC)

        return Evidence(
            id=evidence_id,
            category=EvidenceCategory.CC5_CONTROL_ACTIVITIES,
            evidence_type=EvidenceType.CONFIG_SNAPSHOT,
            title=f"System Configuration Snapshot ({now.date()})",
            description="Current system security and compliance configuration settings",
            collected_at=now,
            period_start=now,
            period_end=now,
            data=config_data,
            checksum=checksum,
            metadata={"collector": "EvidenceCollector", "version": "1.0"},
        )

    def collect_user_access_review(self) -> Evidence:
        """
        Collect user access review data for CC6.3 (User Access Provisioning).

        Returns:
            Evidence with user access review
        """
        if not self.user_repository:
            # Create empty evidence if no user repository
            evidence_id = str(uuid.uuid4())
            now = datetime.now(UTC)
            return Evidence(
                id=evidence_id,
                category=EvidenceCategory.CC6_LOGICAL_ACCESS,
                evidence_type=EvidenceType.USER_ACCESS_REVIEW,
                title=f"User Access Review ({now.date()})",
                description="User repository not configured",
                collected_at=now,
                period_start=now,
                period_end=now,
                data={"users": [], "summary": {"total_users": 0}},
                metadata={"collector": "EvidenceCollector", "version": "1.0"},
            )

        # Get all users
        users = self.user_repository.list_users(limit=1000)

        # Analyze user access
        user_data = []
        for user in users:
            user_data.append(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "role": user.role.value,
                    "status": user.status.value,
                    "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                    "created_at": user.created_at.isoformat(),
                    "has_certificate": bool(user.certificate_serial),
                }
            )

        summary = {
            "total_users": len(users),
            "active_users": sum(1 for u in users if u.status.value == "active"),
            "inactive_users": sum(1 for u in users if u.status.value == "inactive"),
            "locked_users": sum(1 for u in users if u.status.value == "locked"),
            "users_with_certificates": sum(1 for u in users if u.certificate_serial),
            "roles": {},
        }

        # Count by role
        for user in users:
            role = user.role.value
            summary["roles"][role] = summary["roles"].get(role, 0) + 1

        evidence_id = str(uuid.uuid4())
        now = datetime.now(UTC)

        return Evidence(
            id=evidence_id,
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.USER_ACCESS_REVIEW,
            title=f"User Access Review ({now.date()})",
            description=f"Review of {len(users)} user accounts and access permissions",
            collected_at=now,
            period_start=now,
            period_end=now,
            data={"users": user_data, "summary": summary},
            metadata={"collector": "EvidenceCollector", "version": "1.0"},
        )

    def collect_incident_logs(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Evidence:
        """
        Collect security incident logs for CC9 (Risk Mitigation).

        Args:
            start_date: Start of period
            end_date: End of period

        Returns:
            Evidence with incident log data
        """
        # Get failure and error events from audit log
        events = self.audit_logger.get_events_filtered(
            start_date=start_date,
            end_date=end_date,
            status="FAILURE",
        )

        # Categorize incidents
        incidents = []
        for event in events:
            incident = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "user_id": event.user_id,
                "error_message": event.error_message,
                "severity": "high" if event.phi_accessed else "medium",
            }
            incidents.append(incident)

        summary = {
            "total_incidents": len(incidents),
            "high_severity": sum(1 for i in incidents if i["severity"] == "high"),
            "medium_severity": sum(1 for i in incidents if i["severity"] == "medium"),
            "incident_types": {},
        }

        # Count by type
        for incident in incidents:
            incident_type = incident["event_type"]
            summary["incident_types"][incident_type] = (
                summary["incident_types"].get(incident_type, 0) + 1
            )

        evidence_id = str(uuid.uuid4())

        return Evidence(
            id=evidence_id,
            category=EvidenceCategory.CC9_RISK_MITIGATION,
            evidence_type=EvidenceType.INCIDENT_LOG,
            title=f"Security Incidents ({start_date.date()} to {end_date.date()})",
            description=f"Security incident log with {len(incidents)} incidents",
            collected_at=datetime.now(UTC),
            period_start=start_date,
            period_end=end_date,
            data={"incidents": incidents, "summary": summary},
            metadata={"collector": "EvidenceCollector", "version": "1.0"},
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

        # Calculate quarter dates
        quarter_start_months = {1: 1, 2: 4, 3: 7, 4: 10}
        start_month = quarter_start_months[quarter]
        end_month = start_month + 2

        period_start = datetime(year, start_month, 1)
        if end_month == 12:
            period_end = datetime(year, 12, 31, 23, 59, 59)
        else:
            period_end = datetime(year, end_month + 1, 1) - timedelta(seconds=1)

        # Collect access logs for the quarter
        access_evidence = self.collect_access_logs(period_start, period_end)

        # Collect user access review
        user_evidence = self.collect_user_access_review()

        # Combine into quarterly review
        quarterly_data = {
            "quarter": quarter,
            "year": year,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "access_logs": access_evidence.data,
            "user_review": user_evidence.data,
        }

        evidence_id = str(uuid.uuid4())

        return Evidence(
            id=evidence_id,
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.USER_ACCESS_REVIEW,
            title=f"Q{quarter} {year} User Access Review",
            description=f"Quarterly access review for Q{quarter} {year}",
            collected_at=datetime.now(UTC),
            period_start=period_start,
            period_end=period_end,
            data=quarterly_data,
            metadata={
                "collector": "EvidenceCollector",
                "version": "1.0",
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
            # CC6 - Logical Access
            logger.debug("Collecting access logs (CC6)")
            collection.add_evidence(self.collect_access_logs(period_start, period_end))

            logger.debug("Collecting user access review (CC6)")
            collection.add_evidence(self.collect_user_access_review())

            # CC7 - System Operations
            logger.debug("Collecting audit logs (CC7)")
            collection.add_evidence(self.collect_audit_logs(period_start, period_end))

            # CC5 - Control Activities
            logger.debug("Collecting config snapshot (CC5)")
            collection.add_evidence(self.collect_config_snapshot())

            # CC9 - Risk Mitigation
            logger.debug("Collecting incident logs (CC9)")
            collection.add_evidence(self.collect_incident_logs(period_start, period_end))

            # Generate summary
            collection.summary = {
                "total_evidence": len(collection.evidence_items),
                "by_category": {},
                "by_type": {},
            }

            for evidence in collection.evidence_items:
                cat = evidence.category.value
                typ = evidence.evidence_type.value
                collection.summary["by_category"][cat] = (
                    collection.summary["by_category"].get(cat, 0) + 1
                )
                collection.summary["by_type"][typ] = collection.summary["by_type"].get(typ, 0) + 1

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
