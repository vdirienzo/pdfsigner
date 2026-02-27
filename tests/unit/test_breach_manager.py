"""
Tests for breach manager.

Tests breach incident management workflow.
"""

from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

import pytest

from pdfsigner.core.audit.audit_event import AuditEventType
from pdfsigner.core.breach.breach_detector import BreachDetector
from pdfsigner.core.breach.breach_manager import BreachManager, BreachManagerError
from pdfsigner.core.breach.breach_repository import BreachRepository
from pdfsigner.core.breach.breach_types import (
    BreachIncident,
    BreachSeverity,
    BreachStatus,
    BreachType,
)


@pytest.fixture
def temp_db():
    """Create temporary database."""
    with TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "breach_test.db"


@pytest.fixture
def repository(temp_db):
    """Create test repository."""
    return BreachRepository(db_path=temp_db)


@pytest.fixture
def detector():
    """Create test detector."""
    return BreachDetector()


@pytest.fixture
def manager(repository, detector):
    """Create test breach manager."""
    return BreachManager(repository=repository, detector=detector)


def test_report_breach_creates_incident(manager):
    """Test report_breach creates and saves incident."""
    incident = manager.report_breach(
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.HIGH,
        description="Large data export detected",
        affected_users=100,
        affected_records=5000,
        user_id="user123",
        source_ip="192.168.1.100",
        metadata={"action": "export"},
    )

    assert incident is not None
    assert incident.breach_type == BreachType.MASS_EXPORT
    assert incident.severity == BreachSeverity.HIGH
    assert incident.status == BreachStatus.DETECTED
    assert incident.affected_users == 100
    assert incident.affected_records == 5000


def test_report_breach_saves_to_repository(manager, repository):
    """Test report_breach saves incident to repository."""
    incident = manager.report_breach(
        breach_type=BreachType.FAILED_AUTH,
        severity=BreachSeverity.MEDIUM,
        description="Multiple failed login attempts",
        affected_users=1,
    )

    # Verify it was saved
    retrieved = repository.get_incident(incident.id)
    assert retrieved is not None
    assert retrieved.id == incident.id
    assert retrieved.breach_type == BreachType.FAILED_AUTH


def test_update_breach_status_updates_incident(manager):
    """Test update_breach_status updates status correctly."""
    # Create incident
    incident = manager.report_breach(
        breach_type=BreachType.BULK_PHI_ACCESS,
        severity=BreachSeverity.HIGH,
        description="Bulk PHI access detected",
    )

    # Update status
    updated = manager.update_breach_status(
        incident_id=incident.id,
        new_status=BreachStatus.INVESTIGATING,
        note="Investigation started",
    )

    assert updated.status == BreachStatus.INVESTIGATING
    assert len(updated.status_history) > 0
    assert updated.status_history[0]["note"] == "Investigation started"


def test_update_breach_status_nonexistent_incident_raises_error(manager):
    """Test update_breach_status raises error for nonexistent incident."""
    with pytest.raises(BreachManagerError, match="not found"):
        manager.update_breach_status(
            incident_id="nonexistent-id",
            new_status=BreachStatus.RESOLVED,
        )


def test_get_active_breaches_returns_unresolved_incidents(manager):
    """Test get_active_breaches returns only unresolved incidents."""
    # Create multiple incidents with different statuses
    incident1 = manager.report_breach(
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.HIGH,
        description="Active breach 1",
    )

    incident2 = manager.report_breach(
        breach_type=BreachType.FAILED_AUTH,
        severity=BreachSeverity.MEDIUM,
        description="Active breach 2",
    )

    incident3 = manager.report_breach(
        breach_type=BreachType.UNUSUAL_HOURS,
        severity=BreachSeverity.LOW,
        description="Resolved breach",
    )

    # Resolve one
    manager.update_breach_status(incident3.id, BreachStatus.RESOLVED)

    # Get active breaches
    active = manager.get_active_breaches()

    # Should have 2 active (not resolved)
    assert len(active) >= 2
    assert any(inc.id == incident1.id for inc in active)
    assert any(inc.id == incident2.id for inc in active)


def test_get_breach_timeline_returns_status_history(manager):
    """Test get_breach_timeline returns status change history."""
    # Create and update incident
    incident = manager.report_breach(
        breach_type=BreachType.EMERGENCY_ACCESS,
        severity=BreachSeverity.HIGH,
        description="Emergency access used",
    )

    manager.update_breach_status(incident.id, BreachStatus.INVESTIGATING, "Started investigation")
    manager.update_breach_status(incident.id, BreachStatus.CONTAINED, "Threat contained")

    # Get timeline
    timeline = manager.get_breach_timeline(incident.id)

    assert len(timeline) == 2
    assert timeline[0]["to_status"] == "investigating"
    assert timeline[1]["to_status"] == "contained"


def test_get_breach_timeline_nonexistent_incident_raises_error(manager):
    """Test get_breach_timeline raises error for nonexistent incident."""
    with pytest.raises(BreachManagerError, match="not found"):
        manager.get_breach_timeline("nonexistent-id")


def test_detect_and_report_creates_incident_if_detected(manager):
    """Test detect_and_report creates incident when breach detected."""
    incident = manager.detect_and_report(
        "mass_export",
        records_count=2000,
        user_id="user123",
        source_ip="192.168.1.100",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.MASS_EXPORT
    assert incident.affected_records == 2000

    # Verify it was saved
    retrieved = manager.get_incident(incident.id)
    assert retrieved is not None


def test_detect_and_report_returns_none_if_no_breach(manager):
    """Test detect_and_report returns None when no breach detected."""
    incident = manager.detect_and_report(
        "mass_export",
        records_count=100,  # Below threshold
    )

    assert incident is None


def test_get_incident_returns_incident(manager):
    """Test get_incident returns incident by ID."""
    incident = manager.report_breach(
        breach_type=BreachType.PRIVILEGE_ESCALATION,
        severity=BreachSeverity.HIGH,
        description="Privilege escalation detected",
    )

    retrieved = manager.get_incident(incident.id)

    assert retrieved is not None
    assert retrieved.id == incident.id


def test_get_incident_returns_none_if_not_found(manager):
    """Test get_incident returns None for nonexistent ID."""
    retrieved = manager.get_incident("nonexistent-id")

    assert retrieved is None


def test_list_incidents_with_filters(manager):
    """Test list_incidents with various filters."""
    # Create incidents with different properties
    manager.report_breach(
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.HIGH,
        description="High severity breach",
        user_id="user123",
    )

    manager.report_breach(
        breach_type=BreachType.FAILED_AUTH,
        severity=BreachSeverity.MEDIUM,
        description="Medium severity breach",
        user_id="user456",
    )

    # Filter by severity
    high_severity = manager.list_incidents(severity=BreachSeverity.HIGH)
    assert len(high_severity) >= 1
    assert all(inc.severity == BreachSeverity.HIGH for inc in high_severity)

    # Filter by user
    user_incidents = manager.list_incidents(user_id="user123")
    assert len(user_incidents) >= 1
    assert all(inc.user_id == "user123" for inc in user_incidents)


def test_list_incidents_with_date_range(manager):
    """Test list_incidents with date range filter."""
    now = datetime.now()

    # Create incident
    manager.report_breach(
        breach_type=BreachType.UNUSUAL_HOURS,
        severity=BreachSeverity.LOW,
        description="Recent breach",
    )

    # Query with date range
    from datetime import timedelta

    start = now - timedelta(hours=1)
    end = now + timedelta(hours=1)

    incidents = manager.list_incidents(start_date=start, end_date=end)

    assert len(incidents) >= 1


def test_list_incidents_respects_pagination(manager):
    """Test list_incidents respects limit and offset."""
    # Create multiple incidents
    for i in range(5):
        manager.report_breach(
            breach_type=BreachType.MASS_EXPORT,
            severity=BreachSeverity.LOW,
            description=f"Breach {i}",
        )

    # Get first 2
    page1 = manager.list_incidents(limit=2, offset=0)
    assert len(page1) == 2

    # Get next 2
    page2 = manager.list_incidents(limit=2, offset=2)
    assert len(page2) == 2

    # Should be different incidents
    page1_ids = {inc.id for inc in page1}
    page2_ids = {inc.id for inc in page2}
    assert page1_ids.isdisjoint(page2_ids)


def test_log_breach_event_propagates_audit_logger_exception():
    """Test _log_breach_event propagates exceptions from audit logger.

    GDPR Art. 33 requires breach notifications to have a reliable audit trail.
    If audit logging fails, the caller must know — silencing the error could
    cause a breach to be reported as "successful" without an audit record.
    """
    manager = BreachManager.__new__(BreachManager)
    manager.audit_logger = MagicMock()
    manager.audit_logger.log_event.side_effect = OSError("Disk full - audit log write failed")

    incident = BreachIncident(
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.HIGH,
        status=BreachStatus.DETECTED,
        description="Test breach",
        affected_users=10,
        affected_records=100,
    )

    with pytest.raises(OSError, match="Disk full"):
        manager._log_breach_event(
            event_type=AuditEventType.SYSTEM_EVENT,
            incident=incident,
            status="DETECTED",
        )


def test_report_breach_raises_when_audit_logging_fails():
    """Test report_breach wraps audit failure as BreachManagerError.

    When _log_breach_event propagates an exception, report_breach's
    own try/except converts it to BreachManagerError, ensuring the
    caller knows the breach report is incomplete.
    """

    repo = MagicMock()
    repo.save_incident.return_value = BreachIncident(
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.HIGH,
        status=BreachStatus.DETECTED,
        description="Test",
    )

    manager = BreachManager.__new__(BreachManager)
    manager.repository = repo
    manager.audit_logger = MagicMock()
    manager.audit_logger.log_event.side_effect = OSError("Audit write failed")

    with pytest.raises(BreachManagerError, match="Failed to report breach"):
        manager.report_breach(
            breach_type=BreachType.MASS_EXPORT,
            severity=BreachSeverity.HIGH,
            description="Test breach",
        )
