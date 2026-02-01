"""
Tests for breach detector.

Tests breach detection rules and thresholds.
"""

from datetime import datetime

import pytest

from pdfsigner.core.breach.breach_detector import BreachDetector
from pdfsigner.core.breach.breach_types import BreachSeverity, BreachStatus, BreachType


@pytest.fixture
def detector():
    """Create breach detector with default thresholds."""
    return BreachDetector(
        mass_export_threshold=1000,
        failed_auth_threshold=10,
        bulk_phi_threshold=100,
        unusual_hour_start=22,
        unusual_hour_end=6,
    )


def test_check_mass_export_below_threshold_returns_none(detector):
    """Test mass export below threshold returns None."""
    incident = detector.check_mass_export(
        records_count=500,
        user_id="user123",
        source_ip="192.168.1.100",
    )

    assert incident is None


def test_check_mass_export_above_threshold_creates_incident(detector):
    """Test mass export above threshold creates incident."""
    incident = detector.check_mass_export(
        records_count=1500,
        user_id="user123",
        source_ip="192.168.1.100",
        metadata={"action": "bulk_download"},
    )

    assert incident is not None
    assert incident.breach_type == BreachType.MASS_EXPORT
    assert incident.status == BreachStatus.DETECTED
    assert incident.affected_records == 1500
    assert incident.user_id == "user123"
    assert incident.source_ip == "192.168.1.100"


def test_check_mass_export_calculates_severity_correctly(detector):
    """Test mass export severity calculation."""
    # Low severity
    low = detector.check_mass_export(records_count=1500)
    assert low.severity == BreachSeverity.LOW

    # Medium severity
    medium = detector.check_mass_export(records_count=3000)
    assert medium.severity == BreachSeverity.MEDIUM

    # High severity
    high = detector.check_mass_export(records_count=6000)
    assert high.severity == BreachSeverity.HIGH

    # Critical severity
    critical = detector.check_mass_export(records_count=15000)
    assert critical.severity == BreachSeverity.CRITICAL


def test_check_failed_auth_below_threshold_returns_none(detector):
    """Test failed auth below threshold returns None."""
    incident = detector.check_failed_auth(
        attempts=5,
        window_minutes=60,
        user_id="user123",
    )

    assert incident is None


def test_check_failed_auth_above_threshold_creates_incident(detector):
    """Test failed auth above threshold creates incident."""
    incident = detector.check_failed_auth(
        attempts=15,
        window_minutes=60,
        user_id="user123",
        source_ip="10.0.0.50",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.FAILED_AUTH
    assert incident.severity == BreachSeverity.MEDIUM
    assert incident.affected_users == 1
    assert incident.metadata["attempts"] == 15
    assert incident.metadata["window_minutes"] == 60


def test_check_failed_auth_high_severity_for_many_attempts(detector):
    """Test failed auth severity increases with attempt count."""
    incident = detector.check_failed_auth(attempts=75)

    assert incident is not None
    assert incident.severity == BreachSeverity.HIGH


def test_check_bulk_phi_access_below_threshold_returns_none(detector):
    """Test bulk PHI access below threshold returns None."""
    incident = detector.check_bulk_phi_access(
        records=50,
        window_minutes=60,
    )

    assert incident is None


def test_check_bulk_phi_access_above_threshold_creates_incident(detector):
    """Test bulk PHI access above threshold creates incident."""
    incident = detector.check_bulk_phi_access(
        records=200,
        window_minutes=30,
        user_id="doctor123",
        source_ip="192.168.1.10",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.BULK_PHI_ACCESS
    assert incident.affected_records == 200
    assert incident.user_id == "doctor123"


def test_check_unusual_hours_during_normal_hours_returns_none(detector):
    """Test access during normal hours returns None."""
    # 2PM is normal hours
    normal_time = datetime(2024, 1, 15, 14, 30)

    incident = detector.check_unusual_hours(
        access_time=normal_time,
        user_id="user123",
    )

    assert incident is None


def test_check_unusual_hours_during_unusual_hours_creates_incident(detector):
    """Test access during unusual hours creates incident."""
    # 2AM is unusual hours
    unusual_time = datetime(2024, 1, 15, 2, 30)

    incident = detector.check_unusual_hours(
        access_time=unusual_time,
        user_id="user123",
        source_ip="192.168.1.100",
        action="document_access",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.UNUSUAL_HOURS
    assert incident.severity == BreachSeverity.MEDIUM
    assert incident.metadata["action"] == "document_access"


def test_check_emergency_access_always_creates_incident(detector):
    """Test emergency access always creates incident for audit trail."""
    incident = detector.check_emergency_access(
        user_id="user123",
        source_ip="192.168.1.100",
        reason="Patient critical condition",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.EMERGENCY_ACCESS
    assert incident.severity == BreachSeverity.HIGH
    assert incident.metadata["reason"] == "Patient critical condition"


def test_check_privilege_escalation_to_admin_creates_incident(detector):
    """Test privilege escalation to admin creates incident."""
    incident = detector.check_privilege_escalation(
        user_id="user123",
        old_role="viewer",
        new_role="admin",
        admin_id="admin_user",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.PRIVILEGE_ESCALATION
    assert incident.severity == BreachSeverity.HIGH
    assert incident.affected_users == 1


def test_check_privilege_escalation_non_admin_medium_severity(detector):
    """Test privilege escalation to non-admin role is medium severity."""
    incident = detector.check_privilege_escalation(
        user_id="user123",
        old_role="viewer",
        new_role="signer",
    )

    assert incident is not None
    assert incident.severity == BreachSeverity.MEDIUM


def test_check_privilege_escalation_demotion_returns_none(detector):
    """Test privilege demotion does not create incident."""
    incident = detector.check_privilege_escalation(
        user_id="user123",
        old_role="admin",
        new_role="viewer",
    )

    assert incident is None


def test_detect_anomaly_dispatcher_calls_correct_handler(detector):
    """Test detect_anomaly dispatches to correct handler."""
    # Test mass export
    incident = detector.detect_anomaly(
        "mass_export",
        records_count=2000,
        user_id="user123",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.MASS_EXPORT

    # Test failed auth
    incident = detector.detect_anomaly(
        "failed_auth",
        attempts=20,
        user_id="user123",
    )

    assert incident is not None
    assert incident.breach_type == BreachType.FAILED_AUTH


def test_detect_anomaly_unknown_event_type_returns_none(detector):
    """Test detect_anomaly returns None for unknown event type."""
    incident = detector.detect_anomaly(
        "unknown_event_type",
        some_param="value",
    )

    assert incident is None


def test_detector_with_custom_thresholds():
    """Test detector with custom thresholds."""
    custom_detector = BreachDetector(
        mass_export_threshold=500,
        failed_auth_threshold=5,
    )

    # Should trigger with lower threshold
    incident = custom_detector.check_mass_export(records_count=600)
    assert incident is not None

    incident = custom_detector.check_failed_auth(attempts=7)
    assert incident is not None
