"""
Tests for breach notification service.

Tests GDPR and HIPAA compliant notification generation and delivery.
"""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from pdfsigner.core.breach.breach_types import (
    BreachIncident,
    BreachSeverity,
    BreachStatus,
    BreachType,
)
from pdfsigner.core.breach.notification_service import (
    NotificationChannel,
    NotificationService,
    calculate_notification_deadline,
    generate_gdpr_notification,
    generate_hipaa_notification,
)


@pytest.fixture
def sample_incident():
    """Create sample breach incident for testing."""
    return BreachIncident(
        breach_type=BreachType.BULK_PHI_ACCESS,
        severity=BreachSeverity.HIGH,
        status=BreachStatus.DETECTED,
        description="Unauthorized bulk access to patient records detected",
        affected_users=150,
        affected_records=2500,
        user_id="user123",
        source_ip="192.168.1.100",
        metadata={"location": "PHI_database"},
    )


@pytest.fixture
def critical_incident():
    """Create critical severity incident."""
    return BreachIncident(
        breach_type=BreachType.MASS_EXPORT,
        severity=BreachSeverity.CRITICAL,
        status=BreachStatus.DETECTED,
        description="Large-scale data export detected",
        affected_users=5000,
        affected_records=25000,
        user_id="admin456",
        source_ip="10.0.0.50",
    )


@pytest.fixture
def low_severity_incident():
    """Create low severity incident."""
    return BreachIncident(
        breach_type=BreachType.UNUSUAL_HOURS,
        severity=BreachSeverity.LOW,
        status=BreachStatus.DETECTED,
        description="Access during unusual hours",
        affected_users=1,
        affected_records=5,
        user_id="user789",
    )


@pytest.fixture
def notification_service():
    """Create notification service instance."""
    return NotificationService()


# ============================================================================
# NotificationService Tests
# ============================================================================


@pytest.mark.compliance
def test_send_notification_with_single_channel_succeeds(notification_service, sample_incident):
    """Test send_notification with email channel succeeds."""
    results = notification_service.send_notification(
        incident=sample_incident,
        channels=[NotificationChannel.EMAIL],
        recipients=["security@example.com"],
        message="Security breach detected",
    )

    assert "email" in results
    assert results["email"]["success"] is True
    assert results["email"]["recipients"] == 1


@pytest.mark.compliance
def test_send_notification_with_multiple_channels_succeeds(notification_service, sample_incident):
    """Test send_notification with multiple channels succeeds."""
    results = notification_service.send_notification(
        incident=sample_incident,
        channels=[NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
        recipients=["security@example.com", "https://api.example.com/webhook"],
        message="Security breach detected",
    )

    assert "email" in results
    assert "webhook" in results
    assert results["email"]["success"] is True
    assert results["webhook"]["success"] is True


@pytest.mark.compliance
def test_send_notification_with_custom_message_uses_message(notification_service, sample_incident):
    """Test send_notification with custom message uses provided message."""
    custom_message = "URGENT: Security incident requires immediate attention"

    with patch.object(notification_service, "_send_email") as mock_email:
        mock_email.return_value = {"success": True, "recipients": 1, "channel": "email"}

        notification_service.send_notification(
            incident=sample_incident,
            channels=[NotificationChannel.EMAIL],
            recipients=["security@example.com"],
            message=custom_message,
        )

        # Verify custom message was passed to sender
        mock_email.assert_called_once()
        args = mock_email.call_args[0]
        assert args[2] == custom_message


@pytest.mark.compliance
def test_send_notification_without_message_generates_default(notification_service, sample_incident):
    """Test send_notification without message generates default notification."""
    with patch.object(notification_service, "_send_email") as mock_email:
        mock_email.return_value = {"success": True, "recipients": 1, "channel": "email"}

        notification_service.send_notification(
            incident=sample_incident,
            channels=[NotificationChannel.EMAIL],
            recipients=["security@example.com"],
        )

        # Verify default message was generated
        mock_email.assert_called_once()
        args = mock_email.call_args[0]
        message = args[2]
        assert "Data breach notification" in message
        assert sample_incident.id in message


@pytest.mark.compliance
def test_send_notification_handles_channel_errors_gracefully(notification_service, sample_incident):
    """Test send_notification handles channel errors without failing."""
    with patch.object(notification_service, "_send_email") as mock_email:
        mock_email.side_effect = Exception("SMTP connection failed")

        results = notification_service.send_notification(
            incident=sample_incident,
            channels=[NotificationChannel.EMAIL],
            recipients=["security@example.com"],
            message="Test message",
        )

        assert "email" in results
        assert results["email"]["success"] is False
        assert "SMTP connection failed" in results["email"]["error"]


@pytest.mark.compliance
def test_send_notification_continues_after_channel_failure(notification_service, sample_incident):
    """Test send_notification continues to other channels after one fails."""
    with (
        patch.object(notification_service, "_send_email") as mock_email,
        patch.object(notification_service, "_send_webhook") as mock_webhook,
    ):
        mock_email.side_effect = Exception("Email failed")
        mock_webhook.return_value = {"success": True, "endpoints": 1, "channel": "webhook"}

        results = notification_service.send_notification(
            incident=sample_incident,
            channels=[NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
            recipients=["security@example.com", "https://api.example.com/webhook"],
            message="Test message",
        )

        # Email failed but webhook succeeded
        assert results["email"]["success"] is False
        assert results["webhook"]["success"] is True


@pytest.mark.compliance
def test_send_email_returns_success_result(notification_service, sample_incident):
    """Test _send_email returns success result."""
    result = notification_service._send_email(
        recipients=["user1@example.com", "user2@example.com"],
        incident=sample_incident,
        message="Test message",
    )

    assert result["success"] is True
    assert result["recipients"] == 2
    assert result["channel"] == "email"


@pytest.mark.compliance
def test_send_webhook_returns_success_result(notification_service, sample_incident):
    """Test _send_webhook returns success result."""
    result = notification_service._send_webhook(
        endpoints=["https://api1.example.com", "https://api2.example.com"],
        incident=sample_incident,
        message="Test message",
    )

    assert result["success"] is True
    assert result["endpoints"] == 2
    assert result["channel"] == "webhook"


@pytest.mark.compliance
def test_send_sms_returns_success_result(notification_service, sample_incident):
    """Test _send_sms returns success result."""
    result = notification_service._send_sms(
        numbers=["+15551234567", "+15559876543"],
        incident=sample_incident,
        message="Test message",
    )

    assert result["success"] is True
    assert result["recipients"] == 2
    assert result["channel"] == "sms"


@pytest.mark.compliance
def test_send_notification_handles_unknown_channel(notification_service, sample_incident):
    """Test send_notification handles unknown channel gracefully."""
    # Create mock unknown channel
    unknown_channel = Mock()
    unknown_channel.value = "unknown_channel"

    results = notification_service.send_notification(
        incident=sample_incident,
        channels=[unknown_channel],
        recipients=["test@example.com"],
        message="Test message",
    )

    assert "unknown_channel" in results
    assert results["unknown_channel"]["success"] is False
    assert "Unknown channel" in results["unknown_channel"]["error"]


# ============================================================================
# GDPR Notification Generation Tests
# ============================================================================


@pytest.mark.compliance
def test_generate_gdpr_notification_includes_required_fields(sample_incident):
    """Test generate_gdpr_notification includes all GDPR Art. 33 required fields."""
    notification = generate_gdpr_notification(sample_incident)

    # Must include nature of breach
    assert "NATURE OF THE PERSONAL DATA BREACH" in notification
    assert sample_incident.breach_type.value in notification
    assert sample_incident.severity.value in notification

    # Must include contact point
    assert "CONTACT POINT" in notification
    assert "dpo@organization.example" in notification

    # Must include likely consequences
    assert "LIKELY CONSEQUENCES" in notification

    # Must include measures taken
    assert "MEASURES TAKEN OR PROPOSED" in notification
    assert "Immediate containment" in notification

    # Must include affected data subjects
    assert f"Approximate number of data subjects: {sample_incident.affected_users}" in notification
    assert f"Approximate number of records: {sample_incident.affected_records}" in notification


@pytest.mark.compliance
def test_generate_gdpr_notification_includes_incident_metadata(sample_incident):
    """Test generate_gdpr_notification includes incident identification."""
    notification = generate_gdpr_notification(sample_incident)

    assert sample_incident.id in notification
    assert sample_incident.description in notification
    assert "GDPR ARTICLE 33" in notification


@pytest.mark.compliance
def test_generate_gdpr_notification_assesses_high_risk_consequences(critical_incident):
    """Test generate_gdpr_notification assesses high risk consequences correctly."""
    notification = generate_gdpr_notification(critical_incident)

    # High/critical severity should mention high risk
    assert (
        "High risk to rights and freedoms" in notification
        or "Large-scale data exposure" in notification
    )


@pytest.mark.compliance
def test_generate_gdpr_notification_for_low_severity_shows_limited_risk(low_severity_incident):
    """Test generate_gdpr_notification for low severity shows limited risk."""
    notification = generate_gdpr_notification(low_severity_incident)

    # Low severity with few records should show limited risk
    assert "Limited risk" in notification or "Appropriate security measures" in notification


@pytest.mark.compliance
def test_generate_gdpr_notification_includes_regulatory_compliance_statement(sample_incident):
    """Test generate_gdpr_notification includes compliance statement."""
    notification = generate_gdpr_notification(sample_incident)

    assert "This notification is submitted in accordance with GDPR Article 33" in notification


@pytest.mark.compliance
def test_generate_gdpr_notification_formats_dates_correctly(sample_incident):
    """Test generate_gdpr_notification formats dates in ISO and readable format."""
    notification = generate_gdpr_notification(sample_incident)

    # Should have both human-readable and ISO format
    assert sample_incident.detected_at.strftime("%Y-%m-%d") in notification
    assert sample_incident.detected_at.isoformat() in notification


# ============================================================================
# HIPAA Notification Generation Tests
# ============================================================================


@pytest.mark.compliance
def test_generate_hipaa_notification_includes_required_fields(sample_incident):
    """Test generate_hipaa_notification includes all HIPAA §164.404 required fields."""
    notification = generate_hipaa_notification(sample_incident)

    # Brief description of breach
    assert "BREACH DESCRIPTION" in notification
    assert sample_incident.description in notification

    # Types of information involved
    assert "INFORMATION INVOLVED" in notification
    assert "Protected Health Information (PHI)" in notification

    # Steps individuals should take
    assert "STEPS INDIVIDUALS SHOULD TAKE" in notification
    assert "Monitor your accounts" in notification

    # What organization is doing
    assert "WHAT WE ARE DOING" in notification
    assert "investigation" in notification.lower()

    # Contact procedures
    assert "CONTACT INFORMATION" in notification
    assert "privacy@organization.example" in notification


@pytest.mark.compliance
def test_generate_hipaa_notification_includes_breach_identification(sample_incident):
    """Test generate_hipaa_notification includes breach identification."""
    notification = generate_hipaa_notification(sample_incident)

    assert sample_incident.id in notification
    assert "Date Discovered" in notification
    assert sample_incident.detected_at.strftime("%B %d, %Y") in notification


@pytest.mark.compliance
def test_generate_hipaa_notification_includes_regulatory_reporting_statement(sample_incident):
    """Test generate_hipaa_notification includes HHS reporting statement."""
    notification = generate_hipaa_notification(sample_incident)

    assert "REGULATORY REPORTING" in notification
    assert "Department of Health and Human Services" in notification
    assert "HIPAA regulations" in notification


@pytest.mark.compliance
def test_generate_hipaa_notification_lists_phi_types_for_critical_breach(critical_incident):
    """Test generate_hipaa_notification lists detailed PHI types for critical breach."""
    notification = generate_hipaa_notification(critical_incident)

    # Critical breaches should list more PHI types
    assert "Diagnosis and treatment information" in notification
    assert "Social Security Numbers" in notification or "Insurance information" in notification


@pytest.mark.compliance
def test_generate_hipaa_notification_includes_individual_actions(sample_incident):
    """Test generate_hipaa_notification includes actionable steps for individuals."""
    notification = generate_hipaa_notification(sample_incident)

    assert "Monitor your accounts and statements" in notification
    assert "Review your medical records" in notification
    assert "fraud alert" in notification.lower()
    assert "Report any suspicious activity" in notification


@pytest.mark.compliance
def test_generate_hipaa_notification_includes_organization_response(sample_incident):
    """Test generate_hipaa_notification includes organization's response actions."""
    notification = generate_hipaa_notification(sample_incident)

    assert "investigation and containment" in notification.lower()
    assert "additional security measures" in notification.lower()
    assert "Notifying all affected individuals" in notification


# ============================================================================
# Notification Deadline Calculation Tests
# ============================================================================


@pytest.mark.compliance
def test_calculate_notification_deadline_returns_gdpr_72_hour_deadline(sample_incident):
    """Test calculate_notification_deadline returns GDPR 72-hour deadline."""
    deadlines = calculate_notification_deadline(sample_incident)

    expected_gdpr = sample_incident.detected_at + timedelta(hours=72)

    assert "gdpr_authority" in deadlines
    assert deadlines["gdpr_authority"] == expected_gdpr


@pytest.mark.compliance
def test_calculate_notification_deadline_returns_hipaa_60_day_deadline(sample_incident):
    """Test calculate_notification_deadline returns HIPAA 60-day deadline."""
    deadlines = calculate_notification_deadline(sample_incident)

    expected_hipaa_individuals = sample_incident.detected_at + timedelta(days=60)
    expected_hipaa_hhs = sample_incident.detected_at + timedelta(days=60)

    assert "hipaa_individuals" in deadlines
    assert "hipaa_hhs" in deadlines
    assert deadlines["hipaa_individuals"] == expected_hipaa_individuals
    assert deadlines["hipaa_hhs"] == expected_hipaa_hhs


@pytest.mark.compliance
def test_calculate_notification_deadline_includes_all_jurisdictions(sample_incident):
    """Test calculate_notification_deadline includes all regulatory deadlines."""
    deadlines = calculate_notification_deadline(sample_incident)

    # Should have all four deadline types
    assert "gdpr_authority" in deadlines
    assert "gdpr_individuals" in deadlines
    assert "hipaa_individuals" in deadlines
    assert "hipaa_hhs" in deadlines


@pytest.mark.compliance
def test_calculate_notification_deadline_expedites_critical_breaches(critical_incident):
    """Test calculate_notification_deadline expedites deadlines for critical breaches."""
    deadlines = calculate_notification_deadline(critical_incident)

    # Critical breaches should have shorter HIPAA deadline (30 days instead of 60)
    expected_expedited = critical_incident.detected_at + timedelta(days=30)

    assert deadlines["hipaa_individuals"] == expected_expedited


@pytest.mark.compliance
def test_calculate_notification_deadline_does_not_expedite_low_severity(low_severity_incident):
    """Test calculate_notification_deadline uses standard deadlines for low severity."""
    deadlines = calculate_notification_deadline(low_severity_incident)

    # Low severity should use standard 60-day deadline
    expected_standard = low_severity_incident.detected_at + timedelta(days=60)

    assert deadlines["hipaa_individuals"] == expected_standard


@pytest.mark.compliance
def test_calculate_notification_deadline_gdpr_individuals_deadline_is_7_days(sample_incident):
    """Test calculate_notification_deadline sets GDPR individuals deadline to 7 days."""
    deadlines = calculate_notification_deadline(sample_incident)

    expected_individuals = sample_incident.detected_at + timedelta(days=7)

    assert deadlines["gdpr_individuals"] == expected_individuals


@pytest.mark.compliance
def test_calculate_notification_deadline_preserves_detection_time(sample_incident):
    """Test calculate_notification_deadline calculates from exact detection time."""
    # Set specific detection time
    specific_time = datetime(2024, 1, 15, 14, 30, 0)
    sample_incident.detected_at = specific_time

    deadlines = calculate_notification_deadline(sample_incident)

    # GDPR should be exactly 72 hours later
    expected_gdpr = specific_time + timedelta(hours=72)
    assert deadlines["gdpr_authority"] == expected_gdpr

    # HIPAA should be exactly 60 days later
    expected_hipaa = specific_time + timedelta(days=60)
    assert deadlines["hipaa_hhs"] == expected_hipaa


# ============================================================================
# Integration Tests
# ============================================================================


@pytest.mark.compliance
def test_end_to_end_gdpr_notification_workflow(notification_service, sample_incident):
    """Test complete GDPR notification workflow from generation to delivery."""
    # Generate GDPR-compliant notification
    notification = generate_gdpr_notification(sample_incident)

    # Calculate deadlines
    deadlines = calculate_notification_deadline(sample_incident)

    # Send notification
    results = notification_service.send_notification(
        incident=sample_incident,
        channels=[NotificationChannel.EMAIL],
        recipients=["dpo@authority.example"],
        message=notification,
    )

    # Verify complete workflow
    assert "GDPR ARTICLE 33" in notification
    assert "gdpr_authority" in deadlines
    assert results["email"]["success"] is True


@pytest.mark.compliance
def test_end_to_end_hipaa_notification_workflow(notification_service, sample_incident):
    """Test complete HIPAA notification workflow from generation to delivery."""
    # Generate HIPAA-compliant notification
    notification = generate_hipaa_notification(sample_incident)

    # Calculate deadlines
    deadlines = calculate_notification_deadline(sample_incident)

    # Send notification
    results = notification_service.send_notification(
        incident=sample_incident,
        channels=[NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
        recipients=["privacy@org.example", "https://hhs.gov/api/breach"],
        message=notification,
    )

    # Verify complete workflow
    assert "HIPAA BREACH NOTIFICATION" in notification
    assert "hipaa_individuals" in deadlines
    assert results["email"]["success"] is True
    assert results["webhook"]["success"] is True


@pytest.mark.compliance
def test_multi_channel_notification_with_retry_simulation(notification_service, sample_incident):
    """Test multi-channel notification handles partial failures gracefully."""
    with (
        patch.object(notification_service, "_send_email") as mock_email,
        patch.object(notification_service, "_send_webhook") as mock_webhook,
        patch.object(notification_service, "_send_sms") as mock_sms,
    ):
        # Simulate email failure, webhook success, SMS success
        mock_email.side_effect = Exception("Temporary network error")
        mock_webhook.return_value = {"success": True, "endpoints": 1, "channel": "webhook"}
        mock_sms.return_value = {"success": True, "recipients": 1, "channel": "sms"}

        results = notification_service.send_notification(
            incident=sample_incident,
            channels=[
                NotificationChannel.EMAIL,
                NotificationChannel.WEBHOOK,
                NotificationChannel.SMS,
            ],
            recipients=["contact@example.com", "https://api.example.com", "+15551234567"],
            message="Test message",
        )

        # Email failed but others succeeded
        assert results["email"]["success"] is False
        assert results["webhook"]["success"] is True
        assert results["sms"]["success"] is True

        # All channels were attempted despite email failure
        assert len(results) == 3
