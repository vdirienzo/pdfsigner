"""
notification_service.py - Breach notification service

Handles notification generation and delivery per GDPR and HIPAA requirements.
"""

from datetime import UTC, datetime, timedelta
from enum import Enum

from loguru import logger

from pdfsigner.core.breach.breach_types import BreachIncident, BreachSeverity


class NotificationChannel(str, Enum):
    """Notification delivery channels."""

    EMAIL = "email"
    WEBHOOK = "webhook"
    SMS = "sms"


class NotificationService:
    """
    Breach notification service.

    Generates and sends notifications to authorities and affected individuals
    according to GDPR and HIPAA requirements.
    """

    def __init__(self):
        """Initialize notification service."""
        pass

    def send_notification(
        self,
        incident: BreachIncident,
        channels: list[NotificationChannel],
        recipients: list[str],
        message: str | None = None,
    ) -> dict:
        """
        Send breach notification through specified channels.

        Args:
            incident: Breach incident
            channels: Delivery channels to use
            recipients: Recipient addresses/endpoints
            message: Optional custom message (default: auto-generated)

        Returns:
            Dictionary with delivery results per channel
        """
        if not message:
            # Generate default notification based on jurisdiction
            message = self._generate_default_notification(incident)

        results = {}

        for channel in channels:
            try:
                if channel == NotificationChannel.EMAIL:
                    result = self._send_email(recipients, incident, message)
                elif channel == NotificationChannel.WEBHOOK:
                    result = self._send_webhook(recipients, incident, message)
                elif channel == NotificationChannel.SMS:
                    result = self._send_sms(recipients, incident, message)
                else:
                    result = {"success": False, "error": f"Unknown channel: {channel}"}

                results[channel.value] = result

            except Exception as e:
                logger.error(f"Failed to send notification via {channel.value}: {e}")
                results[channel.value] = {"success": False, "error": str(e)}

        logger.info(
            f"Sent notifications for breach {incident.id}: "
            f"channels={[c.value for c in channels]}, recipients={len(recipients)}"
        )

        return results

    def _generate_default_notification(self, incident: BreachIncident) -> str:
        """Generate default notification message."""
        return (
            f"Data breach notification\n\n"
            f"Incident ID: {incident.id}\n"
            f"Type: {incident.breach_type.value}\n"
            f"Severity: {incident.severity.value}\n"
            f"Detected: {incident.detected_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Affected records: {incident.affected_records}\n"
            f"Description: {incident.description}\n"
        )

    def _send_email(self, recipients: list[str], incident: BreachIncident, message: str) -> dict:
        """Send email notification (stub - implement with actual email service)."""
        logger.info(f"[EMAIL] Would send to {len(recipients)} recipients: {message[:100]}...")
        return {
            "success": True,
            "recipients": len(recipients),
            "channel": "email",
        }

    def _send_webhook(self, endpoints: list[str], incident: BreachIncident, message: str) -> dict:
        """Send webhook notification (stub - implement with actual HTTP client)."""
        logger.info(f"[WEBHOOK] Would POST to {len(endpoints)} endpoints: {message[:100]}...")
        return {
            "success": True,
            "endpoints": len(endpoints),
            "channel": "webhook",
        }

    def _send_sms(self, numbers: list[str], incident: BreachIncident, message: str) -> dict:
        """Send SMS notification (stub - implement with actual SMS service)."""
        logger.info(f"[SMS] Would send to {len(numbers)} numbers: {message[:100]}...")
        return {
            "success": True,
            "recipients": len(numbers),
            "channel": "sms",
        }


def generate_gdpr_notification(incident: BreachIncident) -> str:
    """
    Generate GDPR-compliant notification (Art. 33).

    Must include:
    - Nature of breach
    - Contact point for more information
    - Likely consequences
    - Measures taken or proposed

    Args:
        incident: Breach incident

    Returns:
        Formatted notification for supervisory authority
    """
    return f"""GDPR ARTICLE 33 - DATA BREACH NOTIFICATION

1. NATURE OF THE PERSONAL DATA BREACH
   Breach Type: {incident.breach_type.value}
   Severity: {incident.severity.value}
   Detected: {incident.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
   Status: {incident.status.value}

2. DESCRIPTION
   {incident.description}

3. DATA SUBJECTS AND RECORDS AFFECTED
   Approximate number of data subjects: {incident.affected_users}
   Approximate number of records: {incident.affected_records}

4. CONTACT POINT
   Data Protection Officer
   Email: dpo@organization.example
   Phone: +1-555-0123

5. LIKELY CONSEQUENCES
   {_assess_gdpr_consequences(incident)}

6. MEASURES TAKEN OR PROPOSED
   - Immediate containment procedures initiated
   - Forensic investigation in progress
   - Affected systems isolated
   - Notification to data subjects (if required)
   - Implementation of additional security controls

7. INCIDENT REFERENCE
   Incident ID: {incident.id}
   Detected at: {incident.detected_at.isoformat()}

---
This notification is submitted in accordance with GDPR Article 33.
"""


def generate_hipaa_notification(incident: BreachIncident) -> str:
    """
    Generate HIPAA-compliant notification (§164.404, §164.408).

    Must include:
    - Brief description of breach
    - Types of information involved
    - Steps individuals should take
    - What organization is doing
    - Contact procedures

    Args:
        incident: Breach incident

    Returns:
        Formatted notification for HHS and individuals
    """
    return f"""HIPAA BREACH NOTIFICATION (45 CFR §164.404, §164.408)

BREACH IDENTIFICATION
   Incident ID: {incident.id}
   Date Discovered: {incident.detected_at.strftime("%B %d, %Y")}
   Severity: {incident.severity.value}

BREACH DESCRIPTION
   {incident.description}

   Type of breach: {incident.breach_type.value}
   Status: {incident.status.value}

INFORMATION INVOLVED
   Approximate number of individuals affected: {incident.affected_users}
   Approximate number of records affected: {incident.affected_records}

   Types of information potentially compromised:
   - Protected Health Information (PHI)
   - Personal identifiers
   {_list_phi_types(incident)}

STEPS INDIVIDUALS SHOULD TAKE
   1. Monitor your accounts and statements for suspicious activity
   2. Review your medical records for any unauthorized access
   3. Consider placing a fraud alert or security freeze
   4. Report any suspicious activity to us immediately

WHAT WE ARE DOING
   - Conducted immediate investigation and containment
   - Implemented additional security measures
   - Notifying all affected individuals
   - Cooperating with law enforcement if applicable
   - Providing complimentary credit monitoring services (if applicable)

CONTACT INFORMATION
   Privacy Officer
   Email: privacy@organization.example
   Phone: 1-800-555-0100
   Hours: Monday-Friday, 8:00 AM - 6:00 PM EST

   For questions or to report suspicious activity related to this breach,
   please contact us using the information above.

REGULATORY REPORTING
   This breach has been reported to the U.S. Department of Health and Human Services
   as required by HIPAA regulations.

---
Notification Date: {datetime.now(UTC).strftime("%B %d, %Y")}
"""


def calculate_notification_deadline(incident: BreachIncident) -> dict[str, datetime]:
    """
    Calculate notification deadlines per regulations.

    GDPR: 72 hours to supervisory authority (Art. 33)
    HIPAA: 60 days to individuals, without unreasonable delay to HHS (§164.404, §164.408)

    Args:
        incident: Breach incident

    Returns:
        Dictionary with deadline dates for each jurisdiction
    """
    detection_time = incident.detected_at

    deadlines = {
        "gdpr_authority": detection_time + timedelta(hours=72),
        "gdpr_individuals": detection_time + timedelta(days=7),  # If high risk
        "hipaa_individuals": detection_time + timedelta(days=60),
        "hipaa_hhs": detection_time + timedelta(days=60),
    }

    # Adjust based on severity
    if incident.severity == BreachSeverity.CRITICAL:
        # Expedite for critical breaches
        deadlines["hipaa_individuals"] = detection_time + timedelta(days=30)

    return deadlines


def _assess_gdpr_consequences(incident: BreachIncident) -> str:
    """Assess likely consequences for GDPR notification."""
    consequences = []

    if incident.severity in [BreachSeverity.HIGH, BreachSeverity.CRITICAL]:
        consequences.append("- High risk to rights and freedoms of data subjects")
        consequences.append("- Potential for identity theft or fraud")

    if incident.affected_records > 1000:
        consequences.append("- Large-scale data exposure")

    if incident.breach_type.value in ["bulk_phi_access", "mass_data_export"]:
        consequences.append("- Unauthorized access to sensitive personal data")

    if not consequences:
        consequences.append("- Limited risk to data subjects")
        consequences.append("- Appropriate security measures in place")

    return "\n   ".join(consequences)


def _list_phi_types(incident: BreachIncident) -> str:
    """List types of PHI potentially involved."""
    phi_types = [
        "   - Names and contact information",
        "   - Medical record numbers",
        "   - Dates of service",
    ]

    if incident.severity in [BreachSeverity.HIGH, BreachSeverity.CRITICAL]:
        phi_types.extend(
            [
                "   - Diagnosis and treatment information",
                "   - Insurance information",
                "   - Social Security Numbers (if applicable)",
            ]
        )

    return "\n".join(phi_types)
