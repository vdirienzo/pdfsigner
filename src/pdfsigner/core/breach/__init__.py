"""
Breach detection and notification module.

Implements GDPR Art. 33-34 and HIPAA breach notification requirements.

GDPR Compliance:
    - Art. 33: Notification to supervisory authority within 72 hours
    - Art. 34: Communication to data subjects when high risk

HIPAA Compliance:
    - §164.404: Notification to individuals within 60 days
    - §164.408: Notification to Secretary of HHS
"""

from pdfsigner.core.breach.breach_detector import BreachDetector
from pdfsigner.core.breach.breach_manager import BreachManager, get_breach_manager
from pdfsigner.core.breach.breach_report import generate_incident_report, generate_summary_report
from pdfsigner.core.breach.breach_repository import BreachRepository
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

__all__ = [
    # Types
    "BreachIncident",
    "BreachSeverity",
    "BreachStatus",
    "BreachType",
    # Detection
    "BreachDetector",
    # Storage
    "BreachRepository",
    # Management
    "BreachManager",
    "get_breach_manager",
    # Notification
    "NotificationService",
    "NotificationChannel",
    "generate_gdpr_notification",
    "generate_hipaa_notification",
    "calculate_notification_deadline",
    # Reports
    "generate_incident_report",
    "generate_summary_report",
]
