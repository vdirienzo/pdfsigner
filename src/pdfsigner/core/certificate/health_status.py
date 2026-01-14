"""
health_status.py - Certificate health status monitoring

Author: Homero Thompson del Lago del Terror

Provides health level classification for certificates based on
expiration date with color-coded status levels.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class HealthLevel(Enum):
    """Certificate health level based on days until expiry."""

    OK = "ok"  # >60 days - Green
    WARNING = "warning"  # 30-60 days - Yellow
    ALERT = "alert"  # 7-30 days - Orange
    CRITICAL = "critical"  # <7 days - Red
    EXPIRED = "expired"  # <=0 days - Dark red

    @classmethod
    def from_days(cls, days: int) -> "HealthLevel":
        """Determine health level from days until expiry."""
        if days <= 0:
            return cls.EXPIRED
        elif days <= 7:
            return cls.CRITICAL
        elif days <= 30:
            return cls.ALERT
        elif days <= 60:
            return cls.WARNING
        else:
            return cls.OK


# Color mapping for each health level (GTK CSS class names)
HEALTH_COLORS = {
    HealthLevel.OK: "#10B981",  # Green
    HealthLevel.WARNING: "#F59E0B",  # Yellow
    HealthLevel.ALERT: "#F97316",  # Orange
    HealthLevel.CRITICAL: "#EF4444",  # Red
    HealthLevel.EXPIRED: "#991B1B",  # Dark red
}

# CSS class names for styling
HEALTH_CSS_CLASSES = {
    HealthLevel.OK: "cert-status-ok",
    HealthLevel.WARNING: "cert-status-warning",
    HealthLevel.ALERT: "cert-status-alert",
    HealthLevel.CRITICAL: "cert-status-critical",
    HealthLevel.EXPIRED: "cert-status-expired",
}


@dataclass
class CertificateHealth:
    """
    Certificate health status information.

    Provides a comprehensive view of certificate validity
    including days remaining, health level, and display info.
    """

    subject_cn: str
    issuer_cn: str
    not_before: datetime
    not_after: datetime
    serial_number: str = ""

    @property
    def days_remaining(self) -> int:
        """Days until certificate expires."""
        delta = self.not_after - datetime.now(self.not_after.tzinfo)
        return max(0, delta.days)

    @property
    def health_level(self) -> HealthLevel:
        """Current health level based on expiry."""
        return HealthLevel.from_days(self.days_remaining)

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return self.days_remaining <= 0

    @property
    def lifetime_progress(self) -> float:
        """
        Percentage of certificate lifetime consumed.

        Returns:
            Float between 0.0 and 1.0
        """
        total_days = (self.not_after - self.not_before).days
        if total_days <= 0:
            return 1.0
        elapsed = (datetime.now(self.not_after.tzinfo) - self.not_before).days
        return min(1.0, max(0.0, elapsed / total_days))

    @property
    def css_class(self) -> str:
        """CSS class name for styling."""
        return HEALTH_CSS_CLASSES.get(self.health_level, "cert-status-ok")

    @property
    def color(self) -> str:
        """Hex color for the health level."""
        return HEALTH_COLORS.get(self.health_level, "#10B981")

    @property
    def status_icon(self) -> str:
        """Emoji icon for the health level."""
        icons = {
            HealthLevel.OK: "✅",
            HealthLevel.WARNING: "⚠️",
            HealthLevel.ALERT: "🔶",
            HealthLevel.CRITICAL: "🚨",
            HealthLevel.EXPIRED: "❌",
        }
        return icons.get(self.health_level, "✅")

    @property
    def status_text(self) -> str:
        """Human-readable status text."""
        if self.is_expired:
            return "Certificate expired"
        elif self.days_remaining == 1:
            return "Expires tomorrow"
        else:
            return f"Expires in {self.days_remaining} days"
