"""
test_health_status.py - Tests for certificate health status

Author: Homero Thompson del Lago del Terror
"""

from datetime import UTC, datetime, timedelta

import pytest

from pdfsigner.core.certificate.health_status import (
    HEALTH_COLORS,
    HEALTH_CSS_CLASSES,
    CertificateHealth,
    HealthLevel,
)


class TestHealthLevel:
    """Tests for HealthLevel enum."""

    def test_ok_level_value(self):
        """Test OK level has correct value."""
        assert HealthLevel.OK.value == "ok"

    def test_warning_level_value(self):
        """Test WARNING level has correct value."""
        assert HealthLevel.WARNING.value == "warning"

    def test_alert_level_value(self):
        """Test ALERT level has correct value."""
        assert HealthLevel.ALERT.value == "alert"

    def test_critical_level_value(self):
        """Test CRITICAL level has correct value."""
        assert HealthLevel.CRITICAL.value == "critical"

    def test_expired_level_value(self):
        """Test EXPIRED level has correct value."""
        assert HealthLevel.EXPIRED.value == "expired"

    @pytest.mark.parametrize(
        "days,expected",
        [
            (100, HealthLevel.OK),
            (61, HealthLevel.OK),
            (60, HealthLevel.WARNING),
            (45, HealthLevel.WARNING),
            (30, HealthLevel.ALERT),
            (15, HealthLevel.ALERT),
            (7, HealthLevel.CRITICAL),
            (3, HealthLevel.CRITICAL),
            (1, HealthLevel.CRITICAL),
            (0, HealthLevel.EXPIRED),
            (-5, HealthLevel.EXPIRED),
        ],
    )
    def test_from_days(self, days: int, expected: HealthLevel):
        """Test from_days returns correct level for various days."""
        assert HealthLevel.from_days(days) == expected


class TestHealthColors:
    """Tests for health level color mappings."""

    def test_all_levels_have_colors(self):
        """Test all health levels have a color mapping."""
        for level in HealthLevel:
            assert level in HEALTH_COLORS

    def test_colors_are_hex(self):
        """Test all colors are valid hex codes."""
        for color in HEALTH_COLORS.values():
            assert color.startswith("#")
            assert len(color) == 7


class TestHealthCSSClasses:
    """Tests for health level CSS class mappings."""

    def test_all_levels_have_css_classes(self):
        """Test all health levels have CSS class mapping."""
        for level in HealthLevel:
            assert level in HEALTH_CSS_CLASSES

    def test_css_class_format(self):
        """Test CSS classes follow naming convention."""
        for level, css_class in HEALTH_CSS_CLASSES.items():
            assert css_class.startswith("cert-status-")
            assert level.value in css_class


class TestCertificateHealth:
    """Tests for CertificateHealth dataclass."""

    @pytest.fixture
    def now(self):
        """Current time with timezone."""
        return datetime.now(UTC)

    @pytest.fixture
    def sample_health(self, now):
        """Sample certificate health with 45 days remaining."""
        return CertificateHealth(
            subject_cn="John Doe",
            issuer_cn="Test CA",
            not_before=now - timedelta(days=300),
            not_after=now + timedelta(days=45),
            serial_number="ABC123",
        )

    def test_creation(self, sample_health):
        """Test creating CertificateHealth."""
        assert sample_health.subject_cn == "John Doe"
        assert sample_health.issuer_cn == "Test CA"
        assert sample_health.serial_number == "ABC123"

    def test_days_remaining_positive(self, sample_health):
        """Test days_remaining for non-expired cert."""
        # Allow for small timing differences
        assert 44 <= sample_health.days_remaining <= 45

    def test_days_remaining_expired(self, now):
        """Test days_remaining for expired cert."""
        health = CertificateHealth(
            subject_cn="Expired User",
            issuer_cn="Test CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=10),
        )
        assert health.days_remaining == 0

    def test_health_level_warning(self, sample_health):
        """Test health level is WARNING for 45 days."""
        assert sample_health.health_level == HealthLevel.WARNING

    def test_health_level_ok(self, now):
        """Test health level is OK for >60 days."""
        health = CertificateHealth(
            subject_cn="Good User",
            issuer_cn="Test CA",
            not_before=now - timedelta(days=100),
            not_after=now + timedelta(days=100),
        )
        assert health.health_level == HealthLevel.OK

    def test_health_level_critical(self, now):
        """Test health level is CRITICAL for <7 days."""
        health = CertificateHealth(
            subject_cn="Critical User",
            issuer_cn="Test CA",
            not_before=now - timedelta(days=358),
            not_after=now + timedelta(days=3),
        )
        assert health.health_level == HealthLevel.CRITICAL

    def test_health_level_expired(self, now):
        """Test health level is EXPIRED for past date."""
        health = CertificateHealth(
            subject_cn="Expired User",
            issuer_cn="Test CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=5),
        )
        assert health.health_level == HealthLevel.EXPIRED

    def test_is_expired_false(self, sample_health):
        """Test is_expired is False for valid cert."""
        assert sample_health.is_expired is False

    def test_is_expired_true(self, now):
        """Test is_expired is True for expired cert."""
        health = CertificateHealth(
            subject_cn="Expired User",
            issuer_cn="Test CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=5),
        )
        assert health.is_expired is True

    def test_lifetime_progress(self, now):
        """Test lifetime progress calculation."""
        # Certificate that started 300 days ago, expires in 65 days
        # Total: 365 days, elapsed: 300 days = 82.2%
        health = CertificateHealth(
            subject_cn="User",
            issuer_cn="CA",
            not_before=now - timedelta(days=300),
            not_after=now + timedelta(days=65),
        )
        assert 0.80 <= health.lifetime_progress <= 0.85

    def test_lifetime_progress_new_cert(self, now):
        """Test lifetime progress for newly issued cert."""
        health = CertificateHealth(
            subject_cn="New User",
            issuer_cn="CA",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=364),
        )
        assert health.lifetime_progress < 0.01

    def test_lifetime_progress_expired(self, now):
        """Test lifetime progress for expired cert is capped at 1.0."""
        health = CertificateHealth(
            subject_cn="Expired User",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
        )
        assert health.lifetime_progress == 1.0

    def test_css_class(self, sample_health):
        """Test CSS class returns correct value."""
        assert sample_health.css_class == "cert-status-warning"

    def test_color(self, sample_health):
        """Test color returns hex value."""
        assert sample_health.color.startswith("#")

    def test_status_icon(self, sample_health):
        """Test status icon returns emoji."""
        assert sample_health.status_icon == "⚠️"

    def test_status_icon_ok(self, now):
        """Test status icon for OK level."""
        health = CertificateHealth(
            subject_cn="User",
            issuer_cn="CA",
            not_before=now - timedelta(days=100),
            not_after=now + timedelta(days=100),
        )
        assert health.status_icon == "✅"

    def test_status_icon_expired(self, now):
        """Test status icon for expired cert."""
        health = CertificateHealth(
            subject_cn="User",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=5),
        )
        assert health.status_icon == "❌"

    def test_status_text(self, sample_health):
        """Test status text format."""
        text = sample_health.status_text
        assert "Expires in" in text
        assert "days" in text

    def test_status_text_expired(self, now):
        """Test status text for expired cert."""
        health = CertificateHealth(
            subject_cn="User",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=5),
        )
        assert health.status_text == "Certificate expired"

    def test_status_text_tomorrow(self, now):
        """Test status text for cert expiring tomorrow."""
        # Use 36 hours to ensure days_remaining returns 1
        # (accounts for timing differences in test execution)
        health = CertificateHealth(
            subject_cn="User",
            issuer_cn="CA",
            not_before=now - timedelta(days=364),
            not_after=now + timedelta(hours=36),
        )
        assert health.status_text == "Expires tomorrow"

    def test_serial_number_optional(self, now):
        """Test serial_number has default empty value."""
        health = CertificateHealth(
            subject_cn="User",
            issuer_cn="CA",
            not_before=now,
            not_after=now + timedelta(days=365),
        )
        assert health.serial_number == ""
