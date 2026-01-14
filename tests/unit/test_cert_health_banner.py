"""
test_cert_health_banner.py - Tests for certificate health banner logic

Author: Homero Thompson del Lago del Terror

Tests the health status logic that the banner uses.
GUI widget tests are minimal since they require real GTK.
"""

from datetime import UTC, datetime, timedelta

from pdfsigner.core.certificate.health_status import (
    HEALTH_COLORS,
    HEALTH_CSS_CLASSES,
    CertificateHealth,
    HealthLevel,
)


class TestHealthLevel:
    """Tests for HealthLevel enum and classification."""

    def test_from_days_ok(self):
        """Test OK level for >60 days."""
        assert HealthLevel.from_days(90) == HealthLevel.OK
        assert HealthLevel.from_days(61) == HealthLevel.OK
        assert HealthLevel.from_days(365) == HealthLevel.OK

    def test_from_days_warning(self):
        """Test WARNING level for 31-60 days."""
        assert HealthLevel.from_days(60) == HealthLevel.WARNING
        assert HealthLevel.from_days(45) == HealthLevel.WARNING
        assert HealthLevel.from_days(31) == HealthLevel.WARNING

    def test_from_days_alert(self):
        """Test ALERT level for 8-30 days."""
        assert HealthLevel.from_days(30) == HealthLevel.ALERT
        assert HealthLevel.from_days(20) == HealthLevel.ALERT
        assert HealthLevel.from_days(8) == HealthLevel.ALERT

    def test_from_days_critical(self):
        """Test CRITICAL level for 1-7 days."""
        assert HealthLevel.from_days(7) == HealthLevel.CRITICAL
        assert HealthLevel.from_days(5) == HealthLevel.CRITICAL
        assert HealthLevel.from_days(1) == HealthLevel.CRITICAL

    def test_from_days_expired(self):
        """Test EXPIRED level for <=0 days."""
        assert HealthLevel.from_days(0) == HealthLevel.EXPIRED
        assert HealthLevel.from_days(-1) == HealthLevel.EXPIRED
        assert HealthLevel.from_days(-100) == HealthLevel.EXPIRED

    def test_boundary_conditions(self):
        """Test exact boundary values."""
        # 60 days is WARNING (not OK)
        assert HealthLevel.from_days(60) == HealthLevel.WARNING

        # 30 days is ALERT (not WARNING)
        assert HealthLevel.from_days(30) == HealthLevel.ALERT

        # 7 days is CRITICAL (not ALERT)
        assert HealthLevel.from_days(7) == HealthLevel.CRITICAL

        # 0 days is EXPIRED (not CRITICAL)
        assert HealthLevel.from_days(0) == HealthLevel.EXPIRED


class TestCertificateHealth:
    """Tests for CertificateHealth dataclass."""

    def _create_health(self, days_remaining: int) -> CertificateHealth:
        """Create a CertificateHealth with given days remaining."""
        now = datetime.now(UTC)
        not_before = now - timedelta(days=365 - days_remaining)
        not_after = now + timedelta(days=days_remaining)

        return CertificateHealth(
            subject_cn="Test User",
            issuer_cn="Test CA",
            not_before=not_before,
            not_after=not_after,
        )

    def test_days_remaining_positive(self):
        """Test days_remaining for valid certificate."""
        health = self._create_health(45)
        # Allow 1 day tolerance due to time-of-day variations
        assert 44 <= health.days_remaining <= 45

    def test_days_remaining_zero(self):
        """Test days_remaining at expiry."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test",
            issuer_cn="CA",
            not_before=now - timedelta(days=365),
            not_after=now,
        )
        assert health.days_remaining == 0

    def test_days_remaining_negative_clamped(self):
        """Test days_remaining is clamped to 0 for expired certs."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Expired",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
        )
        assert health.days_remaining == 0

    def test_health_level_ok(self):
        """Test health_level property for OK certs."""
        health = self._create_health(90)
        assert health.health_level == HealthLevel.OK

    def test_health_level_warning(self):
        """Test health_level property for WARNING certs."""
        health = self._create_health(45)
        assert health.health_level == HealthLevel.WARNING

    def test_health_level_alert(self):
        """Test health_level property for ALERT certs."""
        health = self._create_health(20)
        assert health.health_level == HealthLevel.ALERT

    def test_health_level_critical(self):
        """Test health_level property for CRITICAL certs."""
        health = self._create_health(5)
        assert health.health_level == HealthLevel.CRITICAL

    def test_health_level_expired(self):
        """Test health_level property for EXPIRED certs."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Expired",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
        )
        assert health.health_level == HealthLevel.EXPIRED

    def test_is_expired_false(self):
        """Test is_expired for valid cert."""
        health = self._create_health(45)
        assert health.is_expired is False

    def test_is_expired_true(self):
        """Test is_expired for expired cert."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Expired",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
        )
        assert health.is_expired is True

    def test_lifetime_progress_half(self):
        """Test lifetime_progress at 50% used."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test",
            issuer_cn="CA",
            not_before=now - timedelta(days=182),
            not_after=now + timedelta(days=183),
        )
        assert 0.4 < health.lifetime_progress < 0.6

    def test_lifetime_progress_full(self):
        """Test lifetime_progress at 100% (expired)."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Expired",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
        )
        assert health.lifetime_progress == 1.0

    def test_css_class_mapping(self):
        """Test css_class property returns correct classes."""
        for level, expected_class in HEALTH_CSS_CLASSES.items():
            if level == HealthLevel.OK:
                health = self._create_health(90)
            elif level == HealthLevel.WARNING:
                health = self._create_health(45)
            elif level == HealthLevel.ALERT:
                health = self._create_health(20)
            elif level == HealthLevel.CRITICAL:
                health = self._create_health(5)
            else:  # EXPIRED
                now = datetime.now(UTC)
                health = CertificateHealth(
                    subject_cn="Expired",
                    issuer_cn="CA",
                    not_before=now - timedelta(days=400),
                    not_after=now - timedelta(days=35),
                )
            assert health.css_class == expected_class

    def test_color_mapping(self):
        """Test color property returns hex colors."""
        health = self._create_health(90)
        assert health.color == HEALTH_COLORS[HealthLevel.OK]

        health_warning = self._create_health(45)
        assert health_warning.color == HEALTH_COLORS[HealthLevel.WARNING]

    def test_status_icon(self):
        """Test status_icon property returns emoji."""
        health_ok = self._create_health(90)
        assert health_ok.status_icon == "✅"

        health_critical = self._create_health(5)
        assert health_critical.status_icon == "🚨"

    def test_status_text_ok(self):
        """Test status_text for valid cert."""
        health = self._create_health(45)
        # Allow for timing variations (44 or 45 days)
        assert "44 days" in health.status_text or "45 days" in health.status_text

    def test_status_text_tomorrow(self):
        """Test status_text for cert expiring tomorrow."""
        # Use 36 hours to ensure days_remaining = 1
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test",
            issuer_cn="CA",
            not_before=now - timedelta(days=364),
            not_after=now + timedelta(hours=36),
        )
        assert health.status_text == "Expires tomorrow"

    def test_status_text_expired(self):
        """Test status_text for expired cert."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Expired",
            issuer_cn="CA",
            not_before=now - timedelta(days=400),
            not_after=now - timedelta(days=35),
        )
        assert health.status_text == "Certificate expired"


class TestCertificateHealthEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_serial_number_optional(self):
        """Test that serial_number is optional and defaults to empty."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test",
            issuer_cn="CA",
            not_before=now - timedelta(days=100),
            not_after=now + timedelta(days=100),
        )
        assert health.serial_number == ""

    def test_serial_number_can_be_set(self):
        """Test that serial_number can be set."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Test",
            issuer_cn="CA",
            not_before=now - timedelta(days=100),
            not_after=now + timedelta(days=100),
            serial_number="ABC123",
        )
        assert health.serial_number == "ABC123"

    def test_zero_day_certificate(self):
        """Test certificate with same start and end date."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Zero Day",
            issuer_cn="CA",
            not_before=now,
            not_after=now,
        )
        assert health.days_remaining == 0
        assert health.lifetime_progress == 1.0
        assert health.is_expired is True

    def test_long_lived_certificate(self):
        """Test certificate with 10-year validity."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="Long Lived",
            issuer_cn="CA",
            not_before=now - timedelta(days=365),
            not_after=now + timedelta(days=3650),
        )
        assert health.health_level == HealthLevel.OK
        assert health.lifetime_progress < 0.2

    def test_subject_cn_unicode(self):
        """Test certificate with unicode characters in subject."""
        now = datetime.now(UTC)
        health = CertificateHealth(
            subject_cn="José García 日本語",
            issuer_cn="CA Internacional 中文",
            not_before=now - timedelta(days=100),
            not_after=now + timedelta(days=100),
        )
        assert "José García" in health.subject_cn
        assert "中文" in health.issuer_cn


class TestHealthConstants:
    """Tests for health level constants."""

    def test_all_levels_have_colors(self):
        """Test all health levels have a color mapping."""
        for level in HealthLevel:
            assert level in HEALTH_COLORS
            assert HEALTH_COLORS[level].startswith("#")

    def test_all_levels_have_css_classes(self):
        """Test all health levels have a CSS class mapping."""
        for level in HealthLevel:
            assert level in HEALTH_CSS_CLASSES
            assert HEALTH_CSS_CLASSES[level].startswith("cert-status-")

    def test_css_class_format(self):
        """Test CSS classes follow naming convention."""
        for level, css_class in HEALTH_CSS_CLASSES.items():
            assert css_class == f"cert-status-{level.value}"
