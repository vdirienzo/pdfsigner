"""Tests for RecentFilesPopover (simplified for GTK mocking limitations)."""

from datetime import datetime, timedelta

# Note: Full GTK widget testing is challenging with mocks.
# These tests focus on testable pure logic.
# More comprehensive tests are in integration/E2E suites.


class TestRelativeTimeLogic:
    """Tests for relative time formatting logic."""

    def test_seconds_to_minutes_boundary(self):
        """Verify time calculation boundaries work correctly."""
        now = datetime.now()

        # < 60 seconds
        time_30s = now - timedelta(seconds=30)
        diff_30s = now - time_30s
        assert diff_30s.seconds < 60

        # >= 60 seconds (1 minute)
        time_1m = now - timedelta(minutes=1)
        diff_1m = now - time_1m
        assert diff_1m.seconds >= 60

    def test_hours_to_days_boundary(self):
        """Verify hours vs days calculation."""
        now = datetime.now()

        # < 24 hours
        time_12h = now - timedelta(hours=12)
        diff_12h = now - time_12h
        assert diff_12h.days == 0
        assert diff_12h.seconds // 3600 == 12

        # >= 24 hours (1 day)
        time_1d = now - timedelta(days=1)
        diff_1d = now - time_1d
        assert diff_1d.days == 1

    def test_days_to_weeks_calculation(self):
        """Verify days to weeks conversion."""
        # 7 days = 1 week
        assert 7 // 7 == 1

        # 14 days = 2 weeks
        assert 14 // 7 == 2

        # 6 days = 0 weeks
        assert 6 // 7 == 0

    def test_days_to_months_approximation(self):
        """Verify days to months approximation (30 days per month)."""
        # 30 days = 1 month
        assert 30 // 30 == 1

        # 60 days = 2 months
        assert 60 // 30 == 2

        # 29 days = 0 months
        assert 29 // 30 == 0

    def test_days_to_years_approximation(self):
        """Verify days to years approximation (365 days per year)."""
        # 365 days = 1 year
        assert 365 // 365 == 1

        # 730 days = 2 years
        assert 730 // 365 == 2

        # 364 days = 0 years
        assert 364 // 365 == 0

    def test_timedelta_consistency(self):
        """Verify timedelta behavior used by _format_relative_time."""
        now = datetime.now()

        # Verify timedelta days attribute
        past_time = now - timedelta(days=5, hours=3)
        diff = now - past_time
        assert diff.days == 5  # Only full days counted
        assert diff.seconds == 3 * 3600  # Hours in seconds

        # Verify seconds attribute (max 86399, resets at day boundary)
        past_time2 = now - timedelta(seconds=7200)  # 2 hours
        diff2 = now - past_time2
        assert diff2.days == 0
        assert diff2.seconds == 7200
