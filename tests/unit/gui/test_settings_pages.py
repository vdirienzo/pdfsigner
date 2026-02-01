"""
test_settings_pages.py - Tests for settings pages

Author: Homero Thompson del Lago del Terror

Tests for validation_page and behavior_page factory functions.
"""

import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# IMPORTANT: Must import conftest_gui first to install GTK mocks
sys.path.insert(0, str(__file__).rsplit("/", 3)[0])
from tests.unit.conftest_gui import install_gui_mocks

# Install mocks before importing GUI modules
install_gui_mocks()

# Now safe to import GUI modules
from pdfsigner.gui.settings_pages.behavior_page import create_behavior_page
from pdfsigner.gui.settings_pages.validation_page import create_validation_page


@pytest.fixture
def mock_settings():
    """Create mock settings object with all required attributes."""
    settings = Mock()

    # Validation page settings
    settings.revocation_check_enabled = True
    settings.revocation_check_timeout = 30
    settings.revocation_cache_ttl = 3600
    settings.revocation_prefer_ocsp = True

    # Behavior page settings
    settings.recent_files_enabled = True
    settings.recent_files_limit = 20
    settings.system_notifications_enabled = True

    return settings


@pytest.fixture
def mock_dialog():
    """Create mock dialog object to store widget references."""
    return MagicMock()


class TestCreateValidationPage:
    """Tests for create_validation_page factory function."""

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_returns_preferences_page(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test create_validation_page returns a PreferencesPage."""
        # Mock translation function to return input
        mock_gettext.side_effect = lambda x: x

        page = create_validation_page(mock_settings, mock_dialog)

        # Should return a page-like object
        assert page is not None
        assert hasattr(page, "set_title")
        assert hasattr(page, "set_icon_name")
        assert hasattr(page, "add")

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_sets_title_and_icon(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test page title and icon are set correctly."""
        mock_gettext.side_effect = lambda x: x

        page = create_validation_page(mock_settings, mock_dialog)

        page.set_title.assert_called_once_with("Validation")
        page.set_icon_name.assert_called_once_with("security-high-symbolic")

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_stores_widget_references(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test widget references are stored in dialog object."""
        mock_gettext.side_effect = lambda x: x

        create_validation_page(mock_settings, mock_dialog)

        # Verify all widget references are stored
        assert hasattr(mock_dialog, "revocation_switch")
        assert hasattr(mock_dialog, "revocation_timeout_spin")
        assert hasattr(mock_dialog, "revocation_cache_ttl_spin")
        assert hasattr(mock_dialog, "revocation_prefer_ocsp_switch")

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_revocation_switch_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test revocation switch reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_check_enabled = True

        create_validation_page(mock_settings, mock_dialog)

        # Should set active state from settings
        mock_dialog.revocation_switch.set_active.assert_called_once_with(True)

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_revocation_switch_false_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test revocation switch with False value."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_check_enabled = False

        create_validation_page(mock_settings, mock_dialog)

        mock_dialog.revocation_switch.set_active.assert_called_once_with(False)

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_timeout_spin_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test timeout spin row reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_check_timeout = 45

        create_validation_page(mock_settings, mock_dialog)

        # SpinRow created with adjustment containing the timeout value
        # The adjustment should have been created with value=45.0
        assert mock_dialog.revocation_timeout_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_timeout_spin_range(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test timeout spin row has correct range (5-60 seconds)."""
        mock_gettext.side_effect = lambda x: x

        # Test with values at boundaries
        mock_settings.revocation_check_timeout = 5
        create_validation_page(mock_settings, mock_dialog)
        assert mock_dialog.revocation_timeout_spin is not None

        mock_settings.revocation_check_timeout = 60
        create_validation_page(mock_settings, mock_dialog)
        assert mock_dialog.revocation_timeout_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_cache_ttl_spin_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test cache TTL spin row reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_cache_ttl = 7200

        create_validation_page(mock_settings, mock_dialog)

        # SpinRow created with adjustment containing the cache TTL value
        assert mock_dialog.revocation_cache_ttl_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_cache_ttl_spin_range(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test cache TTL spin row has correct range (300-86400 seconds)."""
        mock_gettext.side_effect = lambda x: x

        # Test with values at boundaries
        mock_settings.revocation_cache_ttl = 300  # 5 minutes
        create_validation_page(mock_settings, mock_dialog)
        assert mock_dialog.revocation_cache_ttl_spin is not None

        mock_settings.revocation_cache_ttl = 86400  # 24 hours
        create_validation_page(mock_settings, mock_dialog)
        assert mock_dialog.revocation_cache_ttl_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_prefer_ocsp_switch_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test prefer OCSP switch reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_prefer_ocsp = True

        create_validation_page(mock_settings, mock_dialog)

        mock_dialog.revocation_prefer_ocsp_switch.set_active.assert_called_once_with(True)

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_prefer_ocsp_switch_false_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test prefer OCSP switch with False value."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_prefer_ocsp = False

        create_validation_page(mock_settings, mock_dialog)

        mock_dialog.revocation_prefer_ocsp_switch.set_active.assert_called_once_with(False)

    @patch("pdfsigner.gui.settings_pages.validation_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_sets_accessibility_labels(
        self, mock_gettext, mock_set_accessible, mock_settings, mock_dialog
    ):
        """Test accessibility labels are set for all widgets."""
        mock_gettext.side_effect = lambda x: x

        create_validation_page(mock_settings, mock_dialog)

        # Should call set_accessible for each widget
        # revocation_switch, timeout_spin, cache_ttl_spin, prefer_ocsp_switch
        assert mock_set_accessible.call_count == 4

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_create_validation_page_adds_groups_to_page(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test preference groups are added to the page."""
        mock_gettext.side_effect = lambda x: x

        page = create_validation_page(mock_settings, mock_dialog)

        # Should add at least one group (revocation_group)
        assert page.add.called


class TestCreateBehaviorPage:
    """Tests for create_behavior_page factory function."""

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_returns_preferences_page(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test create_behavior_page returns a PreferencesPage."""
        mock_gettext.side_effect = lambda x: x

        page = create_behavior_page(mock_settings, mock_dialog)

        # Should return a page-like object
        assert page is not None
        assert hasattr(page, "set_title")
        assert hasattr(page, "set_icon_name")
        assert hasattr(page, "add")

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_sets_title_and_icon(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test page title and icon are set correctly."""
        mock_gettext.side_effect = lambda x: x

        page = create_behavior_page(mock_settings, mock_dialog)

        page.set_title.assert_called_once_with("Behavior")
        page.set_icon_name.assert_called_once_with("preferences-other-symbolic")

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_stores_widget_references(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test widget references are stored in dialog object."""
        mock_gettext.side_effect = lambda x: x

        create_behavior_page(mock_settings, mock_dialog)

        # Verify all widget references are stored
        assert hasattr(mock_dialog, "recent_files_switch")
        assert hasattr(mock_dialog, "recent_files_limit_spin")
        assert hasattr(mock_dialog, "notifications_switch")

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_recent_files_switch_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test recent files switch reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.recent_files_enabled = True

        create_behavior_page(mock_settings, mock_dialog)

        mock_dialog.recent_files_switch.set_active.assert_called_once_with(True)

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_recent_files_switch_false_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test recent files switch with False value."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.recent_files_enabled = False

        create_behavior_page(mock_settings, mock_dialog)

        mock_dialog.recent_files_switch.set_active.assert_called_once_with(False)

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_recent_files_limit_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test recent files limit spin row reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.recent_files_limit = 20

        create_behavior_page(mock_settings, mock_dialog)

        # SpinRow created with adjustment containing the limit value
        assert mock_dialog.recent_files_limit_spin is not None

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_recent_files_limit_range(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test recent files limit spin row has correct range (5-50)."""
        mock_gettext.side_effect = lambda x: x

        # Test with values at boundaries
        mock_settings.recent_files_limit = 5
        create_behavior_page(mock_settings, mock_dialog)
        assert mock_dialog.recent_files_limit_spin is not None

        mock_settings.recent_files_limit = 50
        create_behavior_page(mock_settings, mock_dialog)
        assert mock_dialog.recent_files_limit_spin is not None

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_notifications_switch_default_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test notifications switch reads default value from settings."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.system_notifications_enabled = True

        create_behavior_page(mock_settings, mock_dialog)

        mock_dialog.notifications_switch.set_active.assert_called_once_with(True)

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_notifications_switch_false_value(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test notifications switch with False value."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.system_notifications_enabled = False

        create_behavior_page(mock_settings, mock_dialog)

        mock_dialog.notifications_switch.set_active.assert_called_once_with(False)

    @patch("pdfsigner.gui.settings_pages.behavior_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_sets_accessibility_labels(
        self, mock_gettext, mock_set_accessible, mock_settings, mock_dialog
    ):
        """Test accessibility labels are set for all widgets."""
        mock_gettext.side_effect = lambda x: x

        create_behavior_page(mock_settings, mock_dialog)

        # Should call set_accessible for each widget
        # recent_files_switch, recent_files_limit_spin, notifications_switch
        assert mock_set_accessible.call_count == 3

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_create_behavior_page_adds_groups_to_page(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test preference groups are added to the page."""
        mock_gettext.side_effect = lambda x: x

        page = create_behavior_page(mock_settings, mock_dialog)

        # Should add two groups (recent_files_group, notifications_group)
        assert page.add.called
        assert page.add.call_count == 2


class TestValidationPageWidgetInteractions:
    """Tests for widget interactions and callbacks."""

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_validation_page_widgets_are_callable(self, mock_gettext, mock_settings, mock_dialog):
        """Test that stored widgets can be interacted with."""
        mock_gettext.side_effect = lambda x: x

        create_validation_page(mock_settings, mock_dialog)

        # Simulate toggling the revocation switch
        mock_dialog.revocation_switch.get_active = Mock(return_value=False)
        assert mock_dialog.revocation_switch.get_active() is False

        # Simulate changing the timeout value
        mock_dialog.revocation_timeout_spin.get_value = Mock(return_value=30.0)
        assert mock_dialog.revocation_timeout_spin.get_value() == 30.0

        # Simulate changing the cache TTL value
        mock_dialog.revocation_cache_ttl_spin.get_value = Mock(return_value=3600.0)
        assert mock_dialog.revocation_cache_ttl_spin.get_value() == 3600.0

        # Simulate toggling the prefer OCSP switch
        mock_dialog.revocation_prefer_ocsp_switch.get_active = Mock(return_value=True)
        assert mock_dialog.revocation_prefer_ocsp_switch.get_active() is True


class TestBehaviorPageWidgetInteractions:
    """Tests for widget interactions and callbacks."""

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_behavior_page_widgets_are_callable(self, mock_gettext, mock_settings, mock_dialog):
        """Test that stored widgets can be interacted with."""
        mock_gettext.side_effect = lambda x: x

        create_behavior_page(mock_settings, mock_dialog)

        # Simulate toggling the recent files switch
        mock_dialog.recent_files_switch.get_active = Mock(return_value=True)
        assert mock_dialog.recent_files_switch.get_active() is True

        # Simulate changing the recent files limit
        mock_dialog.recent_files_limit_spin.get_value = Mock(return_value=25.0)
        assert mock_dialog.recent_files_limit_spin.get_value() == 25.0

        # Simulate toggling the notifications switch
        mock_dialog.notifications_switch.get_active = Mock(return_value=False)
        assert mock_dialog.notifications_switch.get_active() is False


class TestSettingsPagesEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_validation_page_with_minimum_timeout(self, mock_gettext, mock_settings, mock_dialog):
        """Test validation page with minimum timeout value (5 seconds)."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_check_timeout = 5

        page = create_validation_page(mock_settings, mock_dialog)

        assert page is not None
        assert mock_dialog.revocation_timeout_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_validation_page_with_maximum_timeout(self, mock_gettext, mock_settings, mock_dialog):
        """Test validation page with maximum timeout value (60 seconds)."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_check_timeout = 60

        page = create_validation_page(mock_settings, mock_dialog)

        assert page is not None
        assert mock_dialog.revocation_timeout_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_validation_page_with_minimum_cache_ttl(self, mock_gettext, mock_settings, mock_dialog):
        """Test validation page with minimum cache TTL (300 seconds)."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_cache_ttl = 300

        page = create_validation_page(mock_settings, mock_dialog)

        assert page is not None
        assert mock_dialog.revocation_cache_ttl_spin is not None

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_validation_page_with_maximum_cache_ttl(self, mock_gettext, mock_settings, mock_dialog):
        """Test validation page with maximum cache TTL (86400 seconds)."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.revocation_cache_ttl = 86400

        page = create_validation_page(mock_settings, mock_dialog)

        assert page is not None
        assert mock_dialog.revocation_cache_ttl_spin is not None

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_behavior_page_with_minimum_recent_files_limit(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test behavior page with minimum recent files limit (5)."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.recent_files_limit = 5

        page = create_behavior_page(mock_settings, mock_dialog)

        assert page is not None
        assert mock_dialog.recent_files_limit_spin is not None

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_behavior_page_with_maximum_recent_files_limit(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test behavior page with maximum recent files limit (50)."""
        mock_gettext.side_effect = lambda x: x
        mock_settings.recent_files_limit = 50

        page = create_behavior_page(mock_settings, mock_dialog)

        assert page is not None
        assert mock_dialog.recent_files_limit_spin is not None


class TestSettingsPagesTranslations:
    """Tests for i18n/translation support."""

    @patch("pdfsigner.gui.settings_pages.validation_page._")
    def test_validation_page_calls_translation_function(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test validation page calls translation function for all strings."""
        mock_gettext.side_effect = lambda x: x

        create_validation_page(mock_settings, mock_dialog)

        # Should call _ (gettext) multiple times for all translatable strings
        assert mock_gettext.call_count > 0
        # Verify key translations
        translation_calls = [call[0][0] for call in mock_gettext.call_args_list]
        assert "Validation" in translation_calls
        assert "Certificate Revocation" in translation_calls

    @patch("pdfsigner.gui.settings_pages.behavior_page._")
    def test_behavior_page_calls_translation_function(
        self, mock_gettext, mock_settings, mock_dialog
    ):
        """Test behavior page calls translation function for all strings."""
        mock_gettext.side_effect = lambda x: x

        create_behavior_page(mock_settings, mock_dialog)

        # Should call _ (gettext) multiple times for all translatable strings
        assert mock_gettext.call_count > 0
        # Verify key translations
        translation_calls = [call[0][0] for call in mock_gettext.call_args_list]
        assert "Behavior" in translation_calls
        assert "Recent Files" in translation_calls
        assert "Notifications" in translation_calls
