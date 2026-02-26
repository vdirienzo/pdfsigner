"""
test_eidas_page.py - Unit tests for eIDAS settings page

Author: Homero Thompson del Lago del Terror

Tests for create_eidas_page factory function and its helper builders.
"""

import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Install GTK mocks before importing GUI modules
sys.path.insert(0, str(__file__).rsplit("/", 3)[0])
from tests.unit.conftest_gui import install_gui_mocks

install_gui_mocks()

from pdfsigner.gui.settings_pages.eidas_page import (
    _SEAL_APPEARANCES,
    _SEAL_TYPES,
    _VALIDATION_MODES,
    EU_EEA_TERRITORIES,
    create_eidas_page,
)


@pytest.fixture
def mock_settings():
    """Create mock settings object with all eIDAS-related attributes."""
    settings = Mock()

    # Core eIDAS settings
    settings.eidas_enabled = True
    settings.eidas_enforce_qualified = False
    settings.eidas_validation_mode = "eutl"

    # Trusted lists settings
    settings.eidas_cache_days = 7
    settings.eidas_auto_update = True
    settings.eidas_eutl_territories = []  # empty = all selected

    # Remote signing settings
    settings.remote_signing_enabled = False
    settings.remote_signing_qtsp_preset = "custom"
    settings.remote_signing_service_url = ""
    settings.remote_signing_timeout = 30
    settings.remote_signing_verify_ssl = True

    # Seal settings
    settings.seal_enabled = False
    settings.seal_default_type = "advanced"
    settings.seal_appearance = "stamp"
    settings.seal_include_timestamp = True

    return settings


@pytest.fixture
def mock_dialog():
    """Create mock dialog object to store widget references."""
    return MagicMock()


# ============================================================================
# TestCreateEidasPage
# ============================================================================


class TestCreateEidasPage:
    """Tests for create_eidas_page factory function."""

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_returns_preferences_page(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Verify function returns something (not None)."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        page = create_eidas_page(mock_settings, mock_dialog)

        assert page is not None

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_page_title_set(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Title is 'eIDAS / EU'."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        page = create_eidas_page(mock_settings, mock_dialog)

        page.set_title.assert_called_once_with("eIDAS / EU")

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_page_icon_set(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Icon is 'globe-symbolic'."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        page = create_eidas_page(mock_settings, mock_dialog)

        page.set_icon_name.assert_called_once_with("globe-symbolic")


# ============================================================================
# TestWidgetReferences
# ============================================================================


class TestWidgetReferences:
    """Tests for widget references stored on dialog."""

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_core_refs_stored(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Dialog has core eIDAS widget references stored."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        create_eidas_page(mock_settings, mock_dialog)

        assert hasattr(mock_dialog, "eidas_enabled_switch")
        assert hasattr(mock_dialog, "eidas_enforce_qualified_switch")
        assert hasattr(mock_dialog, "eidas_validation_mode_combo")

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_eutl_refs_stored(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Dialog has eidas_cache_days_spin, eidas_auto_update_switch, eidas_territory_checks."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        create_eidas_page(mock_settings, mock_dialog)

        assert hasattr(mock_dialog, "eidas_cache_days_spin")
        assert hasattr(mock_dialog, "eidas_auto_update_switch")
        assert hasattr(mock_dialog, "eidas_territory_checks")

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_remote_signing_refs_stored(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Dialog has remote_signing_enabled_switch, remote_signing_preset_combo, etc."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        create_eidas_page(mock_settings, mock_dialog)

        assert hasattr(mock_dialog, "remote_signing_enabled_switch")
        assert hasattr(mock_dialog, "remote_signing_preset_combo")
        assert hasattr(mock_dialog, "remote_signing_url_entry")
        assert hasattr(mock_dialog, "remote_signing_timeout_spin")
        assert hasattr(mock_dialog, "remote_signing_verify_ssl_switch")

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_seal_refs_stored(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Dialog has seal_enabled_switch, seal_type_combo, etc."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        create_eidas_page(mock_settings, mock_dialog)

        assert hasattr(mock_dialog, "seal_enabled_switch")
        assert hasattr(mock_dialog, "seal_type_combo")
        assert hasattr(mock_dialog, "seal_appearance_combo")
        assert hasattr(mock_dialog, "seal_include_timestamp_switch")

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_qtsp_preset_keys_stored(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """dialog._qtsp_preset_keys is a list with at least 3 entries."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x

        create_eidas_page(mock_settings, mock_dialog)

        assert hasattr(mock_dialog, "_qtsp_preset_keys")
        assert isinstance(mock_dialog._qtsp_preset_keys, list)
        assert len(mock_dialog._qtsp_preset_keys) >= 3


# ============================================================================
# TestTerritorySelection
# ============================================================================


class TestTerritorySelection:
    """Tests for territory constants and default selection."""

    def test_territory_count(self):
        """EU_EEA_TERRITORIES has 30 entries."""
        assert len(EU_EEA_TERRITORIES) == 30

    @patch("pdfsigner.gui.settings_pages.eidas_page.set_accessible")
    @patch("pdfsigner.gui.settings_pages.eidas_page._")
    def test_all_selected_by_default(self, mock_gettext, mock_a11y, mock_settings, mock_dialog):
        """Empty territory list means all checkboxes active."""
        mock_gettext.side_effect = lambda x, **kw: x.format(**kw) if kw else x
        mock_settings.eidas_eutl_territories = []

        create_eidas_page(mock_settings, mock_dialog)

        # eidas_territory_checks is a dict[str, CheckButton]
        checks = mock_dialog.eidas_territory_checks
        assert isinstance(checks, dict)
        assert len(checks) == 30
        # All check buttons should have set_active(True) called
        for code, check in checks.items():
            check.set_active.assert_any_call(True)


# ============================================================================
# TestConstants
# ============================================================================


class TestConstants:
    """Tests for module-level constant lists."""

    def test_validation_modes(self):
        """_VALIDATION_MODES has 3 entries."""
        assert len(_VALIDATION_MODES) == 3
        assert "eutl" in _VALIDATION_MODES
        assert "custom" in _VALIDATION_MODES
        assert "offline" in _VALIDATION_MODES

    def test_seal_types(self):
        """_SEAL_TYPES has 3 entries."""
        assert len(_SEAL_TYPES) == 3
        assert "basic" in _SEAL_TYPES
        assert "advanced" in _SEAL_TYPES
        assert "qualified" in _SEAL_TYPES

    def test_seal_appearances(self):
        """_SEAL_APPEARANCES has 4 entries."""
        assert len(_SEAL_APPEARANCES) == 4
        assert "invisible" in _SEAL_APPEARANCES
        assert "stamp" in _SEAL_APPEARANCES
        assert "banner" in _SEAL_APPEARANCES
        assert "logo" in _SEAL_APPEARANCES
