"""
appearance_page.py - Appearance settings page

Author: Homero Thompson del Lago del Terror

Creates the appearance settings page with theme and language.
Auto-saves changes immediately when user modifies settings.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.i18n import SUPPORTED_LANGUAGES, _

# Theme options (display names need translation at runtime)
THEME_VALUES = ["system", "light", "dark"]


def _save_appearance_setting(key: str, value: str) -> None:
    """
    Save a single appearance setting to config file.

    Args:
        key: Setting key (theme, language)
        value: Setting value
    """
    from loguru import logger

    config_path = Path.home() / ".config" / "pdfsigner" / "config.toml"

    try:
        # Read existing config
        if config_path.exists():
            content = config_path.read_text()
            lines = content.split("\n")
        else:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            lines = ["# PDFSigner - Configuration"]

        # Find and update or append the setting
        key_found = False
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key} ="):
                lines[i] = f'{key} = "{value}"'
                key_found = True
                break

        if not key_found:
            lines.append(f'{key} = "{value}"')

        # Write back
        config_path.write_text("\n".join(lines))
        logger.debug(f"Auto-saved {key} = {value}")

    except Exception as e:
        logger.error(f"Failed to auto-save setting {key}: {e}")


def apply_theme(theme: str) -> None:
    """
    Apply theme setting.

    Args:
        theme: Theme value (system, light, dark)
    """
    style_manager = Adw.StyleManager.get_default()

    if theme == "light":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
    elif theme == "dark":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else:
        style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)


def create_appearance_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the appearance settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for callbacks

    Returns:
        Configured PreferencesPage
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Appearance"))
    page.set_icon_name("preferences-desktop-appearance-symbolic")

    # Group: Theme
    theme_group = Adw.PreferencesGroup()
    theme_group.set_title(_("Theme"))
    theme_group.set_description(_("Application color scheme"))

    # Theme selector
    theme_row = Adw.ComboRow()
    theme_row.set_title(_("Color scheme"))
    theme_row.set_subtitle(_("Choose light, dark, or follow system"))
    theme_row.set_accessible_name(_("Color scheme"))
    theme_row.set_accessible_description(_("Application theme"))

    theme_options = [_("System default"), _("Light"), _("Dark")]
    theme_list = Gtk.StringList.new(theme_options)
    theme_row.set_model(theme_list)

    # Set current selection
    try:
        current_idx = THEME_VALUES.index(settings.theme)
    except ValueError:
        current_idx = 0
    theme_row.set_selected(current_idx)
    theme_row.connect("notify::selected", lambda combo, param: _on_theme_changed(combo, dialog))

    theme_group.add(theme_row)
    page.add(theme_group)

    # Group: Language
    lang_group = Adw.PreferencesGroup()
    lang_group.set_title(_("Language"))
    lang_group.set_description(_("Interface language (restart required)"))

    lang_row = Adw.ComboRow()
    lang_row.set_title(_("Language"))
    lang_row.set_subtitle(_("Requires application restart"))
    lang_row.set_accessible_name(_("Language"))
    lang_row.set_accessible_description(_("Application language"))

    # Build language list
    lang_names = [_("System default")] + list(SUPPORTED_LANGUAGES.values())
    lang_codes = [""] + list(SUPPORTED_LANGUAGES.keys())

    lang_list = Gtk.StringList.new(lang_names)
    lang_row.set_model(lang_list)

    # Set current selection
    current_lang = settings.language
    try:
        if current_lang:
            current_idx = lang_codes.index(current_lang)
        else:
            current_idx = 0
    except ValueError:
        current_idx = 0
    lang_row.set_selected(current_idx)

    # Store lang_codes for callback
    dialog.lang_codes = lang_codes
    lang_row.connect("notify::selected", lambda combo, param: _on_language_changed(combo, dialog))

    lang_group.add(lang_row)
    page.add(lang_group)

    # Store references for saving
    dialog.theme_row = theme_row
    dialog.lang_row = lang_row

    return page


def _on_theme_changed(combo: Adw.ComboRow, dialog) -> None:
    """Applies theme change immediately and saves."""
    selected = combo.get_selected()
    theme = THEME_VALUES[selected]

    # Apply immediately
    apply_theme(theme)

    # Auto-save
    _save_appearance_setting("theme", theme)

    # Show toast
    if hasattr(dialog, "add_toast"):
        dialog.add_toast(Adw.Toast(title=_("Theme changed")))


def _on_language_changed(combo: Adw.ComboRow, dialog) -> None:
    """Handles language change with auto-save."""
    selected = combo.get_selected()
    lang_codes = getattr(dialog, "lang_codes", [""])

    if selected < len(lang_codes):
        lang = lang_codes[selected]

        # Auto-save
        _save_appearance_setting("language", lang)

        # Show toast with restart message
        if hasattr(dialog, "add_toast"):
            dialog.add_toast(Adw.Toast(title=_("Language changed. Restart to apply.")))


def get_selected_theme(dialog) -> str:
    """Gets the selected theme value."""
    if hasattr(dialog, "theme_row"):
        return THEME_VALUES[dialog.theme_row.get_selected()]
    return "system"


def get_selected_language(dialog) -> str:
    """Gets the selected language code."""
    if hasattr(dialog, "lang_row") and hasattr(dialog, "lang_codes"):
        return dialog.lang_codes[dialog.lang_row.get_selected()]
    return ""
