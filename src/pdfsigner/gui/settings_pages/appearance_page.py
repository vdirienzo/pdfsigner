"""
appearance_page.py - Appearance settings page

Author: Homero Thompson del Lago del Terror

Creates the appearance settings page with theme, accent color, and language.
Auto-saves changes immediately when user modifies settings.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk

from pdfsigner.i18n import SUPPORTED_LANGUAGES, _

# Global CSS provider for accent colors
_accent_css_provider: Gtk.CssProvider | None = None

# Theme options (display names need translation at runtime)
THEME_VALUES = ["system", "light", "dark"]

# Accent color options (GNOME/Adwaita palette)
ACCENT_COLORS = {
    "blue": "#3584e4",
    "teal": "#2190a4",
    "green": "#3a944a",
    "yellow": "#c88800",
    "orange": "#ed5b00",
    "red": "#e62d42",
    "pink": "#d56199",
    "purple": "#9141ac",
    "slate": "#6f8396",
}


def _save_appearance_setting(key: str, value: str) -> None:
    """
    Save a single appearance setting to config file.

    Args:
        key: Setting key (theme, accent_color, language)
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


def apply_accent_color(color_name: str) -> None:
    """
    Apply accent color globally via CSS with high priority.

    Args:
        color_name: Name of the color from ACCENT_COLORS
    """
    global _accent_css_provider

    color_hex = ACCENT_COLORS.get(color_name, ACCENT_COLORS["blue"])

    # CSS with high priority targeting libadwaita widgets
    css = f"""
        @define-color accent_bg_color {color_hex};
        @define-color accent_fg_color white;
        @define-color accent_color {color_hex};

        /* Suggested action buttons */
        .suggested-action,
        button.suggested-action,
        button.suggested-action.text-button,
        button.suggested-action.flat {{
            background-color: {color_hex} !important;
            color: white !important;
        }}

        .suggested-action:hover,
        button.suggested-action:hover {{
            background-color: shade({color_hex}, 0.9) !important;
        }}

        .suggested-action:active,
        button.suggested-action:active {{
            background-color: shade({color_hex}, 0.8) !important;
        }}

        /* Accent class */
        .accent {{
            color: {color_hex} !important;
        }}

        /* Switches */
        switch:checked {{
            background-color: {color_hex} !important;
        }}

        switch:checked slider {{
            background-color: white !important;
        }}

        /* Checkboxes and radios */
        check:checked,
        checkbutton check:checked,
        radio:checked,
        radiobutton radio:checked {{
            background-color: {color_hex} !important;
            color: white !important;
        }}

        /* Scale/slider */
        scale trough highlight,
        scale > trough > highlight {{
            background-color: {color_hex} !important;
        }}

        /* Progress bars */
        progressbar > trough > progress,
        progressbar trough progress {{
            background-color: {color_hex} !important;
        }}

        /* Selection */
        selection,
        *:selected {{
            background-color: alpha({color_hex}, 0.3) !important;
        }}

        /* Links */
        link,
        .link {{
            color: {color_hex} !important;
        }}

        /* Navigation sidebar */
        .navigation-sidebar row:selected {{
            background-color: alpha({color_hex}, 0.15) !important;
        }}

        /* Entry focus */
        entry:focus,
        .entry:focus {{
            outline-color: {color_hex} !important;
        }}

        /* Spin buttons */
        spinbutton:focus {{
            outline-color: {color_hex} !important;
        }}
    """

    display = Gdk.Display.get_default()
    if display is None:
        return

    # Remove old provider if exists
    if _accent_css_provider is not None:
        Gtk.StyleContext.remove_provider_for_display(display, _accent_css_provider)

    # Create and apply new provider with USER priority (highest)
    _accent_css_provider = Gtk.CssProvider()
    _accent_css_provider.load_from_data(css.encode())

    # Use STYLE_PROVIDER_PRIORITY_USER (800) for highest priority
    Gtk.StyleContext.add_provider_for_display(
        display, _accent_css_provider, Gtk.STYLE_PROVIDER_PRIORITY_USER
    )


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

    # Accent color selector
    accent_group = Adw.PreferencesGroup()
    accent_group.set_title(_("Accent Color"))
    accent_group.set_description(_("Primary color for buttons and highlights"))

    color_flow = Gtk.FlowBox()
    color_flow.set_selection_mode(Gtk.SelectionMode.SINGLE)
    color_flow.set_max_children_per_line(9)
    color_flow.set_min_children_per_line(5)
    color_flow.set_column_spacing(8)
    color_flow.set_row_spacing(8)
    color_flow.set_margin_top(12)
    color_flow.set_margin_bottom(12)
    color_flow.set_halign(Gtk.Align.CENTER)

    # Create color buttons
    current_accent = settings.accent_color
    for i, (color_name, color_hex) in enumerate(ACCENT_COLORS.items()):
        color_btn = _create_color_button(color_name, color_hex)
        color_flow.insert(color_btn, -1)

        # Select current color
        if color_name == current_accent:
            color_flow.select_child(color_flow.get_child_at_index(i))

    color_flow.connect(
        "child-activated", lambda fb, child: _on_accent_color_selected(fb, child, dialog)
    )

    accent_row = Adw.ActionRow()
    accent_row.set_child(color_flow)
    accent_group.add(accent_row)

    page.add(theme_group)
    page.add(accent_group)

    # Group: Language
    lang_group = Adw.PreferencesGroup()
    lang_group.set_title(_("Language"))
    lang_group.set_description(_("Interface language (restart required)"))

    lang_row = Adw.ComboRow()
    lang_row.set_title(_("Language"))
    lang_row.set_subtitle(_("Requires application restart"))

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

    # Group: Accessibility
    a11y_group = Adw.PreferencesGroup()
    a11y_group.set_title(_("Accessibility"))
    a11y_group.set_description(_("Options to improve accessibility"))

    # High contrast mode
    high_contrast_row = Adw.SwitchRow()
    high_contrast_row.set_title(_("High contrast"))
    high_contrast_row.set_subtitle(_("Increase contrast for better visibility"))
    high_contrast_row.set_active(False)
    a11y_group.add(high_contrast_row)

    # Reduce motion
    reduce_motion_row = Adw.SwitchRow()
    reduce_motion_row.set_title(_("Reduce motion"))
    reduce_motion_row.set_subtitle(_("Minimize animations"))
    reduce_motion_row.set_active(False)
    a11y_group.add(reduce_motion_row)

    # Large text
    large_text_row = Adw.SwitchRow()
    large_text_row.set_title(_("Large text"))
    large_text_row.set_subtitle(_("Use larger font sizes"))
    large_text_row.set_active(False)
    a11y_group.add(large_text_row)

    page.add(a11y_group)

    # Store references for saving
    dialog.theme_row = theme_row
    dialog.lang_row = lang_row
    dialog.accent_color_flow = color_flow
    dialog.high_contrast_row = high_contrast_row
    dialog.reduce_motion_row = reduce_motion_row
    dialog.large_text_row = large_text_row

    return page


def _create_color_button(color_name: str, color_hex: str) -> Gtk.Button:
    """Creates a circular color button."""
    btn = Gtk.Button()
    btn.set_size_request(36, 36)
    btn.add_css_class("circular")
    btn.set_tooltip_text(color_name.title())

    # Set background color via CSS
    css_provider = Gtk.CssProvider()
    css = f"""
        button {{
            background-color: {color_hex};
            min-width: 36px;
            min-height: 36px;
            border-radius: 18px;
            border: 2px solid alpha(white, 0.1);
        }}
        button:hover {{
            border: 2px solid alpha(white, 0.3);
        }}
        button:checked, button:active {{
            border: 3px solid white;
        }}
    """
    css_provider.load_from_data(css.encode())

    style_context = btn.get_style_context()
    style_context.add_provider(css_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    # Store color name for retrieval
    btn.color_name = color_name

    return btn


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


def _on_accent_color_selected(flow_box: Gtk.FlowBox, child: Gtk.FlowBoxChild, dialog) -> None:
    """Handles accent color selection with auto-save."""
    btn = child.get_child()
    if hasattr(btn, "color_name"):
        color_name = btn.color_name
        dialog.selected_accent_color = color_name

        # Apply immediately
        apply_accent_color(color_name)

        # Auto-save
        _save_appearance_setting("accent_color", color_name)

        # Show toast
        if hasattr(dialog, "add_toast"):
            dialog.add_toast(Adw.Toast(title=_("Accent color changed")))


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


def get_selected_accent_color(dialog) -> str:
    """Gets the selected accent color."""
    if hasattr(dialog, "selected_accent_color"):
        return dialog.selected_accent_color
    return "blue"
