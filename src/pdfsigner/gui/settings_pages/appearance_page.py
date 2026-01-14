"""
appearance_page.py - Appearance settings page

Author: Homero Thompson del Lago del Terror

Creates the appearance settings page with theme, accent color, and language.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.i18n import SUPPORTED_LANGUAGES

# Theme options
THEME_OPTIONS = ["System default", "Light", "Dark"]
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
    page.set_title("Appearance")
    page.set_icon_name("preferences-desktop-appearance-symbolic")

    # Group: Theme
    theme_group = Adw.PreferencesGroup()
    theme_group.set_title("Theme")
    theme_group.set_description("Application color scheme")

    # Theme selector
    theme_row = Adw.ComboRow()
    theme_row.set_title("Color scheme")
    theme_row.set_subtitle("Choose light, dark, or follow system")

    theme_list = Gtk.StringList.new(THEME_OPTIONS)
    theme_row.set_model(theme_list)

    # Set current selection
    try:
        current_idx = THEME_VALUES.index(settings.theme)
    except ValueError:
        current_idx = 0
    theme_row.set_selected(current_idx)
    theme_row.connect("notify::selected", lambda combo, param: _on_theme_changed(combo))

    theme_group.add(theme_row)

    # Accent color selector
    accent_group = Adw.PreferencesGroup()
    accent_group.set_title("Accent Color")
    accent_group.set_description("Primary color for buttons and highlights")

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
    lang_group.set_title("Language")
    lang_group.set_description("Interface language")

    lang_row = Adw.ComboRow()
    lang_row.set_title("Language")
    lang_row.set_subtitle("Restart required to apply")

    # Build language list
    lang_names = ["System default"] + list(SUPPORTED_LANGUAGES.values())
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

    lang_group.add(lang_row)
    page.add(lang_group)

    # Group: Accessibility
    a11y_group = Adw.PreferencesGroup()
    a11y_group.set_title("Accessibility")
    a11y_group.set_description("Options to improve accessibility")

    # High contrast mode
    high_contrast_row = Adw.SwitchRow()
    high_contrast_row.set_title("High contrast")
    high_contrast_row.set_subtitle("Increase contrast for better visibility")
    high_contrast_row.set_active(False)
    a11y_group.add(high_contrast_row)

    # Reduce motion
    reduce_motion_row = Adw.SwitchRow()
    reduce_motion_row.set_title("Reduce motion")
    reduce_motion_row.set_subtitle("Minimize animations")
    reduce_motion_row.set_active(False)
    a11y_group.add(reduce_motion_row)

    # Large text
    large_text_row = Adw.SwitchRow()
    large_text_row.set_title("Large text")
    large_text_row.set_subtitle("Use larger font sizes")
    large_text_row.set_active(False)
    a11y_group.add(large_text_row)

    page.add(a11y_group)

    # Store references for saving
    dialog.theme_row = theme_row
    dialog.lang_row = lang_row
    dialog.lang_codes = lang_codes
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


def _on_theme_changed(combo: Adw.ComboRow) -> None:
    """Applies theme change immediately."""
    selected = combo.get_selected()
    theme = THEME_VALUES[selected]

    style_manager = Adw.StyleManager.get_default()

    if theme == "light":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
    elif theme == "dark":
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else:
        style_manager.set_color_scheme(Adw.ColorScheme.DEFAULT)


def _on_accent_color_selected(flow_box: Gtk.FlowBox, child: Gtk.FlowBoxChild, dialog) -> None:
    """Handles accent color selection."""
    btn = child.get_child()
    if hasattr(btn, "color_name"):
        dialog.selected_accent_color = btn.color_name


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
