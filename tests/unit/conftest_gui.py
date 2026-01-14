"""
conftest_gui.py - Setup for GUI tests

Author: Homero Thompson del Lago del Terror

Installs GTK mocks before any GUI module is imported.
Import this at the top of GUI test files.
"""

import sys
from unittest.mock import MagicMock


def _create_gtk_mock():
    """Create comprehensive GTK mock that supports inheritance."""

    class MockMeta(type):
        """Metaclass that makes any class instantiable."""

        def __call__(cls, *args, **kwargs):
            instance = MagicMock()
            instance.__class__ = cls
            return instance

    class GtkBase(metaclass=MockMeta):
        """Base for GTK widget mocks."""

        def __init__(self, *args, **kwargs):
            pass

        def __init_subclass__(cls, **kwargs):
            pass

    # Create mock module structure
    mock_gtk = MagicMock()
    mock_adw = MagicMock()
    mock_glib = MagicMock()

    # GLib.idle_add executes immediately for testing
    mock_glib.idle_add = lambda func, *args: func(*args)

    # ResponseType enum
    mock_gtk.ResponseType = MagicMock()
    mock_gtk.ResponseType.OK = 1
    mock_gtk.ResponseType.CANCEL = 2
    mock_gtk.ResponseType.CLOSE = 3

    # Orientation enum
    mock_gtk.Orientation = MagicMock()
    mock_gtk.Orientation.HORIZONTAL = 0
    mock_gtk.Orientation.VERTICAL = 1

    # Common GTK classes - these need to be classes that can be subclassed
    for widget_name in [
        "Widget",
        "Window",
        "ApplicationWindow",
        "Dialog",
        "Box",
        "Label",
        "Entry",
        "Button",
        "CheckButton",
        "ProgressBar",
        "ListBox",
        "ListBoxRow",
        "ScrolledWindow",
        "Frame",
        "Grid",
        "Spinner",
        "Image",
        "DrawingArea",
        "TextView",
        "ComboBoxText",
        "Switch",
        "Scale",
        "Adjustment",
        "FileChooserNative",
        "FileFilter",
        "DropTarget",
        "DragSource",
        "EventControllerKey",
    ]:
        setattr(mock_gtk, widget_name, GtkBase)

    # Adw classes
    for widget_name in [
        "Application",
        "ApplicationWindow",
        "HeaderBar",
        "StatusPage",
        "PreferencesDialog",
        "PreferencesPage",
        "PreferencesGroup",
        "PreferencesRow",
        "ActionRow",
        "SwitchRow",
        "ComboRow",
        "EntryRow",
        "PasswordEntryRow",
        "SpinRow",
        "ExpanderRow",
        "MessageDialog",
        "Toast",
        "ToastOverlay",
        "Clamp",
        "WindowTitle",
        "Bin",
        "Carousel",
        "ViewStack",
        "ViewSwitcher",
        "NavigationView",
        "NavigationPage",
        "ToolbarView",
        "Banner",
    ]:
        setattr(mock_adw, widget_name, GtkBase)

    # Adw.StyleManager
    mock_style_manager = MagicMock()
    mock_adw.StyleManager = MagicMock()
    mock_adw.StyleManager.get_default = MagicMock(return_value=mock_style_manager)

    # Adw.ColorScheme enum
    mock_adw.ColorScheme = MagicMock()
    mock_adw.ColorScheme.DEFAULT = 0
    mock_adw.ColorScheme.FORCE_LIGHT = 1
    mock_adw.ColorScheme.FORCE_DARK = 4

    return mock_gtk, mock_adw, mock_glib


def install_gui_mocks():
    """Install all GTK/Adw mocks into sys.modules."""
    mock_gtk, mock_adw, mock_glib = _create_gtk_mock()

    # Create gi mock
    mock_gi = MagicMock()
    mock_gi.require_version = MagicMock()

    # Repository mock
    mock_repository = MagicMock()
    mock_repository.Gtk = mock_gtk
    mock_repository.Adw = mock_adw
    mock_repository.GLib = mock_glib
    mock_repository.Gdk = MagicMock()
    mock_repository.GdkPixbuf = MagicMock()
    mock_repository.Gio = MagicMock()
    mock_repository.Pango = MagicMock()

    mock_gi.repository = mock_repository

    # Install in sys.modules
    sys.modules["gi"] = mock_gi
    sys.modules["gi.repository"] = mock_repository
    sys.modules["gi.repository.Gtk"] = mock_gtk
    sys.modules["gi.repository.Adw"] = mock_adw
    sys.modules["gi.repository.GLib"] = mock_glib
    sys.modules["gi.repository.Gdk"] = mock_repository.Gdk
    sys.modules["gi.repository.GdkPixbuf"] = mock_repository.GdkPixbuf
    sys.modules["gi.repository.Gio"] = mock_repository.Gio
    sys.modules["gi.repository.Pango"] = mock_repository.Pango

    return mock_gtk, mock_adw, mock_glib


# Install mocks immediately when this module is imported
_gtk, _adw, _glib = install_gui_mocks()
