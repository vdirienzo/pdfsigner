"""
test_keyboard_shortcuts.py - Tests for keyboard shortcuts

Author: Homero Thompson del Lago del Terror

Tests for keyboard shortcut registration, action creation,
and correct mapping between shortcuts and actions.

Note: These tests read the source code to verify keyboard shortcut
configurations, as full GTK mocking is complex for GUI tests.
"""

import inspect

from tests.unit.conftest_gui import _adw, _gio, _glib, _gtk  # noqa: F401


class TestAppActionDefinitions:
    """Tests for application-level action definitions in source code."""

    def test_create_actions_defines_open_action(self):
        """Verify 'open' action is defined in create_actions method."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_open = Gio.SimpleAction.new("open", None)' in source
        assert "action_open.connect" in source

    def test_create_actions_defines_preferences_action(self):
        """Verify 'preferences' action is defined in create_actions method."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_preferences = Gio.SimpleAction.new("preferences", None)' in source
        assert "action_preferences.connect" in source

    def test_create_actions_defines_shortcuts_action(self):
        """Verify 'shortcuts' action is defined in create_actions method."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_shortcuts = Gio.SimpleAction.new("shortcuts", None)' in source
        assert "action_shortcuts.connect" in source

    def test_create_actions_defines_about_action(self):
        """Verify 'about' action is defined in create_actions method."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_about = Gio.SimpleAction.new("about", None)' in source
        assert "action_about.connect" in source

    def test_create_actions_defines_quit_action(self):
        """Verify 'quit' action is defined in create_actions method."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_quit = Gio.SimpleAction.new("quit", None)' in source
        assert "action_quit.connect" in source

    def test_create_actions_adds_actions_to_app(self):
        """Verify actions are added to the application."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        # Verify add_action is called for each action
        assert source.count("self.add_action(action_") >= 5


class TestWindowActionDefinitions:
    """Tests for window-level action definitions in source code."""

    def test_create_actions_defines_sign_action(self):
        """Verify 'sign' window action is defined in _create_actions method."""
        from pdfsigner.gui.main_window import MainWindow

        source = inspect.getsource(MainWindow._create_actions)
        assert 'action_sign = Gio.SimpleAction.new("sign", None)' in source
        assert "action_sign.connect" in source

    def test_create_actions_defines_validate_action(self):
        """Verify 'validate' window action is defined in _create_actions method."""
        from pdfsigner.gui.main_window import MainWindow

        source = inspect.getsource(MainWindow._create_actions)
        assert 'action_validate = Gio.SimpleAction.new("validate", None)' in source
        assert "action_validate.connect" in source

    def test_create_actions_defines_clear_action(self):
        """Verify 'clear' window action is defined in _create_actions method."""
        from pdfsigner.gui.main_window import MainWindow

        source = inspect.getsource(MainWindow._create_actions)
        assert 'action_clear = Gio.SimpleAction.new("clear", None)' in source
        assert "action_clear.connect" in source

    def test_create_actions_adds_actions_to_window(self):
        """Verify actions are added to the window."""
        from pdfsigner.gui.main_window import MainWindow

        source = inspect.getsource(MainWindow._create_actions)
        # Verify add_action is called for each action
        assert source.count("self.add_action(action_") >= 3


class TestKeyboardShortcutMapping:
    """Tests for keyboard shortcut registration and mapping."""

    def test_shortcut_ctrl_o_maps_to_app_open(self):
        """Verify Ctrl+O is mapped to app.open action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("app.open", ["<Control>o"])' in source

    def test_shortcut_ctrl_comma_maps_to_app_preferences(self):
        """Verify Ctrl+, is mapped to app.preferences action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("app.preferences", ["<Control>comma"])' in source

    def test_shortcut_ctrl_question_maps_to_app_shortcuts(self):
        """Verify Ctrl+? is mapped to app.shortcuts action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("app.shortcuts", ["<Control>question"])' in source

    def test_shortcut_ctrl_q_maps_to_app_quit(self):
        """Verify Ctrl+Q is mapped to app.quit action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("app.quit", ["<Control>q"])' in source

    def test_shortcut_f1_maps_to_app_about(self):
        """Verify F1 is mapped to app.about action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("app.about", ["F1"])' in source

    def test_shortcut_ctrl_s_maps_to_win_sign(self):
        """Verify Ctrl+S is mapped to win.sign action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("win.sign", ["<Control>s"])' in source

    def test_shortcut_ctrl_shift_v_maps_to_win_validate(self):
        """Verify Ctrl+Shift+V is mapped to win.validate action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("win.validate", ["<Control><Shift>v"])' in source

    def test_shortcut_ctrl_l_and_delete_map_to_win_clear(self):
        """Verify Ctrl+L and Delete are mapped to win.clear action."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'self.set_accels_for_action("win.clear", ["<Control>l", "Delete"])' in source

    def test_all_eight_shortcuts_are_registered(self):
        """Verify all 8 keyboard shortcuts are registered."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        # Count set_accels_for_action calls
        assert source.count("self.set_accels_for_action") == 8


class TestShortcutFormat:
    """Tests for GTK accelerator format compliance."""

    def test_shortcuts_use_gtk_angle_bracket_format(self):
        """Verify shortcuts use GTK angle bracket format like <Control>."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        # Check that Control is wrapped in angle brackets
        assert "<Control>" in source
        # Check that Shift is wrapped in angle brackets
        assert "<Shift>" in source

    def test_app_actions_use_app_prefix(self):
        """Verify application-level shortcuts use 'app.' prefix."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        # Count app.* actions (open, preferences, shortcuts, quit, about)
        assert source.count('"app.') == 5

    def test_window_actions_use_win_prefix(self):
        """Verify window-level shortcuts use 'win.' prefix."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        # Count win.* actions (sign, validate, clear)
        assert source.count('"win.') == 3


class TestStandardShortcutConventions:
    """Tests for verifying shortcuts follow standard conventions."""

    def test_open_uses_standard_ctrl_o_shortcut(self):
        """Verify open files uses standard Ctrl+O shortcut."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert '"<Control>o"' in source

    def test_preferences_uses_standard_ctrl_comma_shortcut(self):
        """Verify preferences uses standard Ctrl+, shortcut."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert '"<Control>comma"' in source

    def test_quit_uses_standard_ctrl_q_shortcut(self):
        """Verify quit uses standard Ctrl+Q shortcut."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert '"<Control>q"' in source

    def test_save_uses_standard_ctrl_s_shortcut(self):
        """Verify sign (save) uses standard Ctrl+S shortcut."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert '"<Control>s"' in source

    def test_delete_key_used_for_clear_action(self):
        """Verify Delete key is used for clearing/removing items."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert '"Delete"' in source

    def test_f1_used_for_help_about(self):
        """Verify F1 is used for help/about."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert '"F1"' in source


class TestShortcutActionConsistency:
    """Tests for consistency between actions and shortcuts."""

    def test_each_app_action_has_corresponding_shortcut(self):
        """Verify each app action has a keyboard shortcut."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)

        # Extract action names
        action_names = ["open", "preferences", "shortcuts", "about", "quit"]

        for action in action_names:
            # Verify action is created
            assert f'action_{action} = Gio.SimpleAction.new("{action}", None)' in source
            # Verify action has a shortcut
            assert f'"app.{action}"' in source

    def test_each_window_action_has_corresponding_shortcut(self):
        """Verify each window action has a keyboard shortcut."""
        from pdfsigner.gui.app import PDFSignerApp
        from pdfsigner.gui.main_window import MainWindow

        app_source = inspect.getsource(PDFSignerApp.create_actions)
        window_source = inspect.getsource(MainWindow._create_actions)

        # Window actions
        action_names = ["sign", "validate", "clear"]

        for action in action_names:
            # Verify action is created in window
            assert f'action_{action} = Gio.SimpleAction.new("{action}", None)' in window_source
            # Verify shortcut is registered in app
            assert f'"win.{action}"' in app_source

    def test_no_duplicate_shortcuts(self):
        """Verify no duplicate keyboard shortcuts are defined."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)

        # Extract all shortcuts (this is a simplified check)
        shortcuts = [
            "<Control>o",
            "<Control>comma",
            "<Control>question",
            "<Control>q",
            "F1",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
        ]

        for shortcut in shortcuts:
            # Each shortcut should appear exactly once
            assert source.count(f'"{shortcut}"') == 1


class TestActionCallbackConnections:
    """Tests for verifying action callbacks are connected."""

    def test_open_action_connects_to_callback(self):
        """Verify open action connects to on_open_action callback."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_open.connect("activate", self.on_open_action)' in source

    def test_preferences_action_connects_to_callback(self):
        """Verify preferences action connects to on_preferences_action callback."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_preferences.connect("activate", self.on_preferences_action)' in source

    def test_shortcuts_action_connects_to_callback(self):
        """Verify shortcuts action connects to on_shortcuts_action callback."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_shortcuts.connect("activate", self.on_shortcuts_action)' in source

    def test_about_action_connects_to_callback(self):
        """Verify about action connects to on_about_action callback."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_about.connect("activate", self.on_about_action)' in source

    def test_quit_action_connects_to_callback(self):
        """Verify quit action connects to on_quit_action callback."""
        from pdfsigner.gui.app import PDFSignerApp

        source = inspect.getsource(PDFSignerApp.create_actions)
        assert 'action_quit.connect("activate", self.on_quit_action)' in source
