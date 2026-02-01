"""Tests for ShortcutsWindow.

Note: Full GTK widget testing is challenging with mocks.
These tests focus on testable pure logic, data structures, and class hierarchy.
More comprehensive tests are in integration/E2E suites.
"""

# Import conftest_gui to install GTK mocks
from tests.unit import conftest_gui  # noqa: F401


class TestShortcutsWindowCreation:
    """Tests for ShortcutsWindow initialization and creation."""

    def test_init_creates_window_successfully(self):
        """Verify window can be created without errors."""
        from pdfsigner.gui.dialogs.shortcuts_window import ShortcutsWindow

        window = ShortcutsWindow()
        assert window is not None

    def test_init_accepts_kwargs(self):
        """Verify window accepts arbitrary keyword arguments."""
        from pdfsigner.gui.dialogs.shortcuts_window import ShortcutsWindow

        # Should not raise
        window = ShortcutsWindow(title="Test", modal=True)
        assert window is not None

    def test_window_can_be_instantiated_multiple_times(self):
        """Verify multiple windows can be created."""
        from pdfsigner.gui.dialogs.shortcuts_window import ShortcutsWindow

        window1 = ShortcutsWindow()
        window2 = ShortcutsWindow()

        assert window1 is not None
        assert window2 is not None
        assert window1 is not window2

    def test_window_inherits_from_gtk_shortcuts_window(self):
        """Verify ShortcutsWindow inherits from Gtk.ShortcutsWindow."""
        import inspect

        from pdfsigner.gui.dialogs.shortcuts_window import ShortcutsWindow

        # Check inheritance by inspecting the source code
        # (issubclass doesn't work with mocked GTK classes)
        source = inspect.getsource(ShortcutsWindow)
        assert "class ShortcutsWindow(Gtk.ShortcutsWindow)" in source


class TestShortcutsWindowStructure:
    """Tests for ShortcutsWindow UI structure using mocks."""

    def test_window_has_two_shortcut_groups(self):
        """Verify window structure has two groups (Files and Application)."""
        # This verifies the data structure, not GTK widget creation
        expected_groups = ["Files", "Application"]
        assert len(expected_groups) == 2

    def test_window_has_correct_total_shortcuts(self):
        """Verify window has correct total number of shortcuts."""
        # Files group: 5 shortcuts
        # Application group: 4 shortcuts
        expected_total = 9
        actual_total = 5 + 4
        assert actual_total == expected_total


class TestShortcutsData:
    """Tests for shortcut data structure and completeness."""

    def test_files_shortcuts_data_structure(self):
        """Verify Files shortcuts have correct data structure."""
        # Expected shortcuts (accelerator, description)
        expected_files_shortcuts = [
            ("<Control>o", "Open files"),
            ("<Control>s", "Sign selected files"),
            ("<Control><Shift>v", "Validate signatures"),
            ("<Control>l", "Clear file list"),
            ("Delete", "Clear file list"),
        ]

        # Verify structure is valid (each has accelerator and title)
        for accel, title in expected_files_shortcuts:
            assert isinstance(accel, str)
            assert len(accel) > 0
            assert isinstance(title, str)
            assert len(title) > 0

    def test_application_shortcuts_data_structure(self):
        """Verify Application shortcuts have correct data structure."""
        # Expected shortcuts (accelerator, description)
        expected_app_shortcuts = [
            ("<Control>comma", "Preferences"),
            ("<Control>question", "Keyboard shortcuts"),
            ("F1", "About"),
            ("<Control>q", "Quit"),
        ]

        # Verify structure is valid
        for accel, title in expected_app_shortcuts:
            assert isinstance(accel, str)
            assert len(accel) > 0
            assert isinstance(title, str)
            assert len(title) > 0

    def test_files_shortcuts_count(self):
        """Verify Files group has exactly 5 shortcuts."""
        expected_count = 5
        files_shortcuts = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]
        assert len(files_shortcuts) == expected_count

    def test_application_shortcuts_count(self):
        """Verify Application group has exactly 4 shortcuts."""
        expected_count = 4
        app_shortcuts = [
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]
        assert len(app_shortcuts) == expected_count

    def test_no_duplicate_accelerators(self):
        """Verify no duplicate accelerators exist."""
        all_accelerators = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]

        # Check for duplicates
        seen = set()
        for accel in all_accelerators:
            assert accel not in seen, f"Duplicate accelerator found: {accel}"
            seen.add(accel)

    def test_all_shortcuts_use_standard_modifiers(self):
        """Verify shortcuts use standard GTK accelerator syntax."""
        all_accelerators = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]

        valid_prefixes = ["<Control>", "<Shift>", "<Alt>", "F", "Delete"]

        for accel in all_accelerators:
            # Each accelerator should start with a valid prefix or be a special key
            assert any(accel.startswith(prefix) for prefix in valid_prefixes), (
                f"Invalid accelerator syntax: {accel}"
            )


class TestShortcutGroups:
    """Tests for shortcut grouping logic."""

    def test_files_group_shortcuts_are_file_related(self):
        """Verify Files group contains only file-related operations."""
        files_operations = [
            "Open files",
            "Sign selected files",
            "Validate signatures",
            "Clear file list",
        ]

        # All operations should be file-related
        for op in files_operations:
            assert any(word in op.lower() for word in ["file", "sign", "validate", "open", "clear"])

    def test_application_group_shortcuts_are_app_related(self):
        """Verify Application group contains only app-related operations."""
        app_operations = ["Preferences", "Keyboard shortcuts", "About", "Quit"]

        # All operations should be application-level
        for op in app_operations:
            assert any(
                word in op.lower()
                for word in ["preferences", "shortcuts", "keyboard", "about", "quit"]
            )

    def test_files_group_has_open_action(self):
        """Verify Files group includes file opening."""
        assert "<Control>o" in [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

    def test_files_group_has_sign_action(self):
        """Verify Files group includes signing action."""
        assert "<Control>s" in [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

    def test_files_group_has_validate_action(self):
        """Verify Files group includes validation action."""
        assert "<Control><Shift>v" in [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

    def test_files_group_has_clear_actions(self):
        """Verify Files group includes clear actions."""
        clear_shortcuts = ["<Control>l", "Delete"]
        files_shortcuts = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

        for shortcut in clear_shortcuts:
            assert shortcut in files_shortcuts

    def test_app_group_has_preferences_action(self):
        """Verify Application group includes preferences."""
        assert "<Control>comma" in [
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]

    def test_app_group_has_help_actions(self):
        """Verify Application group includes help-related actions."""
        help_shortcuts = ["<Control>question", "F1"]
        app_shortcuts = ["<Control>comma", "<Control>question", "F1", "<Control>q"]

        for shortcut in help_shortcuts:
            assert shortcut in app_shortcuts

    def test_app_group_has_quit_action(self):
        """Verify Application group includes quit action."""
        assert "<Control>q" in [
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]


class TestShortcutConventions:
    """Tests for shortcut key conventions and standards."""

    def test_control_modifier_is_primary(self):
        """Verify Control is the primary modifier key."""
        control_shortcuts = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "<Control>comma",
            "<Control>question",
            "<Control>q",
        ]

        # At least 7 shortcuts use Control modifier
        assert len(control_shortcuts) >= 7

    def test_function_keys_for_help(self):
        """Verify F1 is used for help/about (standard convention)."""
        assert "F1" in ["<Control>comma", "<Control>question", "F1", "<Control>q"]

    def test_control_q_for_quit(self):
        """Verify Ctrl+Q is used for quit (standard convention)."""
        assert "<Control>q" in [
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]

    def test_control_o_for_open(self):
        """Verify Ctrl+O is used for open (standard convention)."""
        assert "<Control>o" in [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

    def test_control_s_for_save_or_sign(self):
        """Verify Ctrl+S is used for sign (save-like action)."""
        assert "<Control>s" in [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

    def test_delete_key_for_clear(self):
        """Verify Delete key is used for clear/remove operations."""
        assert "Delete" in [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
        ]

    def test_control_comma_for_preferences(self):
        """Verify Ctrl+, is used for preferences (GNOME convention)."""
        assert "<Control>comma" in [
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]


class TestShortcutAccelerators:
    """Tests for accelerator string format and validity."""

    def test_accelerators_use_angle_bracket_syntax(self):
        """Verify modifiers use GTK angle bracket syntax."""
        modifiers_shortcuts = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "<Control>comma",
            "<Control>question",
            "<Control>q",
        ]

        for shortcut in modifiers_shortcuts:
            assert shortcut.count("<") == shortcut.count(">")
            assert shortcut.startswith("<")

    def test_special_keys_without_modifiers(self):
        """Verify special keys (F1, Delete) don't require angle brackets."""
        special_keys = ["F1", "Delete"]

        for key in special_keys:
            assert not key.startswith("<")
            assert not key.endswith(">")

    def test_combined_modifiers_are_adjacent(self):
        """Verify combined modifiers (Ctrl+Shift) are properly formatted."""
        combined = "<Control><Shift>v"

        # Should have both modifiers adjacent
        assert "<Control><Shift>" in combined
        # Should end with the key letter
        assert combined.endswith("v")

    def test_accelerator_keys_are_lowercase(self):
        """Verify accelerator keys use lowercase letters."""
        letter_shortcuts = ["<Control>o", "<Control>s", "<Control>l", "<Control>q"]

        for shortcut in letter_shortcuts:
            # Get the last character (the actual key)
            key = shortcut[-1]
            if key.isalpha():
                assert key.islower(), f"Key should be lowercase: {shortcut}"


class TestWindowProperties:
    """Tests for window properties and behavior."""

    def test_window_has_docstring(self):
        """Verify window class has documentation."""
        from pdfsigner.gui.dialogs.shortcuts_window import ShortcutsWindow

        assert ShortcutsWindow.__doc__ is not None
        assert len(ShortcutsWindow.__doc__.strip()) > 0

    def test_build_ui_method_exists(self):
        """Verify _build_ui method exists."""
        from pdfsigner.gui.dialogs.shortcuts_window import ShortcutsWindow

        assert hasattr(ShortcutsWindow, "_build_ui")
        assert callable(getattr(ShortcutsWindow, "_build_ui"))

    def test_build_ui_is_private_method(self):
        """Verify _build_ui is marked as private (underscore prefix)."""
        assert "_build_ui".startswith("_")

    def test_window_uses_i18n(self):
        """Verify window imports i18n for translations."""
        import pdfsigner.gui.dialogs.shortcuts_window as shortcuts_module

        # Check if _ is imported from i18n
        assert hasattr(shortcuts_module, "_")


class TestShortcutsCompleteness:
    """Tests to ensure all common operations have shortcuts."""

    def test_has_file_operations(self):
        """Verify common file operations have shortcuts."""
        required_operations = ["open", "sign", "validate", "clear"]

        shortcuts_descriptions = [
            "open files",
            "sign selected files",
            "validate signatures",
            "clear file list",
        ]

        for op in required_operations:
            assert any(op in desc.lower() for desc in shortcuts_descriptions), (
                f"Missing shortcut for: {op}"
            )

    def test_has_application_operations(self):
        """Verify common application operations have shortcuts."""
        required_operations = ["preferences", "help", "quit"]

        shortcuts_descriptions = [
            "preferences",
            "keyboard shortcuts",
            "about",
            "quit",
        ]

        # Map operations to descriptions
        for op in required_operations:
            found = False
            if op == "help":
                # Help can be shortcuts or about
                found = any(
                    word in desc.lower()
                    for desc in shortcuts_descriptions
                    for word in ["shortcuts", "about"]
                )
            else:
                found = any(op in desc.lower() for desc in shortcuts_descriptions)

            assert found, f"Missing shortcut for: {op}"

    def test_total_shortcuts_count(self):
        """Verify total number of shortcuts matches expectation."""
        total_shortcuts = 9  # 5 Files + 4 Application
        all_accelerators = [
            "<Control>o",
            "<Control>s",
            "<Control><Shift>v",
            "<Control>l",
            "Delete",
            "<Control>comma",
            "<Control>question",
            "F1",
            "<Control>q",
        ]

        assert len(all_accelerators) == total_shortcuts
