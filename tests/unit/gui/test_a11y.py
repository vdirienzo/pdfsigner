"""
test_a11y.py - Tests for accessibility helpers

Author: Homero Thompson del Lago del Terror

Comprehensive tests for GTK4 accessibility utility functions.
"""

from unittest.mock import MagicMock

import tests.unit.conftest_gui  # noqa: F401


class TestSetAccessibleName:
    """Tests for set_accessible_name() function."""

    def test_set_accessible_name_calls_update_property(self):
        """set_accessible_name calls widget.update_property with LABEL."""
        from pdfsigner.gui.a11y import set_accessible_name

        # Create mock widget without spec to allow update_property
        mock_widget = MagicMock()

        # Call function
        set_accessible_name(mock_widget, "Test Button")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == ["Test Button"]

    def test_set_accessible_name_with_empty_string(self):
        """set_accessible_name accepts empty string."""
        from pdfsigner.gui.a11y import set_accessible_name

        mock_widget = MagicMock()

        # Should not raise
        set_accessible_name(mock_widget, "")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [""]

    def test_set_accessible_name_with_unicode(self):
        """set_accessible_name handles unicode characters."""
        from pdfsigner.gui.a11y import set_accessible_name

        mock_widget = MagicMock()
        unicode_name = "Botón de cierre ✓"

        set_accessible_name(mock_widget, unicode_name)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [unicode_name]

    def test_set_accessible_name_with_long_string(self):
        """set_accessible_name handles long strings."""
        from pdfsigner.gui.a11y import set_accessible_name

        mock_widget = MagicMock()
        long_name = "A" * 1000

        set_accessible_name(mock_widget, long_name)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [long_name]

    def test_set_accessible_name_with_multiline_text(self):
        """set_accessible_name handles multiline text."""
        from pdfsigner.gui.a11y import set_accessible_name

        mock_widget = MagicMock()
        multiline = "Line 1\nLine 2\nLine 3"

        set_accessible_name(mock_widget, multiline)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [multiline]


class TestSetAccessibleDescription:
    """Tests for set_accessible_description() function."""

    def test_set_accessible_description_calls_update_property(self):
        """set_accessible_description calls widget.update_property with DESCRIPTION."""
        from pdfsigner.gui.a11y import set_accessible_description

        mock_widget = MagicMock()

        set_accessible_description(mock_widget, "This button closes the window")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == ["This button closes the window"]

    def test_set_accessible_description_with_empty_string(self):
        """set_accessible_description accepts empty string."""
        from pdfsigner.gui.a11y import set_accessible_description

        mock_widget = MagicMock()

        set_accessible_description(mock_widget, "")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [""]

    def test_set_accessible_description_with_unicode(self):
        """set_accessible_description handles unicode characters."""
        from pdfsigner.gui.a11y import set_accessible_description

        mock_widget = MagicMock()
        unicode_desc = "Descripción con acentos y símbolos: €, ñ, ü"

        set_accessible_description(mock_widget, unicode_desc)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [unicode_desc]

    def test_set_accessible_description_with_detailed_text(self):
        """set_accessible_description handles detailed text."""
        from pdfsigner.gui.a11y import set_accessible_description

        mock_widget = MagicMock()
        detailed_desc = (
            "This button performs the following actions: "
            "1) Validates the input, "
            "2) Processes the data, "
            "3) Saves the result."
        )

        set_accessible_description(mock_widget, detailed_desc)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [detailed_desc]


class TestSetAccessible:
    """Tests for set_accessible() combined function."""

    def test_set_accessible_with_name_only(self):
        """set_accessible sets only name when description is None."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(mock_widget, name="Save Button")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == ["Save Button"]

    def test_set_accessible_with_description_only(self):
        """set_accessible sets only description when name is None."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(mock_widget, description="Saves the current document")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == ["Saves the current document"]

    def test_set_accessible_with_both_name_and_description(self):
        """set_accessible sets both name and description."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(
            mock_widget,
            name="Save Button",
            description="Saves the current document to disk",
        )

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 2
        assert values == ["Save Button", "Saves the current document to disk"]

    def test_set_accessible_with_neither_name_nor_description(self):
        """set_accessible does nothing when both parameters are None."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(mock_widget)

        # update_property should not be called
        mock_widget.update_property.assert_not_called()

    def test_set_accessible_with_explicit_none_values(self):
        """set_accessible handles explicit None values correctly."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(mock_widget, name=None, description=None)

        # update_property should not be called
        mock_widget.update_property.assert_not_called()

    def test_set_accessible_with_empty_strings(self):
        """set_accessible handles empty strings (not None)."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        # Empty strings are valid values (different from None)
        set_accessible(mock_widget, name="", description="")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 2
        assert values == ["", ""]

    def test_set_accessible_preserves_property_order(self):
        """set_accessible maintains consistent property order."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(
            mock_widget,
            name="Button",
            description="Description",
        )

        # Verify properties are added in correct order (LABEL first, then DESCRIPTION)
        call_args = mock_widget.update_property.call_args
        props, values = call_args[0]

        # Verify we have 2 properties and values match expected order
        assert len(props) == 2
        assert values == ["Button", "Description"]


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_set_accessible_name_with_special_characters(self):
        """set_accessible_name handles special characters."""
        from pdfsigner.gui.a11y import set_accessible_name

        mock_widget = MagicMock()
        special_chars = "<script>alert('test')</script>"

        # Should handle without sanitization (GTK's responsibility)
        set_accessible_name(mock_widget, special_chars)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [special_chars]

    def test_set_accessible_description_with_quotes(self):
        """set_accessible_description handles quotes."""
        from pdfsigner.gui.a11y import set_accessible_description

        mock_widget = MagicMock()
        text_with_quotes = "This is a \"test\" with 'quotes'"

        set_accessible_description(mock_widget, text_with_quotes)

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 1
        assert values == [text_with_quotes]

    def test_set_accessible_with_name_empty_and_description_set(self):
        """set_accessible handles empty name with valid description."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        set_accessible(mock_widget, name="", description="Valid description")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 2
        assert values == ["", "Valid description"]

    def test_set_accessible_with_whitespace_only(self):
        """set_accessible handles whitespace-only strings."""
        from pdfsigner.gui.a11y import set_accessible

        mock_widget = MagicMock()

        # Whitespace strings are valid (not None)
        set_accessible(mock_widget, name="   ", description="\t\n")

        # Verify update_property was called with correct values
        call_args = mock_widget.update_property.call_args
        assert call_args is not None
        properties, values = call_args[0]
        assert len(properties) == 2
        assert values == ["   ", "\t\n"]


class TestPropertyAccess:
    """Test that Gtk.AccessibleProperty enums are accessed correctly."""

    def test_label_property_constant_exists(self):
        """Verify Gtk.AccessibleProperty.LABEL exists."""
        from gi.repository import Gtk

        # Should not raise AttributeError
        label_prop = Gtk.AccessibleProperty.LABEL
        assert label_prop is not None

    def test_description_property_constant_exists(self):
        """Verify Gtk.AccessibleProperty.DESCRIPTION exists."""
        from gi.repository import Gtk

        # Should not raise AttributeError
        desc_prop = Gtk.AccessibleProperty.DESCRIPTION
        assert desc_prop is not None

    def test_properties_are_distinct(self):
        """Verify LABEL and DESCRIPTION are different properties."""
        from gi.repository import Gtk

        label_prop = Gtk.AccessibleProperty.LABEL
        desc_prop = Gtk.AccessibleProperty.DESCRIPTION

        assert label_prop != desc_prop


class TestFunctionSignatures:
    """Test function signature compatibility."""

    def test_set_accessible_name_type_annotations(self):
        """Verify set_accessible_name has correct type annotations."""
        from pdfsigner.gui.a11y import set_accessible_name

        annotations = set_accessible_name.__annotations__

        assert "widget" in annotations
        assert "name" in annotations
        assert annotations["return"] is None

    def test_set_accessible_description_type_annotations(self):
        """Verify set_accessible_description has correct type annotations."""
        from pdfsigner.gui.a11y import set_accessible_description

        annotations = set_accessible_description.__annotations__

        assert "widget" in annotations
        assert "description" in annotations
        assert annotations["return"] is None

    def test_set_accessible_type_annotations(self):
        """Verify set_accessible has correct type annotations."""
        from pdfsigner.gui.a11y import set_accessible

        annotations = set_accessible.__annotations__

        assert "widget" in annotations
        assert "name" in annotations
        assert "description" in annotations
        assert annotations["return"] is None


class TestModuleImports:
    """Test module imports and dependencies."""

    def test_a11y_module_imports(self):
        """Module imports without errors."""

        # Should not raise
        from pdfsigner.gui import a11y

        assert a11y is not None

    def test_all_functions_exported(self):
        """All accessibility functions are importable."""
        from pdfsigner.gui.a11y import (
            set_accessible,
            set_accessible_description,
            set_accessible_name,
        )

        assert set_accessible_name is not None
        assert set_accessible_description is not None
        assert set_accessible is not None

    def test_gtk_dependency_available(self):
        """GTK4 is available via gi.repository."""
        from gi.repository import Gtk

        assert Gtk is not None
        assert hasattr(Gtk, "Widget")
        assert hasattr(Gtk, "AccessibleProperty")


class TestRealWorldUsage:
    """Test real-world usage scenarios."""

    def test_button_accessibility_setup(self):
        """Typical button accessibility setup."""

        from pdfsigner.gui.a11y import set_accessible

        mock_button = MagicMock()

        set_accessible(
            mock_button,
            name="Sign Document",
            description="Digitally sign the selected PDF document with your certificate",
        )

        mock_button.update_property.assert_called_once()

    def test_entry_accessibility_setup(self):
        """Typical entry field accessibility setup."""

        from pdfsigner.gui.a11y import set_accessible

        mock_entry = MagicMock()

        set_accessible(
            mock_entry,
            name="Certificate PIN",
            description="Enter your smart card PIN to unlock the certificate",
        )

        mock_entry.update_property.assert_called_once()

    def test_icon_button_with_name_only(self):
        """Icon button typically needs only name."""

        from pdfsigner.gui.a11y import set_accessible_name

        mock_icon_button = MagicMock()

        # Icon buttons often just need a name since the icon is visual
        set_accessible_name(mock_icon_button, "Close")

        mock_icon_button.update_property.assert_called_once()

    def test_dialog_accessibility_setup(self):
        """Dialog window accessibility setup."""

        from pdfsigner.gui.a11y import set_accessible

        mock_dialog = MagicMock()

        set_accessible(
            mock_dialog,
            name="Certificate Selection",
            description="Select a certificate from your smart card to sign documents",
        )

        mock_dialog.update_property.assert_called_once()

    def test_multiple_widgets_batch_setup(self):
        """Setting up accessibility for multiple widgets."""
        from pdfsigner.gui.a11y import set_accessible

        widgets_config = [
            ("Sign Button", "Sign the document"),
            ("Cancel Button", "Cancel the signing operation"),
            ("Settings Button", "Open application settings"),
        ]

        for name, desc in widgets_config:
            mock_widget = MagicMock()
            set_accessible(mock_widget, name=name, description=desc)
            # Each widget should have update_property called once
            mock_widget.update_property.assert_called_once()
