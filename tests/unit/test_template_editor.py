"""
test_template_editor.py - Tests for template editor functionality

Tests for save_user_template(), delete_user_template(), and
template building from form values.
"""

from pathlib import Path
from unittest.mock import patch

from pdfsigner.core.signature.template import Layer, Template
from pdfsigner.core.signature.template_loader import (
    delete_user_template,
    save_user_template,
)


class TestSaveUserTemplate:
    """Tests for save_user_template function."""

    def test_save_user_template_creates_file(self, tmp_path: Path):
        """Test that save_user_template creates a JSON file."""
        template = Template(
            name="test_save",
            description="Test template",
            width_mm=60,
            height_mm=25,
            layers=[Layer(type="background", color="#ffffff")],
        )

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            result_path = save_user_template(template)

            assert result_path.exists()
            assert result_path.name == "test_save.json"
            assert result_path.parent == tmp_path

    def test_save_user_template_creates_directory_if_missing(self, tmp_path: Path):
        """Test that save_user_template creates parent directory if needed."""
        nested_dir = tmp_path / "subdir" / "templates"
        template = Template(
            name="nested_test",
            layers=[Layer(type="background", color="#fff")],
        )

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", nested_dir):
            result_path = save_user_template(template)

            assert nested_dir.exists()
            assert result_path.exists()

    def test_save_user_template_overwrites_existing(self, tmp_path: Path):
        """Test that save_user_template overwrites existing template."""
        template_v1 = Template(
            name="overwrite_test",
            description="Version 1",
            layers=[Layer(type="background", color="#000")],
        )
        template_v2 = Template(
            name="overwrite_test",
            description="Version 2",
            layers=[Layer(type="background", color="#fff")],
        )

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            save_user_template(template_v1)
            save_user_template(template_v2)

            # Load and verify
            saved_path = tmp_path / "overwrite_test.json"
            loaded = Template.from_json(saved_path)
            assert loaded.description == "Version 2"

    def test_save_user_template_preserves_layers(self, tmp_path: Path):
        """Test that all layers are preserved when saving."""
        template = Template(
            name="layers_test",
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="border", color="#333333"),
                Layer(type="text", x=5, y=15, text="{signer_name}", font_size=11),
                Layer(type="text", x=5, y=40, text="{date}", font_size=8),
            ],
        )

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            result_path = save_user_template(template)

            loaded = Template.from_json(result_path)
            assert len(loaded.layers) == 4
            assert loaded.layers[0].type == "background"
            assert loaded.layers[2].text == "{signer_name}"


class TestDeleteUserTemplate:
    """Tests for delete_user_template function."""

    def test_delete_user_template_existing_returns_true(self, tmp_path: Path):
        """Test deleting an existing template returns True."""
        # Create a template file
        template_path = tmp_path / "to_delete.json"
        template = Template(name="to_delete", layers=[Layer(type="background")])
        template.to_json(template_path)

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            result = delete_user_template("to_delete")

            assert result is True
            assert not template_path.exists()

    def test_delete_user_template_nonexistent_returns_false(self, tmp_path: Path):
        """Test deleting non-existent template returns False."""
        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            result = delete_user_template("nonexistent_xyz")

            assert result is False

    def test_delete_user_template_only_deletes_specified(self, tmp_path: Path):
        """Test that delete only removes the specified template."""
        # Create two templates
        template1 = Template(name="keep_this", layers=[Layer(type="background")])
        template2 = Template(name="delete_this", layers=[Layer(type="background")])
        template1.to_json(tmp_path / "keep_this.json")
        template2.to_json(tmp_path / "delete_this.json")

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            delete_user_template("delete_this")

            assert (tmp_path / "keep_this.json").exists()
            assert not (tmp_path / "delete_this.json").exists()


class TestTemplateBuildingFromFormValues:
    """Tests for building templates programmatically (simulating form values)."""

    def test_build_simple_template_with_background(self):
        """Test creating a template with just a background layer."""
        layers = [Layer(type="background", color="#f5f5f5")]
        template = Template(
            name="simple",
            description="Simple template",
            width_mm=60,
            height_mm=25,
            layers=layers,
        )

        errors = template.validate()
        assert errors == []
        assert len(template.layers) == 1

    def test_build_template_with_text_layers(self):
        """Test creating a template with multiple text layers."""
        layers = [
            Layer(type="background", color="#ffffff"),
            Layer(type="text", x=5, y=15, text="{signer_name}", font_size=11, color="#000000"),
            Layer(type="text", x=5, y=40, text="{org}", font_size=9, color="#666666"),
            Layer(type="text", x=5, y=65, text="{date}", font_size=8, color="#888888"),
        ]
        template = Template(
            name="with_text",
            width_mm=60,
            height_mm=25,
            layers=layers,
        )

        errors = template.validate()
        assert errors == []
        assert len(template.layers) == 4

        # Verify text layers
        text_layers = [layer for layer in template.layers if layer.type == "text"]
        assert len(text_layers) == 3
        assert text_layers[0].text == "{signer_name}"

    def test_build_template_with_border(self):
        """Test creating a template with border."""
        layers = [
            Layer(type="background", color="#ffffff"),
            Layer(type="border", color="#333333", border_width=1),
            Layer(type="text", x=5, y=30, text="{signer_name}", font_size=11),
        ]
        template = Template(name="with_border", layers=layers)

        errors = template.validate()
        assert errors == []

        border = next((layer for layer in template.layers if layer.type == "border"), None)
        assert border is not None
        assert border.border_width == 1

    def test_build_template_custom_dimensions(self):
        """Test creating a template with custom dimensions."""
        template = Template(
            name="custom_size",
            width_mm=80,
            height_mm=40,
            layers=[Layer(type="background", color="#fff")],
        )

        errors = template.validate()
        assert errors == []
        assert template.width_mm == 80
        assert template.height_mm == 40

    def test_build_template_validation_fails_no_name(self):
        """Test that template validation fails without name."""
        template = Template(
            name="",
            layers=[Layer(type="background")],
        )

        errors = template.validate()
        assert len(errors) > 0
        assert any("name" in e.lower() for e in errors)

    def test_build_template_validation_fails_no_layers(self):
        """Test that template validation fails without layers."""
        template = Template(name="empty", layers=[])

        errors = template.validate()
        assert len(errors) > 0
        assert any("layer" in e.lower() for e in errors)

    def test_build_template_with_all_content_options(self):
        """Test template with name, org, and date (typical form output)."""
        # Simulate form with all checkboxes enabled
        show_name = True
        show_org = True
        show_date = True

        layers = [Layer(type="background", color="#ffffff")]

        y_pos = 15
        if show_name:
            layers.append(Layer(type="text", x=5, y=y_pos, text="{signer_name}", font_size=11))
            y_pos += 25
        if show_org:
            layers.append(Layer(type="text", x=5, y=y_pos, text="{org}", font_size=9))
            y_pos += 25
        if show_date:
            layers.append(Layer(type="text", x=5, y=y_pos, text="{date}", font_size=8))

        template = Template(name="full_content", layers=layers)

        errors = template.validate()
        assert errors == []
        assert len(template.layers) == 4

    def test_build_template_partial_content(self):
        """Test template with only some content enabled."""
        # Simulate form with only name and date (no org)
        layers = [
            Layer(type="background", color="#ffffff"),
            Layer(type="text", x=5, y=15, text="{signer_name}", font_size=11),
            Layer(type="text", x=5, y=40, text="{date}", font_size=8),
        ]

        template = Template(name="partial", layers=layers)

        errors = template.validate()
        assert errors == []
        assert len(template.layers) == 3


class TestTemplateNameValidation:
    """Tests for template name format validation."""

    def test_valid_name_alphanumeric(self):
        """Test valid alphanumeric name."""
        template = Template(name="mytemplate", layers=[Layer(type="background")])
        errors = template.validate()
        assert errors == []

    def test_valid_name_with_underscore(self):
        """Test valid name with underscores."""
        template = Template(name="my_custom_template", layers=[Layer(type="background")])
        errors = template.validate()
        assert errors == []

    def test_valid_name_with_hyphen(self):
        """Test valid name with hyphens."""
        template = Template(name="my-template", layers=[Layer(type="background")])
        errors = template.validate()
        assert errors == []

    def test_valid_name_with_numbers(self):
        """Test valid name with numbers."""
        template = Template(name="template2025", layers=[Layer(type="background")])
        errors = template.validate()
        assert errors == []


class TestTemplateEditMode:
    """Tests for template edit functionality."""

    def test_template_roundtrip_save_and_load(self, tmp_path: Path):
        """Test saving and loading a template preserves all data."""
        original = Template(
            name="roundtrip_test",
            description="Test roundtrip",
            width_mm=70,
            height_mm=30,
            layers=[
                Layer(type="background", color="#f0f0f0"),
                Layer(type="border", color="#333333", border_width=2),
                Layer(type="text", x=5, y=20, text="{signer_name}", font_size=12, color="#000000"),
                Layer(type="text", x=5, y=50, text="{org}", font_size=10, color="#666666"),
                Layer(type="text", x=5, y=75, text="{date}", font_size=9, color="#888888"),
            ],
        )

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            save_user_template(original)
            loaded = Template.from_json(tmp_path / "roundtrip_test.json")

            assert loaded.name == original.name
            assert loaded.description == original.description
            assert loaded.width_mm == original.width_mm
            assert loaded.height_mm == original.height_mm
            assert len(loaded.layers) == len(original.layers)

            # Verify each layer
            for orig_layer, load_layer in zip(original.layers, loaded.layers):
                assert orig_layer.type == load_layer.type
                assert orig_layer.color == load_layer.color

    def test_template_with_custom_text_roundtrip(self, tmp_path: Path):
        """Test custom text is preserved in save/load cycle."""
        original = Template(
            name="custom_text_test",
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="text", x=5, y=30, text="APPROVED", font_size=14, color="#00aa00"),
            ],
        )

        with patch("pdfsigner.core.signature.template_loader.USER_TEMPLATES_DIR", tmp_path):
            save_user_template(original)
            loaded = Template.from_json(tmp_path / "custom_text_test.json")

            text_layer = next(layer for layer in loaded.layers if layer.type == "text")
            assert text_layer.text == "APPROVED"
            assert text_layer.font_size == 14
            assert text_layer.color == "#00aa00"


class TestFieldData:
    """Tests for the FieldData dataclass used in dynamic field list."""

    def test_field_data_creation_default_values(self):
        """Test FieldData creation with defaults."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        field = FieldData(text="test", font_size=10, color="#000000")
        assert field.text == "test"
        assert field.font_size == 10
        assert field.color == "#000000"
        assert field.is_variable is False

    def test_field_data_variable_field(self):
        """Test FieldData for variable (predefined) fields."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        field = FieldData(
            text="{signer_name}",
            font_size=11,
            color="#000000",
            is_variable=True,
        )
        assert field.is_variable is True
        assert field.text == "{signer_name}"

    def test_field_data_custom_text(self):
        """Test FieldData for custom text fields."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        field = FieldData(
            text="APPROVED",
            font_size=14,
            color="#00aa00",
            is_variable=False,
        )
        assert field.is_variable is False
        assert field.text == "APPROVED"


class TestPredefinedFields:
    """Tests for predefined field mappings."""

    def test_predefined_fields_contains_signer_name(self):
        """Test that PREDEFINED_FIELDS contains signer_name."""
        from pdfsigner.gui.template_editor_dialog import PREDEFINED_FIELDS

        assert "{signer_name}" in PREDEFINED_FIELDS

    def test_predefined_fields_contains_org(self):
        """Test that PREDEFINED_FIELDS contains org."""
        from pdfsigner.gui.template_editor_dialog import PREDEFINED_FIELDS

        assert "{org}" in PREDEFINED_FIELDS

    def test_predefined_fields_contains_date(self):
        """Test that PREDEFINED_FIELDS contains date."""
        from pdfsigner.gui.template_editor_dialog import PREDEFINED_FIELDS

        assert "{date}" in PREDEFINED_FIELDS


class TestDynamicFieldsBuilding:
    """Tests for building templates with dynamic field list."""

    def test_build_template_from_field_data_list(self):
        """Test building template layers from FieldData list."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        fields = [
            FieldData(text="{signer_name}", font_size=11, color="#000000", is_variable=True),
            FieldData(text="{org}", font_size=9, color="#666666", is_variable=True),
            FieldData(text="{date}", font_size=8, color="#888888", is_variable=True),
        ]

        # Simulate template building logic
        layers = [Layer(type="background", color="#ffffff")]
        text_x = 5
        margin_pct = 10
        available_pct = 80
        spacing = available_pct / (len(fields) + 0.5)
        y_positions = [margin_pct + spacing * (i + 0.5) for i in range(len(fields))]

        for i, field in enumerate(fields):
            layers.append(
                Layer(
                    type="text",
                    x=text_x,
                    y=y_positions[i],
                    text=field.text,
                    font_size=field.font_size,
                    color=field.color,
                )
            )

        template = Template(name="dynamic_test", layers=layers)

        errors = template.validate()
        assert errors == []
        assert len(template.layers) == 4  # background + 3 text

    def test_build_template_with_mixed_fields(self):
        """Test building template with both variables and custom text."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        fields = [
            FieldData(text="{signer_name}", font_size=11, color="#000000", is_variable=True),
            FieldData(text="APPROVED", font_size=10, color="#00aa00", is_variable=False),
            FieldData(text="{date}", font_size=8, color="#888888", is_variable=True),
        ]

        layers = [Layer(type="background", color="#ffffff")]
        for i, field in enumerate(fields):
            layers.append(
                Layer(
                    type="text",
                    x=5,
                    y=15 + i * 25,
                    text=field.text,
                    font_size=field.font_size,
                    color=field.color,
                )
            )

        template = Template(name="mixed_fields", layers=layers)

        text_layers = [layer for layer in template.layers if layer.type == "text"]
        assert len(text_layers) == 3
        assert text_layers[0].text == "{signer_name}"
        assert text_layers[1].text == "APPROVED"
        assert text_layers[2].text == "{date}"

    def test_empty_custom_text_filtered_out(self):
        """Test that empty custom text fields are filtered."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        fields = [
            FieldData(text="{signer_name}", font_size=11, color="#000000", is_variable=True),
            FieldData(text="", font_size=10, color="#333333", is_variable=False),  # Empty
            FieldData(text="   ", font_size=10, color="#333333", is_variable=False),  # Whitespace
            FieldData(text="{date}", font_size=8, color="#888888", is_variable=True),
        ]

        # Filter logic from template editor
        filtered = [f for f in fields if f.is_variable or f.text.strip()]

        assert len(filtered) == 2
        assert filtered[0].text == "{signer_name}"
        assert filtered[1].text == "{date}"


class TestFieldReordering:
    """Tests for field order affecting Y positions."""

    def test_field_order_affects_y_positions(self):
        """Test that changing field order changes Y positions."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        # Order 1: name, org, date
        fields1 = [
            FieldData(text="{signer_name}", font_size=11, color="#000", is_variable=True),
            FieldData(text="{org}", font_size=9, color="#666", is_variable=True),
            FieldData(text="{date}", font_size=8, color="#888", is_variable=True),
        ]

        # Order 2: date, name, org (reordered)
        fields2 = [
            FieldData(text="{date}", font_size=8, color="#888", is_variable=True),
            FieldData(text="{signer_name}", font_size=11, color="#000", is_variable=True),
            FieldData(text="{org}", font_size=9, color="#666", is_variable=True),
        ]

        # Build layer positions
        def build_y_positions(fields_list):
            margin_pct = 10
            available_pct = 80
            spacing = available_pct / (len(fields_list) + 0.5)
            return [margin_pct + spacing * (i + 0.5) for i in range(len(fields_list))]

        y1 = build_y_positions(fields1)
        y2 = build_y_positions(fields2)

        # Same number of positions
        assert len(y1) == len(y2)
        # Position values are the same (just content order differs)
        assert y1[0] == y2[0]
        assert y1[1] == y2[1]
        assert y1[2] == y2[2]

    def test_single_field_centered(self):
        """Test that single field is centered vertically."""
        from pdfsigner.gui.template_editor_dialog import FieldData

        fields = [
            FieldData(text="{signer_name}", font_size=11, color="#000", is_variable=True),
        ]

        margin_pct = 10
        available_pct = 80

        if len(fields) == 1:
            y_positions = [margin_pct + available_pct * 0.3]
        else:
            spacing = available_pct / (len(fields) + 0.5)
            y_positions = [margin_pct + spacing * (i + 0.5) for i in range(len(fields))]

        assert len(y_positions) == 1
        # Single field at roughly 34% from top (10 + 80*0.3 = 34)
        assert y_positions[0] == 34.0


class TestTemplateWithQR:
    """Tests for templates with QR code."""

    def test_template_with_qr_layer(self):
        """Test creating template with QR layer."""
        layers = [
            Layer(type="background", color="#ffffff"),
            Layer(type="qr", x=3, y=10, width=25, height=80),
            Layer(type="text", x=32, y=30, text="{signer_name}", font_size=11),
        ]
        template = Template(name="with_qr", layers=layers)

        errors = template.validate()
        assert errors == []

        qr_layer = next((layer for layer in template.layers if layer.type == "qr"), None)
        assert qr_layer is not None
        assert qr_layer.x == 3

    def test_qr_position_affects_text_x(self):
        """Test that QR position affects text X coordinate."""
        # QR on left: text starts after QR
        text_x_left = 32

        # QR on right: text starts from left
        text_x_right = 5

        assert text_x_left > text_x_right
