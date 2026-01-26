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
