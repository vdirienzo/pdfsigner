"""
test_signature_template.py - Tests for signature template system

Tests template serialization, rendering, and variable substitution.
"""

import tempfile
from pathlib import Path

from PIL import Image

from pdfsigner.core.signature.template import Layer, Template
from pdfsigner.core.signature.template_loader import (
    get_builtin_templates_dir,
    list_builtin_templates,
    load_template,
)
from pdfsigner.core.signature.template_renderer import (
    _mm_to_px,
    _parse_color,
    _substitute_variables,
    render_preview,
    render_template,
)


class TestLayer:
    """Tests for Layer dataclass."""

    def test_layer_creation_default_values(self):
        """Test layer with default values."""
        layer = Layer(type="text")
        assert layer.type == "text"
        assert layer.x == 0
        assert layer.y == 0
        assert layer.font_size == 12
        assert layer.opacity == 1.0

    def test_layer_to_dict_minimal(self):
        """Test layer to dict only includes non-default values."""
        layer = Layer(type="background", color="#ffffff")
        data = layer.to_dict()

        assert data["type"] == "background"
        assert data["color"] == "#ffffff"
        assert "x" not in data  # Default value excluded
        assert "font_size" not in data

    def test_layer_from_dict_roundtrip(self):
        """Test layer serialization roundtrip."""
        original = Layer(
            type="text",
            x=10,
            y=20,
            text="{signer_name}",
            font_size=14,
            color="#333333",
        )
        data = original.to_dict()
        restored = Layer.from_dict(data)

        assert restored.type == original.type
        assert restored.x == original.x
        assert restored.y == original.y
        assert restored.text == original.text
        assert restored.font_size == original.font_size
        assert restored.color == original.color


class TestTemplate:
    """Tests for Template dataclass."""

    def test_template_creation(self):
        """Test basic template creation."""
        template = Template(
            name="test",
            description="Test template",
            width_mm=60,
            height_mm=25,
        )
        assert template.name == "test"
        assert template.width_mm == 60
        assert len(template.layers) == 0

    def test_template_to_json_roundtrip(self):
        """Test template JSON serialization roundtrip."""
        original = Template(
            name="test",
            description="Test template",
            width_mm=50,
            height_mm=20,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="text", x=5, y=10, text="{signer_name}", font_size=11),
            ],
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_path = Path(f.name)

        try:
            original.to_json(temp_path)
            restored = Template.from_json(temp_path)

            assert restored.name == original.name
            assert restored.description == original.description
            assert restored.width_mm == original.width_mm
            assert len(restored.layers) == len(original.layers)
            assert restored.layers[0].color == "#ffffff"
            assert restored.layers[1].text == "{signer_name}"
        finally:
            temp_path.unlink()

    def test_template_validation_valid(self):
        """Test validation passes for valid template."""
        template = Template(
            name="valid",
            layers=[Layer(type="background", color="#fff")],
        )
        errors = template.validate()
        assert errors == []

    def test_template_validation_missing_name(self):
        """Test validation catches missing name."""
        template = Template(name="", layers=[Layer(type="background")])
        errors = template.validate()
        assert any("name is required" in e for e in errors)

    def test_template_validation_invalid_dimensions(self):
        """Test validation catches invalid dimensions."""
        template = Template(name="test", width_mm=5, layers=[Layer(type="background")])
        errors = template.validate()
        assert any("width_mm" in e for e in errors)

    def test_template_validation_text_layer_missing_text(self):
        """Test validation catches text layer without text."""
        template = Template(
            name="test",
            layers=[Layer(type="text")],  # Missing text property
        )
        errors = template.validate()
        assert any("text layer requires" in e for e in errors)


class TestTemplateLoader:
    """Tests for template loading functions."""

    def test_list_builtin_templates(self):
        """Test listing builtin templates."""
        templates = list_builtin_templates()
        assert "corporate" in templates
        assert "minimal" in templates
        assert "with_qr" in templates

    def test_load_builtin_template_corporate(self):
        """Test loading corporate template."""
        template = load_template("corporate")
        assert template is not None
        assert template.name == "corporate"
        assert len(template.layers) > 0

    def test_load_builtin_template_minimal(self):
        """Test loading minimal template."""
        template = load_template("minimal")
        assert template is not None
        assert template.name == "minimal"

    def test_load_nonexistent_template(self):
        """Test loading non-existent template returns None."""
        template = load_template("nonexistent_template_xyz")
        assert template is None

    def test_get_builtin_templates_dir_exists(self):
        """Test builtin templates directory exists."""
        dir_path = get_builtin_templates_dir()
        assert dir_path.exists()
        assert (dir_path / "corporate.json").exists()


class TestTemplateRenderer:
    """Tests for template rendering functions."""

    def test_mm_to_px_conversion(self):
        """Test millimeter to pixel conversion at 300 DPI."""
        # 25.4mm = 1 inch = 300 pixels at 300 DPI
        px = _mm_to_px(25.4)
        assert px == 300

    def test_parse_color_hex6(self):
        """Test parsing 6-digit hex color."""
        rgba = _parse_color("#ff0000")
        assert rgba == (255, 0, 0, 255)

    def test_parse_color_hex8(self):
        """Test parsing 8-digit hex color with alpha."""
        rgba = _parse_color("#ff000080")
        assert rgba == (255, 0, 0, 128)

    def test_parse_color_none_uses_default(self):
        """Test None color uses default."""
        rgba = _parse_color(None, "#00ff00")
        assert rgba == (0, 255, 0, 255)

    def test_substitute_variables_basic(self):
        """Test basic variable substitution."""
        text = "Signed by {signer_name} on {date}"
        variables = {"signer_name": "John Smith", "date": "2025-01-26"}
        result = _substitute_variables(text, variables)
        assert result == "Signed by John Smith on 2025-01-26"

    def test_substitute_variables_removes_unresolved(self):
        """Test unresolved variables are removed."""
        text = "Name: {signer_name}, Org: {org}"
        variables = {"signer_name": "John"}
        result = _substitute_variables(text, variables)
        assert result == "Name: John, Org: "

    def test_render_template_creates_png(self):
        """Test template rendering creates valid PNG."""
        template = Template(
            name="test",
            width_mm=50,
            height_mm=20,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="text", x=5, y=30, text="Test", font_size=12),
            ],
        )

        png_path = render_template(template, {"signer_name": "Test"})

        assert png_path.exists()
        assert png_path.suffix == ".png"

        # Verify it's a valid image
        img = Image.open(png_path)
        assert img.mode == "RGB"
        assert img.width > 0
        assert img.height > 0

        # Cleanup
        png_path.unlink()

    def test_render_template_dimensions_match(self):
        """Test rendered image has correct dimensions."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=25,
            layers=[Layer(type="background", color="#fff")],
        )

        png_path = render_template(template)
        img = Image.open(png_path)

        # At 300 DPI: 60mm ≈ 709px, 25mm ≈ 295px
        expected_width = _mm_to_px(60)
        expected_height = _mm_to_px(25)

        assert img.width == expected_width
        assert img.height == expected_height

        png_path.unlink()

    def test_render_preview_returns_image(self):
        """Test preview rendering returns PIL Image."""
        template = load_template("corporate")
        assert template is not None

        preview = render_preview(template, width_px=300)

        assert isinstance(preview, Image.Image)
        assert preview.width == 300
        # Height should be proportional
        assert preview.height > 0

    def test_render_corporate_template(self):
        """Test rendering corporate builtin template."""
        template = load_template("corporate")
        variables = {
            "signer_name": "John A. Smith",
            "org": "Acme Corp",
            "date": "2025-01-26 14:30",
        }

        png_path = render_template(
            template,
            variables=variables,
            templates_dir=get_builtin_templates_dir(),
        )

        assert png_path.exists()

        img = Image.open(png_path)
        assert img.mode == "RGB"

        png_path.unlink()


class TestBuiltinTemplates:
    """Tests for builtin template JSON files."""

    def test_corporate_template_structure(self):
        """Test corporate builtin template has expected structure."""
        # Load directly from builtin dir to avoid user template overrides
        builtin_path = get_builtin_templates_dir() / "corporate.json"
        template = Template.from_json(builtin_path)

        assert template.name == "corporate"
        assert template.width_mm == 60
        assert template.height_mm == 25

        layer_types = [layer.type for layer in template.layers]
        assert "background" in layer_types
        assert "border" in layer_types
        assert "text" in layer_types

    def test_minimal_template_structure(self):
        """Test minimal template is compact."""
        template = load_template("minimal")

        assert template.name == "minimal"
        assert template.height_mm < 15  # Should be compact

    def test_with_qr_template_has_qr_layer(self):
        """Test with_qr template includes QR layer."""
        template = load_template("with_qr")

        layer_types = [layer.type for layer in template.layers]
        assert "qr" in layer_types

    def test_all_builtin_templates_valid(self):
        """Test all builtin templates pass validation."""
        for name in list_builtin_templates():
            template = load_template(name)
            assert template is not None
            errors = template.validate()
            assert errors == [], f"Template '{name}' has errors: {errors}"
