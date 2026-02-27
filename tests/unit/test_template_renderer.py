"""
test_template_renderer.py - Tests for template rendering

Tests PNG rendering, layer composition, and variable substitution.
"""

from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from pdfsigner.core.signature.template import Layer, Template
from pdfsigner.core.signature.template_renderer import (
    DPI,
    MM_TO_INCH,
    _load_font,
    _mm_to_px,
    _parse_color,
    _render_layer,
    _sanitize_image_path,
    _substitute_variables,
    render_preview,
    render_template,
)


class TestMmToPxConversion:
    """Tests for _mm_to_px conversion function."""

    def test_mm_to_px_one_inch(self):
        """25.4mm (1 inch) should equal DPI pixels."""
        result = _mm_to_px(25.4)
        assert result == DPI  # 300 pixels at 300 DPI

    def test_mm_to_px_60mm(self):
        """60mm should convert correctly to pixels."""
        # 60mm / 25.4mm/inch * 300 DPI = 708.66 ≈ 708 pixels
        result = _mm_to_px(60)
        expected = int((60 / MM_TO_INCH) * DPI)
        assert result == expected

    def test_mm_to_px_zero(self):
        """0mm should return 0 pixels."""
        result = _mm_to_px(0)
        assert result == 0

    def test_mm_to_px_small_value(self):
        """Small mm values should convert correctly."""
        result = _mm_to_px(1.0)
        expected = int((1.0 / MM_TO_INCH) * DPI)
        assert result == expected
        assert result > 0  # Should be at least 1 pixel


class TestParseColor:
    """Tests for _parse_color function."""

    def test_parse_color_6_digit_hex(self):
        """6-digit hex color should parse to RGBA with full alpha."""
        result = _parse_color("#ff0000")
        assert result == (255, 0, 0, 255)

    def test_parse_color_8_digit_hex_with_alpha(self):
        """8-digit hex color should include alpha channel."""
        result = _parse_color("#ff000080")
        assert result == (255, 0, 0, 128)

    def test_parse_color_green(self):
        """Green color should parse correctly."""
        result = _parse_color("#00ff00")
        assert result == (0, 255, 0, 255)

    def test_parse_color_blue(self):
        """Blue color should parse correctly."""
        result = _parse_color("#0000ff")
        assert result == (0, 0, 255, 255)

    def test_parse_color_white(self):
        """White color should parse correctly."""
        result = _parse_color("#ffffff")
        assert result == (255, 255, 255, 255)

    def test_parse_color_black(self):
        """Black color should parse correctly."""
        result = _parse_color("#000000")
        assert result == (0, 0, 0, 255)

    def test_parse_color_none_uses_default(self):
        """None color should use provided default."""
        result = _parse_color(None, "#00ff00")
        assert result == (0, 255, 0, 255)

    def test_parse_color_empty_uses_default(self):
        """Empty string should use provided default."""
        result = _parse_color("", "#ff00ff")
        assert result == (255, 0, 255, 255)

    def test_parse_color_without_hash(self):
        """Color without # prefix should still parse."""
        result = _parse_color("ff0000")
        assert result == (255, 0, 0, 255)

    def test_parse_color_invalid_length_returns_black(self):
        """Invalid hex length should return black."""
        result = _parse_color("#fff")  # 3 digits
        assert result == (0, 0, 0, 255)


class TestSubstituteVariables:
    """Tests for _substitute_variables function."""

    def test_substitute_variables_basic(self):
        """Basic variable substitution should work."""
        text = "Signed by {signer_name}"
        variables = {"signer_name": "John Smith"}

        result = _substitute_variables(text, variables)

        assert result == "Signed by John Smith"

    def test_substitute_variables_multiple(self):
        """Multiple variables should all be substituted."""
        text = "{signer_name} - {date} - {org}"
        variables = {
            "signer_name": "Jane Doe",
            "date": "2025-01-27",
            "org": "ACME Corp",
        }

        result = _substitute_variables(text, variables)

        assert result == "Jane Doe - 2025-01-27 - ACME Corp"

    def test_substitute_variables_removes_unresolved(self):
        """Unresolved variables should be removed."""
        text = "Name: {signer_name}, Unknown: {unknown_var}"
        variables = {"signer_name": "Test"}

        result = _substitute_variables(text, variables)

        assert result == "Name: Test, Unknown: "

    def test_substitute_variables_empty_dict(self):
        """Empty variables dict should remove all placeholders."""
        text = "{signer_name} on {date}"
        variables = {}

        result = _substitute_variables(text, variables)

        assert result == " on "

    def test_substitute_variables_no_placeholders(self):
        """Text without placeholders should be unchanged."""
        text = "Static text with no variables"
        variables = {"signer_name": "Test"}

        result = _substitute_variables(text, variables)

        assert result == "Static text with no variables"

    def test_substitute_variables_special_characters(self):
        """Variables with special characters should work."""
        text = "Signer: {signer_name}"
        variables = {"signer_name": "James O'Connor"}

        result = _substitute_variables(text, variables)

        assert result == "Signer: James O'Connor"


class TestLoadFont:
    """Tests for _load_font function."""

    def test_load_font_returns_font_object(self):
        """Should return a PIL font object."""
        font = _load_font("sans-serif", 24)
        assert font is not None

    def test_load_font_sans_serif(self):
        """Sans-serif family should load."""
        font = _load_font("sans-serif", 16)
        assert font is not None

    def test_load_font_serif(self):
        """Serif family should load."""
        font = _load_font("serif", 16)
        assert font is not None

    def test_load_font_mono(self):
        """Mono family should load."""
        font = _load_font("mono", 16)
        assert font is not None

    def test_load_font_unknown_fallback(self):
        """Unknown font family should fallback to sans-serif."""
        font = _load_font("unknown-family", 16)
        assert font is not None

    def test_load_font_different_sizes(self):
        """Different font sizes should be handled."""
        font_small = _load_font("sans-serif", 8)
        font_large = _load_font("sans-serif", 72)

        assert font_small is not None
        assert font_large is not None


class TestSanitizeImagePath:
    """Tests for _sanitize_image_path function."""

    def test_sanitize_image_path_valid(self, tmp_path: Path):
        """Valid image path within templates_dir should pass."""
        image_file = tmp_path / "logo.png"
        image_file.touch()

        result = _sanitize_image_path("logo.png", tmp_path)

        assert result == image_file

    def test_sanitize_image_path_traversal_blocked(self, tmp_path: Path):
        """Path traversal should return None."""
        result = _sanitize_image_path("../../../etc/passwd", tmp_path)
        assert result is None

    def test_sanitize_image_path_nonexistent_returns_none(self, tmp_path: Path):
        """Non-existent image should return None."""
        result = _sanitize_image_path("nonexistent.png", tmp_path)
        assert result is None


class TestRenderLayer:
    """Tests for _render_layer function."""

    @pytest.fixture
    def canvas(self):
        """Create a test canvas for rendering."""
        image = Image.new("RGBA", (300, 200), (255, 255, 255, 255))
        draw = ImageDraw.Draw(image)
        return image, draw

    def test_render_background_layer(self, canvas):
        """Background layer should fill entire canvas."""
        image, draw = canvas
        layer = Layer(type="background", color="#ff0000")

        _render_layer(draw, layer, 300, 200, {}, None, image)

        # Check center pixel is red
        pixel = image.getpixel((150, 100))
        assert pixel[0] == 255  # Red channel
        assert pixel[1] == 0  # Green channel
        assert pixel[2] == 0  # Blue channel

    def test_render_border_layer(self, canvas):
        """Border layer should draw rectangle outline."""
        image, draw = canvas
        layer = Layer(type="border", color="#333333", border_width=2)

        _render_layer(draw, layer, 300, 200, {}, None, image)

        # Border should be at edges
        # Check top-left corner area
        edge_pixel = image.getpixel((0, 0))
        assert edge_pixel != (255, 255, 255, 255)  # Not white

    def test_render_text_layer_with_variables(self, canvas):
        """Text layer should render with variable substitution."""
        image, draw = canvas
        layer = Layer(
            type="text",
            x=10,
            y=10,
            text="{signer_name}",
            font_size=12,
            color="#000000",
        )
        variables = {"signer_name": "Test User"}

        _render_layer(draw, layer, 300, 200, variables, None, image)

        # Image should have been modified (not all white)
        # Simple check: at least some pixels should differ from white
        pixels = list(image.getdata())
        non_white = [p for p in pixels if p != (255, 255, 255, 255)]
        assert len(non_white) > 0

    def test_render_text_layer_empty_text_after_substitution(self, canvas):
        """Empty text after substitution should not render."""
        image, draw = canvas
        original_data = list(image.getdata())

        layer = Layer(
            type="text",
            x=10,
            y=10,
            text="{undefined_var}",
            font_size=12,
        )
        variables = {}

        _render_layer(draw, layer, 300, 200, variables, None, image)

        # Image should be unchanged
        new_data = list(image.getdata())
        assert original_data == new_data

    def test_render_qr_placeholder(self, canvas):
        """QR layer without image should render placeholder."""
        image, draw = canvas
        layer = Layer(
            type="qr",
            x=10,
            y=10,
            width=20,
            height=20,
        )

        _render_layer(draw, layer, 300, 200, {}, None, image)

        # Should render something (placeholder)
        pixels = list(image.getdata())
        non_white = [p for p in pixels if p != (255, 255, 255, 255)]
        assert len(non_white) > 0


class TestRenderTemplate:
    """Tests for render_template function."""

    def test_render_template_creates_png(self):
        """Should create valid PNG file."""
        template = Template(
            name="test",
            width_mm=50,
            height_mm=20,
            layers=[Layer(type="background", color="#ffffff")],
        )

        png_path = render_template(template)

        try:
            assert png_path.exists()
            assert png_path.suffix == ".png"

            # Verify it's a valid image
            img = Image.open(png_path)
            assert img.mode == "RGB"
        finally:
            png_path.unlink()

    def test_render_template_dimensions_match(self):
        """Rendered image should have correct dimensions for template size."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=25,
            layers=[Layer(type="background", color="#fff")],
        )

        png_path = render_template(template)

        try:
            img = Image.open(png_path)

            expected_width = _mm_to_px(60)
            expected_height = _mm_to_px(25)

            assert img.width == expected_width
            assert img.height == expected_height
        finally:
            png_path.unlink()

    def test_render_template_with_variables(self):
        """Variables should be substituted in text layers."""
        template = Template(
            name="test",
            width_mm=50,
            height_mm=20,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="text", x=5, y=30, text="{signer_name}", font_size=12),
            ],
        )

        png_path = render_template(template, {"signer_name": "Test User"})

        try:
            assert png_path.exists()
            img = Image.open(png_path)
            assert img is not None
        finally:
            png_path.unlink()

    def test_render_template_adds_default_date(self):
        """Should add default date variable if not provided."""
        template = Template(
            name="test",
            width_mm=50,
            height_mm=20,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="text", x=5, y=30, text="{date}", font_size=10),
            ],
        )

        png_path = render_template(template, {})

        try:
            assert png_path.exists()
        finally:
            png_path.unlink()

    def test_render_template_with_qr_image(self):
        """Should render QR layer when qr_image provided."""
        template = Template(
            name="test",
            width_mm=50,
            height_mm=50,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="qr", x=10, y=10, width=30, height=30),
            ],
        )

        # Create a small QR image
        qr_image = Image.new("RGB", (100, 100), color="black")

        png_path = render_template(template, {}, qr_image=qr_image)

        try:
            assert png_path.exists()
            img = Image.open(png_path)
            assert img is not None
        finally:
            png_path.unlink()


class TestRenderPreview:
    """Tests for render_preview function."""

    def test_render_preview_returns_image(self):
        """Should return PIL Image object."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=25,
            layers=[Layer(type="background", color="#ffffff")],
        )

        preview = render_preview(template, width_px=300)

        assert isinstance(preview, Image.Image)
        assert preview.mode == "RGB"

    def test_render_preview_respects_width(self):
        """Preview should have requested width."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=25,
            layers=[Layer(type="background")],
        )

        preview = render_preview(template, width_px=400)

        assert preview.width == 400

    def test_render_preview_maintains_aspect_ratio(self):
        """Height should be calculated from aspect ratio."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=30,  # 2:1 aspect ratio
            layers=[Layer(type="background")],
        )

        preview = render_preview(template, width_px=400)

        # Height should be 200 for 2:1 ratio
        expected_height = int(400 * (30 / 60))
        assert preview.height == expected_height

    def test_render_preview_with_text(self):
        """Preview should render text layers."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=25,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="text", x=5, y=30, text="Preview Text", font_size=12),
            ],
        )

        preview = render_preview(template, width_px=300)

        assert preview is not None
        # Preview should have non-white pixels (text rendered)
        pixels = list(preview.getdata())
        non_white = [p for p in pixels if p != (255, 255, 255)]
        assert len(non_white) > 0

    def test_render_preview_qr_placeholder(self):
        """Preview should render QR placeholder pattern."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=60,
            layers=[
                Layer(type="background", color="#ffffff"),
                Layer(type="qr", x=20, y=20, width=60, height=60),
            ],
        )

        preview = render_preview(template, width_px=300)

        assert preview is not None

    def test_render_preview_explicit_height(self):
        """Explicit height should override aspect ratio calculation."""
        template = Template(
            name="test",
            width_mm=60,
            height_mm=30,
            layers=[Layer(type="background")],
        )

        preview = render_preview(template, width_px=400, height_px=100)

        assert preview.width == 400
        assert preview.height == 100


class TestBuiltinTemplateRendering:
    """Tests for rendering builtin templates."""

    def test_render_default_template(self):
        """Default template should render without errors."""
        from pdfsigner.core.signature.template_loader import load_template

        template = load_template("default")
        assert template is not None

        png_path = render_template(template, {"signer_name": "Test User", "date": "2025-01-27"})

        try:
            assert png_path.exists()
            img = Image.open(png_path)
            assert img.mode == "RGB"
        finally:
            png_path.unlink()

    def test_render_corporate_template(self):
        """Corporate template should render without errors."""
        from pdfsigner.core.signature.template_loader import (
            get_builtin_templates_dir,
            load_template,
        )

        template = load_template("corporate")
        assert template is not None

        png_path = render_template(
            template,
            {"signer_name": "Test User", "date": "2025-01-27", "org": "Test Corp"},
            templates_dir=get_builtin_templates_dir(),
        )

        try:
            assert png_path.exists()
        finally:
            png_path.unlink()

    def test_render_minimal_template(self):
        """Minimal template should render without errors."""
        from pdfsigner.core.signature.template_loader import load_template

        template = load_template("minimal")
        assert template is not None

        png_path = render_template(template, {"signer_name": "J. Doe"})

        try:
            assert png_path.exists()
        finally:
            png_path.unlink()
