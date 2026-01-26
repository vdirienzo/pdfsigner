"""
Tests for template_validator.py - JSON Schema validation

Author: Homero Thompson del Lago del Terror
"""

import json
from pathlib import Path

import pytest

from pdfsigner.core.security.template_validator import (
    TEMPLATE_SCHEMA,
    TemplateValidationError,
    validate_template_data,
    validate_template_file,
    validate_template_strict,
)


class TestValidateTemplateData:
    """Tests for validate_template_data function."""

    def test_valid_minimal_template(self):
        """Minimal valid template should pass validation."""
        data = {
            "name": "minimal",
            "layers": [{"type": "background", "color": "#ffffff"}],
        }
        errors = validate_template_data(data)
        assert errors == []

    def test_valid_complete_template(self):
        """Complete valid template should pass validation."""
        data = {
            "name": "complete",
            "description": "A complete template",
            "width_mm": 60,
            "height_mm": 25,
            "layers": [
                {"type": "background", "color": "#ffffff"},
                {"type": "border", "color": "#333333", "border_width": 2},
                {
                    "type": "text",
                    "text": "{signer_name}",
                    "x": 5,
                    "y": 30,
                    "font_size": 12,
                    "font_family": "sans-serif",
                    "alignment": "left",
                    "opacity": 1.0,
                },
            ],
        }
        errors = validate_template_data(data)
        assert errors == []

    def test_missing_name_fails(self):
        """Template without name should fail."""
        data = {"layers": [{"type": "background"}]}
        errors = validate_template_data(data)
        assert len(errors) > 0
        assert any("name" in e.lower() for e in errors)

    def test_missing_layers_fails(self):
        """Template without layers should fail."""
        data = {"name": "no_layers"}
        errors = validate_template_data(data)
        assert len(errors) > 0
        assert any("layers" in e.lower() for e in errors)

    def test_empty_layers_fails(self):
        """Template with empty layers array should fail."""
        data = {"name": "empty_layers", "layers": []}
        errors = validate_template_data(data)
        assert len(errors) > 0

    def test_invalid_layer_type_fails(self):
        """Layer with invalid type should fail."""
        data = {
            "name": "bad_layer",
            "layers": [{"type": "invalid_type"}],
        }
        errors = validate_template_data(data)
        assert len(errors) > 0
        assert any("type" in e.lower() for e in errors)

    def test_invalid_width_mm_fails(self):
        """Width outside valid range should fail."""
        data = {
            "name": "bad_width",
            "width_mm": 500,  # Max is 200
            "layers": [{"type": "background"}],
        }
        errors = validate_template_data(data)
        assert len(errors) > 0

    def test_invalid_color_format_fails(self):
        """Invalid color format should fail."""
        data = {
            "name": "bad_color",
            "layers": [{"type": "background", "color": "red"}],  # Should be #RRGGBB
        }
        errors = validate_template_data(data)
        assert len(errors) > 0

    def test_valid_color_formats(self):
        """Valid color formats should pass."""
        # 6-digit hex
        data1 = {
            "name": "hex6",
            "layers": [{"type": "background", "color": "#ff0000"}],
        }
        assert validate_template_data(data1) == []

        # 8-digit hex (with alpha)
        data2 = {
            "name": "hex8",
            "layers": [{"type": "background", "color": "#ff0000ff"}],
        }
        assert validate_template_data(data2) == []

    def test_text_layer_requires_text(self):
        """Text layer without text property should fail validation."""
        data = {
            "name": "text_no_text",
            "layers": [{"type": "text"}],  # Missing text property
        }
        errors = validate_template_data(data)
        # Schema requires text for text layers
        assert len(errors) > 0

    def test_image_layer_requires_image_path(self):
        """Image layer without image_path should fail validation."""
        data = {
            "name": "image_no_path",
            "layers": [{"type": "image"}],  # Missing image_path
        }
        errors = validate_template_data(data)
        assert len(errors) > 0

    def test_image_path_no_leading_slash(self):
        """Image path with leading slash should fail."""
        data = {
            "name": "bad_image_path",
            "layers": [{"type": "image", "image_path": "/absolute/path.png"}],
        }
        errors = validate_template_data(data)
        assert len(errors) > 0

    def test_additional_properties_rejected(self):
        """Unknown properties should be rejected."""
        data = {
            "name": "extra_props",
            "unknown_field": "value",
            "layers": [{"type": "background"}],
        }
        errors = validate_template_data(data)
        assert len(errors) > 0

    def test_name_pattern_validation(self):
        """Name must match alphanumeric pattern."""
        # Valid names
        assert (
            validate_template_data({"name": "valid_name", "layers": [{"type": "background"}]}) == []
        )
        assert (
            validate_template_data({"name": "valid-name", "layers": [{"type": "background"}]}) == []
        )

        # Invalid names
        invalid_names = ["name with spaces", "name.with.dots", "name@special", "../traversal"]
        for name in invalid_names:
            data = {"name": name, "layers": [{"type": "background"}]}
            errors = validate_template_data(data)
            assert len(errors) > 0, f"Name '{name}' should fail validation"


class TestValidateTemplateFile:
    """Tests for validate_template_file function."""

    def test_valid_file(self, tmp_path: Path):
        """Valid template file should pass."""
        template_path = tmp_path / "valid.json"
        data = {
            "name": "valid",
            "layers": [{"type": "background", "color": "#ffffff"}],
        }
        template_path.write_text(json.dumps(data))

        errors = validate_template_file(template_path)
        assert errors == []

    def test_invalid_json(self, tmp_path: Path):
        """Invalid JSON should return error."""
        template_path = tmp_path / "invalid.json"
        template_path.write_text("not valid json {")

        errors = validate_template_file(template_path)
        assert len(errors) > 0
        assert any("json" in e.lower() for e in errors)

    def test_missing_file(self, tmp_path: Path):
        """Missing file should return error."""
        template_path = tmp_path / "missing.json"

        errors = validate_template_file(template_path)
        assert len(errors) > 0
        assert any("not found" in e.lower() for e in errors)


class TestValidateTemplateStrict:
    """Tests for validate_template_strict function."""

    def test_valid_template_no_exception(self):
        """Valid template should not raise exception."""
        data = {
            "name": "valid",
            "layers": [{"type": "background"}],
        }
        validate_template_strict(data)  # Should not raise

    def test_invalid_template_raises(self):
        """Invalid template should raise TemplateValidationError."""
        data = {"name": "invalid"}  # Missing layers

        with pytest.raises(TemplateValidationError) as exc_info:
            validate_template_strict(data)

        assert len(exc_info.value.errors) > 0


class TestTemplateSchema:
    """Tests for the schema itself."""

    def test_schema_has_required_fields(self):
        """Schema should define required fields."""
        assert "properties" in TEMPLATE_SCHEMA
        assert "name" in TEMPLATE_SCHEMA["properties"]
        assert "layers" in TEMPLATE_SCHEMA["properties"]

    def test_layer_types_defined(self):
        """All layer types should be defined in schema."""
        layer_def = TEMPLATE_SCHEMA["$defs"]["layer"]
        type_enum = layer_def["properties"]["type"]["enum"]

        expected_types = ["background", "border", "text", "image", "qr"]
        assert set(type_enum) == set(expected_types)
