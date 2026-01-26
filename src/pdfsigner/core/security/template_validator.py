"""
template_validator.py - JSON Schema validation for signature templates

Author: Homero Thompson del Lago del Terror

Validates template JSON files against a strict schema to prevent
malformed data and potential security issues.
"""

from __future__ import annotations

import json
from pathlib import Path

from loguru import logger

# JSON Schema for signature templates (Draft 2020-12)
TEMPLATE_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "PDFSigner Signature Template",
    "description": "Schema for signature stamp templates",
    "type": "object",
    "required": ["name", "layers"],
    "additionalProperties": False,
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": "^[a-zA-Z0-9_-]+$",
            "description": "Template name (alphanumeric, underscore, hyphen only)",
        },
        "description": {
            "type": "string",
            "maxLength": 256,
            "default": "",
        },
        "width_mm": {
            "type": "number",
            "minimum": 10,
            "maximum": 200,
            "default": 60,
            "description": "Stamp width in millimeters",
        },
        "height_mm": {
            "type": "number",
            "minimum": 5,
            "maximum": 100,
            "default": 25,
            "description": "Stamp height in millimeters",
        },
        "layers": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": {"$ref": "#/$defs/layer"},
        },
    },
    "$defs": {
        "layer": {
            "type": "object",
            "required": ["type"],
            "additionalProperties": False,
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["background", "border", "text", "image", "qr"],
                },
                "x": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100,
                    "default": 0,
                    "description": "X position (0-100% of width)",
                },
                "y": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100,
                    "default": 0,
                    "description": "Y position (0-100% of height)",
                },
                "width": {
                    "type": ["number", "null"],
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Layer width (0-100% of stamp width)",
                },
                "height": {
                    "type": ["number", "null"],
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Layer height (0-100% of stamp height)",
                },
                "color": {
                    "type": ["string", "null"],
                    "pattern": "^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$",
                    "description": "Hex color (#RRGGBB or #RRGGBBAA)",
                },
                "border_width": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10,
                    "default": 1,
                },
                "image_path": {
                    "type": ["string", "null"],
                    "maxLength": 255,
                    "pattern": "^[^/\\\\][^\\\\]*$",
                    "description": "Relative path to image (no leading slash, no backslash)",
                },
                "text": {
                    "type": ["string", "null"],
                    "maxLength": 500,
                },
                "font_size": {
                    "type": "integer",
                    "minimum": 4,
                    "maximum": 72,
                    "default": 12,
                },
                "font_family": {
                    "type": "string",
                    "enum": ["sans-serif", "serif", "mono"],
                    "default": "sans-serif",
                },
                "alignment": {
                    "type": "string",
                    "enum": ["left", "center", "right"],
                    "default": "left",
                },
                "opacity": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "default": 1.0,
                },
            },
            "allOf": [
                {
                    "if": {"properties": {"type": {"const": "text"}}},
                    "then": {"required": ["type", "text"]},
                },
                {
                    "if": {"properties": {"type": {"const": "image"}}},
                    "then": {"required": ["type", "image_path"]},
                },
            ],
        },
    },
}


class TemplateValidationError(Exception):
    """Raised when template validation fails."""

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = errors or [message]


def _get_validator():
    """Get JSON Schema validator (lazy import to handle optional dependency)."""
    try:
        from jsonschema import Draft202012Validator, validators

        # Create validator with format checking
        validator_cls = validators.extend(
            Draft202012Validator,
            type_checker=Draft202012Validator.TYPE_CHECKER,
        )
        return validator_cls(TEMPLATE_SCHEMA)
    except ImportError:
        logger.warning("jsonschema not installed, template validation disabled")
        return None


def validate_template_data(data: dict) -> list[str]:
    """
    Validate template data against JSON Schema.

    Args:
        data: Template data dictionary

    Returns:
        List of validation error messages (empty if valid)
    """
    validator = _get_validator()
    if validator is None:
        # Fallback to basic validation if jsonschema not available
        errors = []
        if not isinstance(data, dict):
            errors.append("Template must be a JSON object")
            return errors

        if "name" not in data:
            errors.append("Missing required field: name")
        elif not isinstance(data.get("name"), str) or not data["name"]:
            errors.append("Template name must be a non-empty string")

        if "layers" not in data:
            errors.append("Missing required field: layers")
        elif not isinstance(data.get("layers"), list) or len(data["layers"]) == 0:
            errors.append("Template must have at least one layer")

        return errors

    errors = []
    for error in sorted(validator.iter_errors(data), key=lambda e: e.path):
        path = ".".join(str(p) for p in error.path) if error.path else "root"
        errors.append(f"{path}: {error.message}")

    return errors


def validate_template_file(path: Path) -> list[str]:
    """
    Validate a template JSON file.

    Args:
        path: Path to template JSON file

    Returns:
        List of validation error messages (empty if valid)
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]
    except FileNotFoundError:
        return [f"File not found: {path}"]
    except Exception as e:
        return [f"Error reading file: {e}"]

    return validate_template_data(data)


def validate_template_strict(data: dict) -> None:
    """
    Validate template data and raise exception if invalid.

    Args:
        data: Template data dictionary

    Raises:
        TemplateValidationError: If validation fails
    """
    errors = validate_template_data(data)
    if errors:
        raise TemplateValidationError(
            f"Template validation failed with {len(errors)} error(s)",
            errors=errors,
        )
