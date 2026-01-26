"""
template.py - Signature template data models

Author: Homero Thompson del Lago del Terror

Defines Layer and Template dataclasses for customizable
visual signature stamps with JSON serialization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from loguru import logger

LayerType = Literal["background", "image", "text", "qr", "border"]
TextAlignment = Literal["left", "center", "right"]


@dataclass
class Layer:
    """
    A visual element of the signature stamp.

    Positions use relative coordinates (0-100% of stamp dimensions).
    This allows templates to scale to different stamp sizes.
    """

    type: LayerType
    x: float = 0  # Position X (0-100% of width)
    y: float = 0  # Position Y (0-100% of height)
    width: float | None = None  # Relative width (0-100%)
    height: float | None = None  # Relative height (0-100%)

    # Background/border properties
    color: str | None = None  # Hex color (e.g., "#ffffff")
    border_width: int = 1

    # Image properties
    image_path: str | None = None  # Relative to templates/ directory

    # Text properties
    text: str | None = None  # Can contain {variables}
    font_size: int = 12
    font_family: str = "sans-serif"
    alignment: TextAlignment = "left"

    # Common properties
    opacity: float = 1.0

    def to_dict(self) -> dict[str, object]:
        """Convert layer to dictionary for JSON serialization."""
        result: dict[str, object] = {"type": self.type}

        # Only include non-default values
        if self.x != 0:
            result["x"] = self.x
        if self.y != 0:
            result["y"] = self.y
        if self.width is not None:
            result["width"] = self.width
        if self.height is not None:
            result["height"] = self.height

        if self.color is not None:
            result["color"] = self.color
        if self.border_width != 1:
            result["border_width"] = self.border_width

        if self.image_path is not None:
            result["image_path"] = self.image_path

        if self.text is not None:
            result["text"] = self.text
        if self.font_size != 12:
            result["font_size"] = self.font_size
        if self.font_family != "sans-serif":
            result["font_family"] = self.font_family
        if self.alignment != "left":
            result["alignment"] = self.alignment

        if self.opacity != 1.0:
            result["opacity"] = self.opacity

        return result

    @classmethod
    def from_dict(cls, data: dict) -> Layer:
        """Create layer from dictionary."""
        return cls(
            type=data["type"],
            x=data.get("x", 0),
            y=data.get("y", 0),
            width=data.get("width"),
            height=data.get("height"),
            color=data.get("color"),
            border_width=data.get("border_width", 1),
            image_path=data.get("image_path"),
            text=data.get("text"),
            font_size=data.get("font_size", 12),
            font_family=data.get("font_family", "sans-serif"),
            alignment=data.get("alignment", "left"),
            opacity=data.get("opacity", 1.0),
        )


@dataclass
class Template:
    """
    Complete signature stamp template definition.

    Templates consist of ordered layers that are rendered
    from bottom to top (first layer = background).
    """

    name: str
    description: str = ""
    width_mm: float = 60
    height_mm: float = 25
    layers: list[Layer] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert template to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "width_mm": self.width_mm,
            "height_mm": self.height_mm,
            "layers": [layer.to_dict() for layer in self.layers],
        }

    def to_json(self, path: Path) -> None:
        """Save template to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.debug(f"Template saved to: {path}")

    @classmethod
    def from_dict(cls, data: dict) -> Template:
        """Create template from dictionary."""
        layers = [Layer.from_dict(layer) for layer in data.get("layers", [])]
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            width_mm=data.get("width_mm", 60),
            height_mm=data.get("height_mm", 25),
            layers=layers,
        )

    @classmethod
    def from_json(cls, path: Path) -> Template:
        """Load template from JSON file."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Template loaded from: {path}")
        return cls.from_dict(data)

    def validate(self) -> list[str]:
        """
        Validate template structure.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not self.name:
            errors.append("Template name is required")

        if self.width_mm < 10 or self.width_mm > 200:
            errors.append(f"Invalid width_mm: {self.width_mm} (must be 10-200)")

        if self.height_mm < 5 or self.height_mm > 100:
            errors.append(f"Invalid height_mm: {self.height_mm} (must be 5-100)")

        if not self.layers:
            errors.append("Template must have at least one layer")

        for i, layer in enumerate(self.layers):
            if layer.type not in ("background", "image", "text", "qr", "border"):
                errors.append(f"Layer {i}: invalid type '{layer.type}'")

            if layer.type == "text" and not layer.text:
                errors.append(f"Layer {i}: text layer requires 'text' property")

            if layer.type == "image" and not layer.image_path:
                errors.append(f"Layer {i}: image layer requires 'image_path' property")

            if not (0 <= layer.opacity <= 1):
                errors.append(f"Layer {i}: opacity must be between 0 and 1")

        return errors
