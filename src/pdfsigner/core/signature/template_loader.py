"""
template_loader.py - Load and manage signature templates

Author: Homero Thompson del Lago del Terror

Provides functions to discover and load builtin and custom templates.
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from pdfsigner.core.signature.template import Template

# Builtin templates directory (relative to this module)
BUILTIN_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "config" / "builtin_templates"

# User templates directory
USER_TEMPLATES_DIR = Path.home() / ".config" / "pdfsigner" / "templates"


def get_builtin_templates_dir() -> Path:
    """Get the path to builtin templates directory."""
    return BUILTIN_TEMPLATES_DIR


def get_user_templates_dir() -> Path:
    """Get the path to user templates directory."""
    return USER_TEMPLATES_DIR


def list_builtin_templates() -> list[str]:
    """
    List names of available builtin templates.

    Returns:
        List of template names (without .json extension)
    """
    templates = []
    if BUILTIN_TEMPLATES_DIR.exists():
        for path in BUILTIN_TEMPLATES_DIR.glob("*.json"):
            templates.append(path.stem)
    return sorted(templates)


def list_user_templates() -> list[str]:
    """
    List names of user-defined templates.

    Returns:
        List of template names (without .json extension)
    """
    templates = []
    if USER_TEMPLATES_DIR.exists():
        for path in USER_TEMPLATES_DIR.glob("*.json"):
            templates.append(path.stem)
    return sorted(templates)


def list_all_templates() -> list[tuple[str, str]]:
    """
    List all available templates with their source.

    Returns:
        List of (name, source) tuples where source is "builtin" or "user"
    """
    templates = []

    for name in list_builtin_templates():
        templates.append((name, "builtin"))

    for name in list_user_templates():
        # User templates override builtin ones with same name
        if not any(t[0] == name for t in templates):
            templates.append((name, "user"))

    return sorted(templates, key=lambda t: t[0])


def load_template(name: str) -> Template | None:
    """
    Load a template by name.

    Searches user templates first, then builtin templates.

    Args:
        name: Template name (without .json extension)

    Returns:
        Template object or None if not found
    """
    # Check user templates first
    user_path = USER_TEMPLATES_DIR / f"{name}.json"
    if user_path.exists():
        try:
            return Template.from_json(user_path)
        except Exception as e:
            logger.error(f"Failed to load user template '{name}': {e}")

    # Check builtin templates
    builtin_path = BUILTIN_TEMPLATES_DIR / f"{name}.json"
    if builtin_path.exists():
        try:
            return Template.from_json(builtin_path)
        except Exception as e:
            logger.error(f"Failed to load builtin template '{name}': {e}")

    logger.warning(f"Template not found: {name}")
    return None


def load_template_from_path(path: Path) -> Template | None:
    """
    Load a template from a specific path.

    Args:
        path: Path to template JSON file

    Returns:
        Template object or None if failed
    """
    try:
        return Template.from_json(path)
    except Exception as e:
        logger.error(f"Failed to load template from '{path}': {e}")
        return None


def get_template_info(name: str) -> dict | None:
    """
    Get basic info about a template without fully loading it.

    Args:
        name: Template name

    Returns:
        Dict with name, description, width_mm, height_mm or None
    """
    template = load_template(name)
    if template:
        return {
            "name": template.name,
            "description": template.description,
            "width_mm": template.width_mm,
            "height_mm": template.height_mm,
        }
    return None


def save_user_template(template: Template) -> Path:
    """
    Save a template to the user templates directory.

    Args:
        template: Template object to save

    Returns:
        Path to the saved JSON file
    """
    USER_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    path = USER_TEMPLATES_DIR / f"{template.name}.json"
    template.to_json(path)
    logger.info(f"User template saved: {path}")
    return path


def delete_user_template(name: str) -> bool:
    """
    Delete a user template by name.

    Args:
        name: Template name (without .json extension)

    Returns:
        True if deleted, False if not found
    """
    path = USER_TEMPLATES_DIR / f"{name}.json"
    if path.exists():
        path.unlink()
        logger.info(f"User template deleted: {name}")
        return True
    logger.warning(f"User template not found for deletion: {name}")
    return False
