"""
signature - Visual signature template system

Author: Homero Thompson del Lago del Terror

Provides customizable signature templates with layers.
"""

from pdfsigner.core.signature.template import Layer, Template
from pdfsigner.core.signature.template_loader import (
    get_builtin_templates_dir,
    list_all_templates,
    list_builtin_templates,
    load_template,
)
from pdfsigner.core.signature.template_renderer import render_preview, render_template

__all__ = [
    "Layer",
    "Template",
    "render_template",
    "render_preview",
    "load_template",
    "list_builtin_templates",
    "list_all_templates",
    "get_builtin_templates_dir",
]
