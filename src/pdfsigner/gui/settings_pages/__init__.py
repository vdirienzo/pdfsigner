"""
settings_pages - Settings dialog page components

Author: Homero Thompson del Lago del Terror

Modular settings pages for the PDFSigner preferences dialog.
"""

from .advanced_page import create_advanced_page
from .appearance_page import (
    create_appearance_page,
    get_selected_accent_color,
    get_selected_language,
    get_selected_theme,
)
from .general_page import create_general_page
from .signature_page import create_signature_page
from .tsa_presets import TSA_PRESET_NAMES, TSA_PRESETS

__all__ = [
    "create_general_page",
    "create_signature_page",
    "create_advanced_page",
    "create_appearance_page",
    "get_selected_theme",
    "get_selected_language",
    "get_selected_accent_color",
    "TSA_PRESETS",
    "TSA_PRESET_NAMES",
]
