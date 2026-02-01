"""
settings_pages - Settings dialog page components

Author: Homero Thompson del Lago del Terror

Modular settings pages for the PDFSigner preferences dialog.
"""

from .advanced_page import create_advanced_page
from .appearance_page import (
    apply_theme,
    create_appearance_page,
    get_selected_language,
    get_selected_theme,
)
from .argentina_page import create_argentina_page
from .behavior_page import create_behavior_page
from .general_page import create_general_page
from .healthcare_page import create_healthcare_page
from .ltv_page import create_ltv_page
from .signature_page import create_signature_page
from .tsa_presets import TSA_PRESET_NAMES, TSA_PRESETS
from .validation_page import create_validation_page

__all__ = [
    "create_general_page",
    "create_signature_page",
    "create_validation_page",
    "create_ltv_page",
    "create_behavior_page",
    "create_advanced_page",
    "create_appearance_page",
    "create_healthcare_page",
    "create_argentina_page",
    "get_selected_theme",
    "get_selected_language",
    "apply_theme",
    "TSA_PRESETS",
    "TSA_PRESET_NAMES",
]
