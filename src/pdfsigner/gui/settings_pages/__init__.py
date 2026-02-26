"""
settings_pages - Settings dialog page components

Author: Homero Thompson del Lago del Terror

Modular settings pages for the PDFSigner preferences dialog.
"""

from .appearance_page import (
    add_appearance_groups,
    apply_theme,
    create_appearance_page,
    get_selected_language,
    get_selected_theme,
)
from .argentina_page import add_argentina_groups, create_argentina_page
from .behavior_page import add_behavior_groups, create_behavior_page
from .compliance_page import create_compliance_page
from .eidas_page import add_eidas_groups, create_eidas_page
from .general_page import create_general_page
from .healthcare_page import create_healthcare_page
from .security_page import create_security_page
from .signature_page import create_signature_page
from .tsa_presets import TSA_PRESET_NAMES, TSA_PRESETS
from .validation_page import add_validation_groups, create_validation_page

__all__ = [
    # Consolidated pages (used by settings_dialog)
    "create_general_page",
    "create_signature_page",
    "create_security_page",
    "create_healthcare_page",
    "create_compliance_page",
    # Individual pages (backward compat for tests)
    "create_validation_page",
    "create_behavior_page",
    "create_appearance_page",
    "create_argentina_page",
    "create_eidas_page",
    # Group builders
    "add_appearance_groups",
    "add_behavior_groups",
    "add_validation_groups",
    "add_argentina_groups",
    "add_eidas_groups",
    # Helpers
    "get_selected_theme",
    "get_selected_language",
    "apply_theme",
    "TSA_PRESETS",
    "TSA_PRESET_NAMES",
]
