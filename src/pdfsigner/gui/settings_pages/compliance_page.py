"""
compliance_page.py - Compliance settings page (consolidated)

Author: Homero Thompson del Lago del Terror

Creates the compliance settings page consolidating:
- Argentina (Ley 25.506)
- eIDAS / EU (Regulation 2024/1183)
"""

import gi

gi.require_version("Adw", "1")
from gi.repository import Adw

from pdfsigner.i18n import _

from .argentina_page import add_argentina_groups
from .eidas_page import add_eidas_groups


def create_compliance_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the consolidated compliance settings page.

    Includes Argentina (Ley 25.506) and eIDAS (EU) groups.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for widget reference storage

    Returns:
        Configured PreferencesPage with all compliance options
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Compliance"))
    page.set_icon_name("emblem-documents-symbolic")

    add_argentina_groups(page, settings, dialog)
    add_eidas_groups(page, settings, dialog)

    return page
