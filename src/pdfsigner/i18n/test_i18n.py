#!/usr/bin/env python3
"""
test_i18n.py - Test internationalization functionality

Author: Homero Thompson del Lago del Terror

Quick script to test translations without running the full GUI.

Usage:
    python test_i18n.py           # Test with system language
    LANGUAGE=es python test_i18n.py  # Test Spanish
    LANGUAGE=en python test_i18n.py  # Test English
"""

import sys
from pathlib import Path

# Add src to path to import pdfsigner
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pdfsigner.i18n import SUPPORTED_LANGUAGES, _, get_current_language, set_language


def test_translations():
    """Test various translations."""
    current_lang = get_current_language()
    print(f"Current language: {current_lang} ({SUPPORTED_LANGUAGES.get(current_lang, 'Unknown')})")
    print("-" * 60)

    # Test common strings
    test_strings = [
        "PDFSigner",
        "Sign",
        "Validate",
        "Settings",
        "Argentina",
        "Ley 25.506 Compliance",
        "Enable Argentine compliance",
        "Governmental Certifiers (Free)",
        "Private Certifiers",
        "Legal Information",
        "Important Notice",
        "Website",
        "View",
        "Error",
        "Token not found",
    ]

    for original in test_strings:
        translated = _(original)
        if original != translated:
            print(f"✓ {original:<40} → {translated}")
        else:
            print(f"  {original:<40} (no translation)")

    print("-" * 60)


def test_all_languages():
    """Test all supported languages."""
    print("Testing all supported languages:")
    print("=" * 60)

    test_string = "Enable Argentine compliance"

    for lang_code, lang_name in SUPPORTED_LANGUAGES.items():
        set_language(lang_code)
        translated = _(test_string)
        status = "✓" if translated != test_string else " "
        print(f"{status} {lang_code} ({lang_name:<10}): {translated}")

    print("=" * 60)


if __name__ == "__main__":
    if "--all" in sys.argv:
        test_all_languages()
    else:
        test_translations()
