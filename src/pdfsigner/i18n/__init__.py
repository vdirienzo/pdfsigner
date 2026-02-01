"""
i18n/__init__.py - Internationalization support

Author: Homero Thompson del Lago del Terror

Provides gettext-based internationalization for PDFSigner.
Supports: English (en), Spanish (es), Portuguese (pt), French (fr), German (de)
"""

import gettext
import locale
import os
from collections.abc import Callable
from pathlib import Path

# Supported languages
SUPPORTED_LANGUAGES = {
    "en": "English",
    "es": "Español",
    "pt": "Português",
    "fr": "Français",
    "de": "Deutsch",
}

# Default language
DEFAULT_LANGUAGE = "en"

# Global translation function
_current_translation: gettext.GNUTranslations | gettext.NullTranslations | None = None


def get_locale_dir() -> Path:
    """Get the locales directory path."""
    return Path(__file__).parent / "locales"


def get_system_language() -> str:
    """
    Detect system language.

    Returns:
        Two-letter language code (e.g., 'en', 'es')
    """
    try:
        # Try to get from environment
        lang = os.environ.get("LANGUAGE", "")
        if lang:
            lang = lang.split(":")[0].split("_")[0]
            if lang in SUPPORTED_LANGUAGES:
                return lang

        # Try locale
        loc = locale.getdefaultlocale()[0]
        if loc:
            lang = loc.split("_")[0]
            if lang in SUPPORTED_LANGUAGES:
                return lang
    except Exception:
        pass

    return DEFAULT_LANGUAGE


def set_language(lang_code: str) -> None:
    """
    Set the application language.

    Args:
        lang_code: Two-letter language code (en, es, pt, fr, de)
    """
    global _current_translation

    if lang_code not in SUPPORTED_LANGUAGES:
        lang_code = DEFAULT_LANGUAGE

    locale_dir = get_locale_dir()

    try:
        _current_translation = gettext.translation(
            "pdfsigner",
            localedir=str(locale_dir),
            languages=[lang_code],
        )
    except FileNotFoundError:
        # Fallback to NullTranslations (returns original strings)
        _current_translation = gettext.NullTranslations()


def get_translation() -> Callable[[str], str]:
    """
    Get the translation function.

    Returns:
        Function that translates strings
    """
    global _current_translation

    if _current_translation is None:
        set_language(get_system_language())

    if _current_translation is None:
        raise RuntimeError("Translation system not properly initialized")
    return _current_translation.gettext


def _(text: str) -> str:
    """
    Translate a string.

    This is the main function to use for translations.
    Usage: _("Hello World")

    Args:
        text: Text to translate

    Returns:
        Translated text
    """
    return get_translation()(text)


def ngettext(singular: str, plural: str, n: int) -> str:
    """
    Translate a string with plural forms.

    Usage: ngettext("1 file", "{n} files", count)

    Args:
        singular: Singular form
        plural: Plural form
        n: Count

    Returns:
        Translated text
    """
    global _current_translation

    if _current_translation is None:
        set_language(get_system_language())

    if _current_translation is None:
        raise RuntimeError("Translation system not properly initialized")
    return _current_translation.ngettext(singular, plural, n)


def get_current_language() -> str:
    """
    Get the current language code.

    Returns:
        Two-letter language code
    """
    # Check if we have a translation set
    lang = os.environ.get("PDFSIGNER_LANGUAGE", "")
    if lang and lang in SUPPORTED_LANGUAGES:
        return lang
    return get_system_language()


# Initialize with system language on import
set_language(get_system_language())

__all__ = [
    "_",
    "ngettext",
    "set_language",
    "get_current_language",
    "get_system_language",
    "SUPPORTED_LANGUAGES",
]
