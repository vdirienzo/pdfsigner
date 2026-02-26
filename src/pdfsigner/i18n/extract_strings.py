#!/usr/bin/env python3
"""
extract_strings.py - Extract translatable strings from PDFSigner

Author: Homero Thompson del Lago del Terror

Extracts all translatable strings marked with _() or ngettext() and
generates/updates .po files for each supported language.

Usage:
    python extract_strings.py              # Extract and update all languages
    python extract_strings.py --compile    # Compile .po to .mo files
    python extract_strings.py --lang es    # Update only Spanish
"""

import argparse
import subprocess
import sys
from pathlib import Path


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent.parent


def get_i18n_dir() -> Path:
    """Get the i18n directory."""
    return Path(__file__).parent


def get_source_dirs() -> list[Path]:
    """Get directories to scan for translatable strings."""
    root = get_project_root()
    return [
        root / "src" / "pdfsigner" / "gui",
        root / "src" / "pdfsigner" / "cli",
        root / "src" / "pdfsigner" / "api",
        root / "src" / "pdfsigner" / "core",
    ]


def extract_strings() -> int:
    """
    Extract translatable strings from source files.

    Returns:
        0 on success, non-zero on error
    """
    i18n_dir = get_i18n_dir()
    pot_file = i18n_dir / "pdfsigner.pot"
    source_dirs = get_source_dirs()

    print("Extracting translatable strings...")
    print(f"Output: {pot_file}")

    # Find all Python files in source directories
    py_files: list[Path] = []
    for source_dir in source_dirs:
        if source_dir.exists():
            py_files.extend(source_dir.rglob("*.py"))

    if not py_files:
        print("Error: No Python files found in source directories")
        return 1

    print(f"Found {len(py_files)} Python files")

    # Build xgettext command
    cmd = [
        "xgettext",
        "--language=Python",
        "--keyword=_",
        "--keyword=ngettext:1,2",
        "--from-code=UTF-8",
        "--output=" + str(pot_file),
        "--package-name=PDFSigner",
        "--package-version=0.6.0",
        "--msgid-bugs-address=",
        "--copyright-holder=Homero Thompson del Lago del Terror",
    ]

    # Add all source files
    cmd.extend(str(f) for f in py_files)

    try:
        subprocess.run(cmd, check=True, cwd=get_project_root())
        print(f"✓ Successfully created {pot_file}")
        return 0
    except FileNotFoundError:
        print("Error: xgettext not found. Install gettext package:")
        print("  Ubuntu/Debian: sudo apt install gettext")
        print("  macOS: brew install gettext")
        print("  Fedora: sudo dnf install gettext")
        return 1
    except subprocess.CalledProcessError as e:
        print(f"Error running xgettext: {e}")
        return 1


def update_po_file(lang: str) -> int:
    """
    Update a .po file from the .pot template.

    Args:
        lang: Language code (es, pt, fr, de, en)

    Returns:
        0 on success, non-zero on error
    """
    i18n_dir = get_i18n_dir()
    pot_file = i18n_dir / "pdfsigner.pot"
    po_file = i18n_dir / "locales" / lang / "LC_MESSAGES" / "pdfsigner.po"

    if not pot_file.exists():
        print(f"Error: Template file {pot_file} not found. Run extract first.")
        return 1

    # Create locale directory if it doesn't exist
    po_file.parent.mkdir(parents=True, exist_ok=True)

    if po_file.exists():
        # Update existing .po file
        print(f"Updating {lang}...")
        cmd = [
            "msgmerge",
            "--update",
            "--backup=none",
            str(po_file),
            str(pot_file),
        ]
    else:
        # Create new .po file from template
        print(f"Creating {lang}...")
        cmd = [
            "msginit",
            "--input=" + str(pot_file),
            "--output-file=" + str(po_file),
            "--locale=" + lang,
            "--no-translator",
        ]

    try:
        subprocess.run(cmd, check=True, cwd=get_project_root())
        print(f"✓ Successfully updated {po_file}")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Error updating {lang}: {e}")
        return 1


def compile_po_file(lang: str) -> int:
    """
    Compile a .po file to .mo format.

    Args:
        lang: Language code (es, pt, fr, de, en)

    Returns:
        0 on success, non-zero on error
    """
    i18n_dir = get_i18n_dir()
    po_file = i18n_dir / "locales" / lang / "LC_MESSAGES" / "pdfsigner.po"
    mo_file = i18n_dir / "locales" / lang / "LC_MESSAGES" / "pdfsigner.mo"

    if not po_file.exists():
        print(f"Warning: {po_file} not found, skipping")
        return 0

    print(f"Compiling {lang}...")
    cmd = [
        "msgfmt",
        "--output-file=" + str(mo_file),
        str(po_file),
    ]

    try:
        subprocess.run(cmd, check=True, cwd=get_project_root())
        print(f"✓ Successfully compiled {mo_file}")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Error compiling {lang}: {e}")
        return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Extract and compile translatable strings for PDFSigner"
    )
    parser.add_argument(
        "--compile",
        action="store_true",
        help="Compile .po files to .mo format",
    )
    parser.add_argument(
        "--lang",
        choices=["es", "pt", "fr", "de", "en"],
        help="Update/compile only specific language",
    )
    parser.add_argument(
        "--skip-extract",
        action="store_true",
        help="Skip extraction step (only update/compile)",
    )

    args = parser.parse_args()

    # Determine languages to process
    languages = [args.lang] if args.lang else ["es", "pt", "fr", "de", "en"]

    # Step 1: Extract strings (unless skipped)
    if not args.skip_extract and not args.compile:
        result = extract_strings()
        if result != 0:
            return result

    # Step 2: Update .po files (unless only compiling)
    if not args.compile:
        for lang in languages:
            result = update_po_file(lang)
            if result != 0:
                return result

    # Step 3: Compile to .mo files (if requested)
    if args.compile or not args.skip_extract:
        for lang in languages:
            result = compile_po_file(lang)
            if result != 0:
                return result

    print("\n✓ All operations completed successfully!")
    print("\nNext steps:")
    print("1. Edit .po files in src/pdfsigner/i18n/locales/<lang>/LC_MESSAGES/")
    print("2. Add your translations for msgid entries")
    print("3. Run: python extract_strings.py --compile")
    print("4. Test translations by setting LANGUAGE environment variable:")
    print("   LANGUAGE=es pdfsigner-gui")

    return 0


if __name__ == "__main__":
    sys.exit(main())
