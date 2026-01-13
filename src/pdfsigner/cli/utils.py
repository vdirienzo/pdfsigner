"""
utils.py - Utilidades compartidas del CLI

Autor: Homero Thompson del Lago del Terror

Funciones compartidas entre comandos CLI.
"""

import getpass
from pathlib import Path

from loguru import logger


def get_pin_from_user() -> str:
    """Solicita PIN por consola."""
    return getpass.getpass("Ingrese PIN del token: ")


def collect_pdf_files(paths: list[Path], recursive: bool = False) -> list[Path]:
    """
    Recolecta archivos PDF de paths (archivos o directorios).

    Args:
        paths: Lista de paths (archivos o directorios)
        recursive: Buscar recursivamente en directorios

    Returns:
        Lista de archivos PDF encontrados
    """
    pdf_files = []

    for path in paths:
        if path.is_file():
            if path.suffix.lower() == ".pdf":
                pdf_files.append(path)
            else:
                logger.warning(f"Ignorando archivo no-PDF: {path}")
        elif path.is_dir():
            pattern = "**/*.pdf" if recursive else "*.pdf"
            found = list(path.glob(pattern))
            logger.info(f"Encontrados {len(found)} PDFs en {path}")
            pdf_files.extend(found)
        else:
            logger.error(f"Path no existe: {path}")

    return sorted(set(pdf_files))
