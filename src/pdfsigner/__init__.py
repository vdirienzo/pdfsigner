"""
PDFSigner - Plugin de Nautilus para firma digital de PDFs

Autor: Homero Thompson del Lago del Terror

Firma digital PAdES-LTV con token USB SafeNet 5110.
"""

__version__ = "0.1.0"
__author__ = "Homero Thompson del Lago del Terror"

from pdfsigner.exceptions import PDFSignerError

__all__ = ["PDFSignerError", "__version__"]
