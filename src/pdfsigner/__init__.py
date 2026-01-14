"""
PDFSigner - Digital PDF signing application

Author: Homero Thompson del Lago del Terror

PAdES-LTV digital signatures with SafeNet 5110 USB token.
"""

__version__ = "0.8.7"
__author__ = "Homero Thompson del Lago del Terror"

from pdfsigner.exceptions import PDFSignerError

__all__ = ["PDFSignerError", "__version__"]
