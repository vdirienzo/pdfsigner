"""
Core - Módulos principales de PDFSigner

Autor: Homero Thompson del Lago del Terror
"""

from pdfsigner.core.signer.pdf_signer import PDFSigner, SignatureAppearance
from pdfsigner.core.token.nss_handler import NSSHandler

__all__ = ["PDFSigner", "SignatureAppearance", "NSSHandler"]
