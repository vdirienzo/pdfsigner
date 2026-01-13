"""
Signer - Módulo de firma de PDFs

Autor: Homero Thompson del Lago del Terror
"""

from pdfsigner.core.signer.batch_manager import BatchManager
from pdfsigner.core.signer.lta_handler import LTAHandler
from pdfsigner.core.signer.multi_signer import MultiSignatureHandler
from pdfsigner.core.signer.pdf_signer import PDFSigner, SignatureAppearance

__all__ = [
    "PDFSigner",
    "SignatureAppearance",
    "BatchManager",
    "LTAHandler",
    "MultiSignatureHandler",
]
