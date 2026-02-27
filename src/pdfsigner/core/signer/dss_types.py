"""
dss_types.py - Data types for Document Security Store operations

Author: Homero Thompson del Lago del Terror

Contains the ValidationInfo dataclass used by DSSManager.
Extracted from dss_manager.py to keep each module under 400 lines.
"""

from dataclasses import dataclass, field


@dataclass
class ValidationInfo:
    """
    Información de validación recopilada para LTV.

    Attributes:
        ocsp_responses: Lista de respuestas OCSP en formato DER
        crls: Lista de CRLs en formato DER
        certificates: Lista de certificados en formato DER
    """

    ocsp_responses: list[bytes] = field(default_factory=list)
    crls: list[bytes] = field(default_factory=list)
    certificates: list[bytes] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Verifica si no hay información de validación."""
        return not (self.ocsp_responses or self.crls or self.certificates)
