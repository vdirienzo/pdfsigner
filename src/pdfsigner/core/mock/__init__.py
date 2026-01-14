"""
Mock - Módulo de simulación para dry-run

Autor: Homero Thompson del Lago del Terror

Contiene implementaciones mock para pruebas sin token real.
"""

from pdfsigner.core.mock.mock_batch import MockBatchManager, enable_dry_run_mode
from pdfsigner.core.mock.mock_certificate import (
    MockCertificate,
    MockCertificateInfo,
    create_mock_certificate,
)
from pdfsigner.core.mock.mock_nss import MockNSSHandler

__all__ = [
    "MockNSSHandler",
    "MockBatchManager",
    "MockCertificate",
    "MockCertificateInfo",
    "create_mock_certificate",
    "enable_dry_run_mode",
]
