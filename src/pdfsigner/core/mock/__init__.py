"""
Mock - Módulo de simulación para dry-run

Autor: Homero Thompson del Lago del Terror

Contiene implementaciones mock para pruebas sin token real.
"""

from pdfsigner.core.mock.mock_handlers import (
    MockBatchManager,
    MockNSSHandler,
    create_mock_certificate,
)

__all__ = ["MockNSSHandler", "MockBatchManager", "create_mock_certificate"]
