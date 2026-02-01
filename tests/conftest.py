"""
conftest.py - Fixtures de pytest para PDFSigner

Autor: Homero Thompson del Lago del Terror
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def pytest_configure(config):
    """
    Configure pytest environment before test collection.

    Set required environment variables for API settings validation.
    """
    # Set JWT secret key for API tests (required by APISettings validator)
    if "PDFSIGNER_API_JWT_SECRET_KEY" not in os.environ:
        os.environ["PDFSIGNER_API_JWT_SECRET_KEY"] = (
            "test-secret-key-for-pytest-only-not-for-production-use"
        )


@pytest.fixture
def temp_dir():
    """Directorio temporal para tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_pdf(temp_dir: Path) -> Path:
    """Crea un PDF de prueba válido usando PyMuPDF."""
    import fitz  # PyMuPDF

    pdf_path = temp_dir / "test.pdf"

    # Create a valid PDF with PyMuPDF
    doc = fitz.open()
    page = doc.new_page(width=612, height=792)  # Letter size
    # Add some text so it's not completely empty
    page.insert_text((72, 72), "Test PDF Document", fontsize=12)
    doc.save(str(pdf_path))
    doc.close()

    return pdf_path


@pytest.fixture
def mock_nss_handler():
    """Mock de NSSHandler para tests sin token real."""

    handler = MagicMock()
    handler.initialize.return_value = None
    handler.get_available_tokens.return_value = ["Test Token"]
    handler.connect_token.return_value = None
    handler.authenticate.return_value = None
    handler.list_certificates.return_value = []
    handler.close.return_value = None

    # Mock the _session for PKCS11Signer
    handler._session = MagicMock()

    return handler


@pytest.fixture
def mock_lta_handler():
    """Mock de LTAHandler para tests sin TSA real."""
    handler = MagicMock()
    handler.get_timestamper.return_value = None
    handler.tsa_config = MagicMock()
    handler.tsa_config.url = ""
    return handler


@pytest.fixture
def mock_settings(temp_dir: Path, monkeypatch):
    """Mock de settings para tests."""
    from pdfsigner.config.settings import Settings

    # Crear directorio NSS de prueba
    nss_dir = temp_dir / ".nss"
    nss_dir.mkdir()

    settings = Settings(
        nss_db_path=nss_dir,
        tsa_url="https://test.tsa.example.com",
        log_level="DEBUG",
        log_dir=temp_dir / "logs",
    )

    # Monkeypatch get_settings
    monkeypatch.setattr(
        "pdfsigner.config.settings.get_settings",
        lambda: settings,
    )

    return settings
