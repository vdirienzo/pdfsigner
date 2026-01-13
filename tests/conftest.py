"""
conftest.py - Fixtures de pytest para PDFSigner

Autor: Homero Thompson del Lago del Terror
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def temp_dir():
    """Directorio temporal para tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_pdf(temp_dir: Path) -> Path:
    """Crea un PDF de prueba mínimo."""
    # PDF mínimo válido
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
213
%%EOF
"""
    pdf_path = temp_dir / "test.pdf"
    pdf_path.write_bytes(pdf_content)
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
