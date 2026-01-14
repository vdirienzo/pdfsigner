"""
test_tsa_integration.py - Integration tests for TSA servers

Author: Homero Thompson del Lago del Terror

Tests real connectivity to TSA timestamp servers:
- FreeTSA (freetsa.org)
- DigiCert (timestamp.digicert.com)
- Sectigo (timestamp.sectigo.com)

These tests require internet connection.
"""

import hashlib
from pathlib import Path

import pytest
import requests

from pdfsigner.core.signer.lta_handler import LTAHandler, TSAConfig


class TestFreeTSAConnectivity:
    """Tests for FreeTSA server connectivity."""

    FREETSA_URL = "https://freetsa.org/tsr"

    def test_freetsa_server_reachable(self):
        """Test that FreeTSA server is reachable."""
        # FreeTSA may block HEAD requests without proper headers
        # Use GET with a User-Agent to test connectivity
        headers = {
            "User-Agent": "PDFSigner/1.0 (TSA Client)",
        }
        response = requests.get(self.FREETSA_URL, headers=headers, timeout=30)

        # FreeTSA accepts connections - may return 200, 400, 403, or 405
        # Any response means the server is reachable
        assert response.status_code is not None
        print(f"FreeTSA response code: {response.status_code}")

    def test_freetsa_post_with_content_type(self):
        """Test that POST with correct Content-Type is accepted."""
        headers = {
            "Content-Type": "application/timestamp-query",
            "User-Agent": "PDFSigner/1.0 (TSA Client)",
        }
        response = requests.post(
            self.FREETSA_URL,
            headers=headers,
            data=b"",  # Empty TSQ will be rejected but connection works
            timeout=30,
        )

        # Server responds (200 with error body, or 400/415 for bad request)
        assert response.status_code is not None
        print(f"FreeTSA POST response: {response.status_code}")


class TestLTAHandlerWithFreeTSA:
    """Tests for LTAHandler with real FreeTSA connection."""

    @pytest.fixture
    def lta_handler(self):
        """Create LTAHandler configured for FreeTSA."""
        config = TSAConfig(
            url="https://freetsa.org/tsr",
            timeout=30,
        )
        return LTAHandler(config)

    def test_validate_tsa_connection_success(self, lta_handler):
        """Test TSA connection validation succeeds."""
        result = lta_handler.validate_tsa_connection()

        assert result is True

    def test_get_timestamper_returns_valid_instance(self, lta_handler):
        """Test getting timestamper returns valid HTTPTimeStamper."""
        from pyhanko.sign.timestamps import HTTPTimeStamper

        timestamper = lta_handler.get_timestamper()

        assert isinstance(timestamper, HTTPTimeStamper)
        assert timestamper.url == "https://freetsa.org/tsr"

    def test_timestamper_can_request_timestamp(self, lta_handler):
        """Test that timestamper can actually request a timestamp."""
        import asyncio

        timestamper = lta_handler.get_timestamper()

        # Create a test digest (SHA-256 of "test data")
        test_data = b"This is test data for timestamp"
        digest = hashlib.sha256(test_data).digest()

        # Request timestamp (async method, run with asyncio)
        # async_timestamp takes digest and algorithm name
        async def get_timestamp():
            return await timestamper.async_timestamp(
                message_digest=digest,
                md_algorithm="sha256",
            )

        try:
            ts_token = asyncio.run(get_timestamp())

            # Verify we got a valid response (ContentInfo containing SignedData)
            assert ts_token is not None
            print("✅ Timestamp token received successfully from FreeTSA!")

            # The token should have contents (the actual timestamp data)
            assert ts_token.contents is not None
            print("   Token contains valid timestamp data")

        except Exception as e:
            pytest.fail(f"Failed to get timestamp from FreeTSA: {e}")


class TestTimestampWithPDF:
    """Test timestamp integration with PDF signing."""

    @pytest.fixture
    def sample_pdf(self, tmp_path: Path) -> Path:
        """Create a sample PDF for testing."""
        import fitz

        pdf_path = tmp_path / "test_tsa.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "TSA Integration Test Document", fontsize=14)
        doc.save(str(pdf_path))
        doc.close()
        return pdf_path

    def test_lta_handler_signature_kwargs(self):
        """Test LTA handler provides correct signature kwargs."""
        config = TSAConfig(url="https://freetsa.org/tsr", timeout=30)
        handler = LTAHandler(config)

        kwargs = handler.get_signature_kwargs()

        assert "timestamper" in kwargs
        assert "embed_validation_info" in kwargs
        assert kwargs["embed_validation_info"] is True


class TestTSAConfigValidation:
    """Tests for TSA configuration validation."""

    def test_invalid_url_raises_error(self):
        """Test that invalid URL raises TSAConnectionError."""
        from pdfsigner.exceptions import TSAConnectionError

        config = TSAConfig(url="not-a-valid-url", timeout=5)
        handler = LTAHandler(config)

        with pytest.raises(TSAConnectionError):
            handler.validate_tsa_connection()

    def test_unreachable_server_raises_error(self):
        """Test that unreachable server raises TSAConnectionError."""
        from pdfsigner.exceptions import TSAConnectionError

        config = TSAConfig(url="https://nonexistent.tsa.invalid/tsr", timeout=5)
        handler = LTAHandler(config)

        with pytest.raises(TSAConnectionError):
            handler.validate_tsa_connection()

    def test_empty_url_raises_error(self):
        """Test that empty URL raises TSAConnectionError."""
        from pdfsigner.exceptions import TSAConnectionError

        config = TSAConfig(url="", timeout=5)
        handler = LTAHandler(config)

        with pytest.raises(TSAConnectionError):
            handler.validate_tsa_connection()


class TestDigiCertTSA:
    """Tests for DigiCert TSA server connectivity and timestamping."""

    DIGICERT_URL = "http://timestamp.digicert.com"

    def test_digicert_server_reachable(self):
        """Test that DigiCert TSA server is reachable."""
        headers = {
            "User-Agent": "PDFSigner/1.0 (TSA Client)",
        }
        response = requests.get(self.DIGICERT_URL, headers=headers, timeout=30)

        # Any response means the server is reachable
        assert response.status_code is not None
        print(f"DigiCert response code: {response.status_code}")

    def test_digicert_validate_connection(self):
        """Test LTAHandler validates DigiCert connection."""
        config = TSAConfig(url=self.DIGICERT_URL, timeout=30)
        handler = LTAHandler(config)

        result = handler.validate_tsa_connection()

        assert result is True

    def test_digicert_timestamp_request(self):
        """Test that DigiCert can provide a valid timestamp."""
        import asyncio

        config = TSAConfig(url=self.DIGICERT_URL, timeout=30)
        handler = LTAHandler(config)
        timestamper = handler.get_timestamper()

        # Create a test digest
        test_data = b"DigiCert timestamp test data"
        digest = hashlib.sha256(test_data).digest()

        async def get_timestamp():
            return await timestamper.async_timestamp(
                message_digest=digest,
                md_algorithm="sha256",
            )

        try:
            ts_token = asyncio.run(get_timestamp())

            assert ts_token is not None
            assert ts_token.contents is not None
            print("✅ Timestamp token received successfully from DigiCert!")

        except Exception as e:
            pytest.fail(f"Failed to get timestamp from DigiCert: {e}")


class TestSectigoTSA:
    """Tests for Sectigo TSA server connectivity and timestamping."""

    SECTIGO_URL = "http://timestamp.sectigo.com"

    def test_sectigo_server_reachable(self):
        """Test that Sectigo TSA server is reachable."""
        headers = {
            "User-Agent": "PDFSigner/1.0 (TSA Client)",
        }
        response = requests.get(self.SECTIGO_URL, headers=headers, timeout=30)

        # Any response means the server is reachable
        assert response.status_code is not None
        print(f"Sectigo response code: {response.status_code}")

    def test_sectigo_validate_connection(self):
        """Test LTAHandler validates Sectigo connection."""
        config = TSAConfig(url=self.SECTIGO_URL, timeout=30)
        handler = LTAHandler(config)

        result = handler.validate_tsa_connection()

        assert result is True

    def test_sectigo_timestamp_request(self):
        """Test that Sectigo can provide a valid timestamp."""
        import asyncio

        config = TSAConfig(url=self.SECTIGO_URL, timeout=30)
        handler = LTAHandler(config)
        timestamper = handler.get_timestamper()

        # Create a test digest
        test_data = b"Sectigo timestamp test data"
        digest = hashlib.sha256(test_data).digest()

        async def get_timestamp():
            return await timestamper.async_timestamp(
                message_digest=digest,
                md_algorithm="sha256",
            )

        try:
            ts_token = asyncio.run(get_timestamp())

            assert ts_token is not None
            assert ts_token.contents is not None
            print("✅ Timestamp token received successfully from Sectigo!")

        except Exception as e:
            pytest.fail(f"Failed to get timestamp from Sectigo: {e}")
