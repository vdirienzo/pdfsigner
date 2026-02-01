"""
test_tls_middleware.py - Tests for TLS/HTTPS middleware

Tests:
- HTTP to HTTPS redirect
- TLS version validation
- Certificate path validation
- mTLS client cert requirement
- Config validation errors
- Proxy header handling (X-Forwarded-Proto)

Author: Homero Thompson del Lago del Terror
"""

import ssl
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from pdfsigner.api.config import APISettings
from pdfsigner.api.middleware.tls import (
    TLSRedirectMiddleware,
    TLSRequirementMiddleware,
    get_ssl_context,
    validate_tls_config,
)


class TestTLSRedirectMiddleware:
    """Tests for TLS redirect middleware."""

    def test_redirect_http_to_https(self):
        """Test HTTP requests are redirected to HTTPS."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        # Add TLS redirect middleware
        app.add_middleware(TLSRedirectMiddleware, tls_redirect_enabled=True)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test", follow_redirects=False)

        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert response.headers["location"] == "https://testserver/test"

    def test_no_redirect_for_https(self):
        """Test HTTPS requests are not redirected."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRedirectMiddleware, tls_redirect_enabled=True)

        # Simulate HTTPS request
        client = TestClient(app, base_url="https://testserver")
        response = client.get("/test")

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}

    def test_redirect_preserves_query_params(self):
        """Test redirect preserves query parameters."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRedirectMiddleware, tls_redirect_enabled=True)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test?foo=bar&baz=qux", follow_redirects=False)

        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert "https://testserver/test?foo=bar&baz=qux" in response.headers["location"]

    def test_redirect_respects_forwarded_proto_https(self):
        """Test X-Forwarded-Proto: https is not redirected (proxy scenario)."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRedirectMiddleware, tls_redirect_enabled=True)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test", headers={"X-Forwarded-Proto": "https"})

        # Should not redirect because proxy reports HTTPS
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}

    def test_redirect_disabled(self):
        """Test redirect can be disabled."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRedirectMiddleware, tls_redirect_enabled=False)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test")

        # Should not redirect
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}


class TestTLSRequirementMiddleware:
    """Tests for TLS requirement (strict mode) middleware."""

    def test_reject_http_when_required(self):
        """Test HTTP requests are rejected when TLS is required."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRequirementMiddleware, require_tls=True)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test")

        assert response.status_code == status.HTTP_426_UPGRADE_REQUIRED
        assert "HTTPS required" in response.json()["detail"]
        assert response.headers.get("Upgrade") == "TLS/1.2, HTTP/1.1"

    def test_allow_https_when_required(self):
        """Test HTTPS requests are allowed when TLS is required."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRequirementMiddleware, require_tls=True)

        client = TestClient(app, base_url="https://testserver")
        response = client.get("/test")

        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}

    def test_requirement_respects_forwarded_proto(self):
        """Test X-Forwarded-Proto: https is accepted (proxy scenario)."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRequirementMiddleware, require_tls=True)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test", headers={"X-Forwarded-Proto": "https"})

        # Should allow because proxy reports HTTPS
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}

    def test_requirement_disabled(self):
        """Test TLS requirement can be disabled."""
        app = FastAPI()

        @app.get("/test")
        async def test_route():
            return {"status": "ok"}

        app.add_middleware(TLSRequirementMiddleware, require_tls=False)

        client = TestClient(app, base_url="http://testserver")
        response = client.get("/test")

        # Should allow HTTP when requirement is disabled
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}


class TestSSLContext:
    """Tests for SSL context creation."""

    def test_ssl_context_disabled(self):
        """Test SSL context returns None when TLS is disabled."""
        settings = APISettings(tls_enabled=False)
        context = get_ssl_context(settings)
        assert context is None

    def test_ssl_context_missing_cert_file(self, tmp_path: Path):
        """Test SSL context raises error when cert file is missing."""
        key_file = tmp_path / "key.pem"
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path="/nonexistent/cert.pem",
            tls_key_path=str(key_file),
        )

        with pytest.raises(FileNotFoundError, match="TLS certificate not found"):
            get_ssl_context(settings)

    def test_ssl_context_missing_key_file(self, tmp_path: Path):
        """Test SSL context raises error when key file is missing."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text("dummy cert")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path="/nonexistent/key.pem",
        )

        with pytest.raises(FileNotFoundError, match="TLS key not found"):
            get_ssl_context(settings)

    def test_ssl_context_tlsv12(self, tmp_path: Path):
        """Test SSL context with TLSv1.2 minimum version."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_min_version="TLSv1.2",
        )

        with patch.object(ssl.SSLContext, "load_cert_chain"):
            context = get_ssl_context(settings)
            assert context is not None
            assert context.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_ssl_context_tlsv13(self, tmp_path: Path):
        """Test SSL context with TLSv1.3 minimum version."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_min_version="TLSv1.3",
        )

        with patch.object(ssl.SSLContext, "load_cert_chain"):
            context = get_ssl_context(settings)
            assert context is not None
            assert context.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_ssl_context_mtls_disabled(self, tmp_path: Path):
        """Test SSL context without client certificate requirement."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_require_client_cert=False,
        )

        with patch.object(ssl.SSLContext, "load_cert_chain"):
            context = get_ssl_context(settings)
            assert context is not None
            assert context.verify_mode == ssl.CERT_NONE

    def test_ssl_context_mtls_with_ca_cert(self, tmp_path: Path):
        """Test SSL context with mTLS and custom CA certificate."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        ca_file = tmp_path / "ca.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")
        ca_file.write_text("dummy ca")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_require_client_cert=True,
            tls_ca_cert_path=str(ca_file),
        )

        with (
            patch.object(ssl.SSLContext, "load_cert_chain"),
            patch.object(ssl.SSLContext, "load_verify_locations"),
        ):
            context = get_ssl_context(settings)
            assert context is not None
            assert context.verify_mode == ssl.CERT_REQUIRED

    def test_ssl_context_mtls_system_ca(self, tmp_path: Path):
        """Test SSL context with mTLS using system CA certificates."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_require_client_cert=True,
            tls_ca_cert_path="",  # Use system CAs
        )

        with (
            patch.object(ssl.SSLContext, "load_cert_chain"),
            patch.object(ssl.SSLContext, "load_default_certs"),
        ):
            context = get_ssl_context(settings)
            assert context is not None
            assert context.verify_mode == ssl.CERT_REQUIRED

    def test_ssl_context_invalid_cert_key(self, tmp_path: Path):
        """Test SSL context raises error for invalid cert/key pair."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("invalid cert")
        key_file.write_text("invalid key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
        )

        with pytest.raises(ssl.SSLError, match="Failed to load TLS certificate/key"):
            get_ssl_context(settings)


class TestTLSConfigValidation:
    """Tests for TLS configuration validation."""

    def test_validation_disabled_tls(self):
        """Test validation passes when TLS is disabled."""
        settings = APISettings(tls_enabled=False)
        is_valid, errors = validate_tls_config(settings)

        assert is_valid
        assert len(errors) == 0

    def test_validation_missing_cert_path(self):
        """Test validation fails when cert path is not configured."""
        settings = APISettings(
            tls_enabled=True,
            tls_cert_path="",
            tls_key_path="/path/to/key.pem",
        )
        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("tls_cert_path not configured" in err for err in errors)

    def test_validation_missing_key_path(self):
        """Test validation fails when key path is not configured."""
        settings = APISettings(
            tls_enabled=True,
            tls_cert_path="/path/to/cert.pem",
            tls_key_path="",
        )
        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("tls_key_path not configured" in err for err in errors)

    def test_validation_cert_file_not_found(self, tmp_path: Path):
        """Test validation fails when cert file doesn't exist."""
        key_file = tmp_path / "key.pem"
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path="/nonexistent/cert.pem",
            tls_key_path=str(key_file),
        )
        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("certificate file not found" in err for err in errors)

    def test_validation_key_file_not_found(self, tmp_path: Path):
        """Test validation fails when key file doesn't exist."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text("dummy cert")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path="/nonexistent/key.pem",
        )
        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("key file not found" in err for err in errors)

    def test_validation_invalid_tls_version(self, tmp_path: Path):
        """Test validation fails for invalid TLS version."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
        )
        # Manually override to invalid value (bypassing pydantic validation)
        settings.tls_min_version = "TLSv1.0"  # type: ignore[assignment]

        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("Invalid tls_min_version" in err for err in errors)

    def test_validation_ca_cert_not_found(self, tmp_path: Path):
        """Test validation fails when CA cert file doesn't exist (mTLS)."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_require_client_cert=True,
            tls_ca_cert_path="/nonexistent/ca.pem",
        )
        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("CA certificate file not found" in err for err in errors)

    def test_validation_cert_is_directory(self, tmp_path: Path):
        """Test validation fails when cert path is a directory."""
        cert_dir = tmp_path / "cert"
        cert_dir.mkdir()
        key_file = tmp_path / "key.pem"
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_dir),
            tls_key_path=str(key_file),
        )
        is_valid, errors = validate_tls_config(settings)

        assert not is_valid
        assert any("not a file" in err for err in errors)

    def test_validation_success(self, tmp_path: Path):
        """Test validation passes with valid configuration."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_min_version="TLSv1.2",
        )
        is_valid, errors = validate_tls_config(settings)

        assert is_valid
        assert len(errors) == 0

    def test_validation_success_with_mtls(self, tmp_path: Path):
        """Test validation passes with mTLS configuration."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        ca_file = tmp_path / "ca.pem"
        cert_file.write_text("dummy cert")
        key_file.write_text("dummy key")
        ca_file.write_text("dummy ca")

        settings = APISettings(
            tls_enabled=True,
            tls_cert_path=str(cert_file),
            tls_key_path=str(key_file),
            tls_require_client_cert=True,
            tls_ca_cert_path=str(ca_file),
        )
        is_valid, errors = validate_tls_config(settings)

        assert is_valid
        assert len(errors) == 0
