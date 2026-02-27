"""
test_revocation_ssrf.py - Tests for SSRF protection in revocation checking

Tests that OCSP and CRL URL validation prevents SSRF attacks.
"""

import pytest

from pdfsigner.core.security.url_validator import SSRFError, validate_crl_url, validate_ocsp_url


class TestOCSPUrlValidation:
    """Test OCSP URL validation."""

    def test_valid_ocsp_url_passes(self, monkeypatch):
        """Valid public OCSP URL should pass."""

        # Mock DNS to return public IP
        def mock_getaddrinfo(hostname, port, family):
            return [(2, 1, 6, "", ("93.184.216.34", 80))]

        import socket

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        url = "http://ocsp.example.com/ocsp"
        result = validate_ocsp_url(url)
        assert result == url

    def test_localhost_ocsp_blocked(self):
        """Localhost OCSP URL should be blocked."""
        with pytest.raises(SSRFError):
            validate_ocsp_url("http://localhost/ocsp")

    def test_private_ip_ocsp_blocked(self):
        """Private IP OCSP URL should be blocked."""
        with pytest.raises(SSRFError):
            validate_ocsp_url("http://192.168.1.100/ocsp")

    def test_metadata_ocsp_blocked(self):
        """Cloud metadata OCSP URL should be blocked."""
        with pytest.raises(SSRFError):
            validate_ocsp_url("http://169.254.169.254/ocsp")

    def test_dns_rebinding_blocked(self, monkeypatch):
        """DNS rebinding to private IP should be blocked."""

        def mock_getaddrinfo(hostname, port, family):
            # Simulate DNS rebinding - hostname resolves to private IP
            return [(2, 1, 6, "", ("10.0.0.1", 80))]

        import socket

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        with pytest.raises(SSRFError, match="private IP"):
            validate_ocsp_url("http://malicious-rebind.example.com/ocsp")


class TestCRLUrlValidation:
    """Test CRL URL validation."""

    def test_valid_http_crl_passes(self, monkeypatch):
        """Valid HTTP CRL URL should pass."""

        def mock_getaddrinfo(hostname, port, family):
            return [(2, 1, 6, "", ("93.184.216.34", 80))]

        import socket

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        url = "http://crl.example.com/ca.crl"
        result = validate_crl_url(url)
        assert result == url

    def test_ldap_crl_passes(self, monkeypatch):
        """LDAP CRL URL should pass (CRLs support LDAP)."""

        def mock_getaddrinfo(hostname, port, family):
            return [(2, 1, 6, "", ("93.184.216.34", 389))]

        import socket

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        url = "ldap://ldap.example.com/cn=CRL"
        result = validate_crl_url(url)
        assert result == url

    def test_file_scheme_blocked(self):
        """File scheme CRL should be blocked."""
        with pytest.raises(SSRFError):
            validate_crl_url("file:///etc/passwd")

    def test_localhost_crl_blocked(self):
        """Localhost CRL URL should be blocked."""
        with pytest.raises(SSRFError):
            validate_crl_url("http://127.0.0.1/ca.crl")


class TestRevocationCheckerSSRF:
    """Test that RevocationChecker uses SSRF protection."""

    def test_ocsp_checker_imports_validator(self):
        """OCSPChecker module should import SSRF validator."""
        import inspect

        from pdfsigner.core.certificate import ocsp_checker

        source = inspect.getsource(ocsp_checker)
        assert "validate_ocsp_url" in source
        assert "SSRFError" in source

    def test_crl_checker_imports_validator(self):
        """CRLChecker module should import SSRF validator."""
        import inspect

        from pdfsigner.core.certificate import crl_checker

        source = inspect.getsource(crl_checker)
        assert "validate_crl_url" in source
        assert "SSRFError" in source

    def test_ocsp_check_validates_url(self):
        """OCSP check should validate URL before request."""
        import inspect

        from pdfsigner.core.certificate import ocsp_checker

        source = inspect.getsource(ocsp_checker)
        # Check that validation happens before the request
        ocsp_section = source[
            source.find("Sending OCSP request") - 500 : source.find("Sending OCSP request")
        ]
        assert "validate_ocsp_url" in ocsp_section

    def test_crl_check_validates_url(self):
        """CRL check should validate URL before request."""
        import inspect

        from pdfsigner.core.certificate import crl_checker

        source = inspect.getsource(crl_checker)
        # Check that validation happens before the request
        crl_section = source[source.find("Downloading CRL") - 500 : source.find("Downloading CRL")]
        assert "validate_crl_url" in crl_section
