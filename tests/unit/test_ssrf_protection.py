"""
test_ssrf_protection.py - Tests for SSRF protection

Tests URL validation to prevent Server-Side Request Forgery attacks.
"""

import pytest

from pdfsigner.core.security.url_validator import (
    SSRFError,
    is_private_ip,
    validate_crl_url,
    validate_ocsp_url,
    validate_tsa_url,
    validate_url,
)


class TestIsPrivateIP:
    """Test private IP detection."""

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.0.1",
            "0.0.0.1",
        ],
    )
    def test_private_ipv4_detected(self, ip):
        """Private IPv4 addresses should be detected."""
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
            "93.184.216.34",
        ],
    )
    def test_public_ipv4_not_private(self, ip):
        """Public IPv4 addresses should not be detected as private."""
        assert is_private_ip(ip) is False

    def test_ipv6_loopback(self):
        """IPv6 loopback should be detected as private."""
        assert is_private_ip("::1") is True

    def test_invalid_ip(self):
        """Invalid IP should return False."""
        assert is_private_ip("not-an-ip") is False
        assert is_private_ip("") is False


class TestValidateUrl:
    """Test URL validation."""

    def test_valid_https_url(self):
        """Valid HTTPS URL should pass."""
        url = "https://example.com/path"
        result = validate_url(url, check_dns=False)
        assert result == url

    def test_valid_http_url(self):
        """Valid HTTP URL should pass."""
        url = "http://example.com/path"
        result = validate_url(url, check_dns=False)
        assert result == url

    def test_empty_url_rejected(self):
        """Empty URL should be rejected."""
        with pytest.raises(SSRFError, match="cannot be empty"):
            validate_url("")

    def test_invalid_scheme_rejected(self):
        """Non-HTTP(S) schemes should be rejected by default."""
        with pytest.raises(SSRFError, match="scheme.*not allowed"):
            validate_url("ftp://example.com/file", check_dns=False)

    def test_file_scheme_rejected(self):
        """File scheme should be rejected."""
        with pytest.raises(SSRFError, match="scheme.*not allowed"):
            validate_url("file:///etc/passwd", check_dns=False)

    def test_localhost_rejected(self):
        """Localhost should be rejected."""
        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://localhost/admin", check_dns=False)

    def test_localhost_variants_rejected(self):
        """Localhost variants should be rejected."""
        variants = [
            "http://localhost.localdomain/",
            "http://127.0.0.1/",
            "http://127.1/",
        ]
        for url in variants:
            with pytest.raises(SSRFError):
                validate_url(url, check_dns=False)

    def test_metadata_endpoint_rejected(self):
        """Cloud metadata endpoints should be rejected."""
        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://169.254.169.254/latest/meta-data/", check_dns=False)

        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://metadata.google.internal/", check_dns=False)

    def test_whitelist_allows_domain(self):
        """Whitelisted domain should be allowed."""
        url = "https://allowed.example.com/path"
        result = validate_url(url, whitelist={"allowed.example.com"}, check_dns=False)
        assert result == url

    def test_whitelist_blocks_non_listed(self):
        """Non-whitelisted domain should be blocked."""
        with pytest.raises(SSRFError, match="not in whitelist"):
            validate_url(
                "https://evil.com/",
                whitelist={"good.com"},
                check_dns=False,
            )

    def test_whitelist_allows_subdomain(self):
        """Subdomain of whitelisted domain should be allowed."""
        url = "https://sub.example.com/path"
        result = validate_url(url, whitelist={"example.com"}, check_dns=False)
        assert result == url


class TestValidateTsaUrl:
    """Test TSA URL validation."""

    def test_default_tsa_whitelisted(self):
        """Default TSA servers should be allowed."""
        urls = [
            "http://freetsa.org/tsr",
            "https://timestamp.digicert.com",
            "https://timestamp.globalsign.com/tsa/v4/tsr",
        ]
        for url in urls:
            result = validate_tsa_url(url, custom_whitelist=None)
            assert result == url

    def test_custom_tsa_allowed(self):
        """Custom TSA servers should be allowed via whitelist."""
        url = "https://custom-tsa.example.com/timestamp"
        result = validate_tsa_url(url, custom_whitelist={"custom-tsa.example.com"})
        assert result == url

    def test_private_tsa_blocked(self):
        """Private network TSA URLs should be blocked."""
        with pytest.raises(SSRFError):
            # Even if whitelisted, DNS check will fail for private IPs
            validate_tsa_url("http://192.168.1.100/tsr")


class TestValidateOcspUrl:
    """Test OCSP URL validation."""

    def test_valid_ocsp_url(self):
        """Valid OCSP URL should pass."""
        # OCSP URLs are typically HTTP (not HTTPS) for performance
        url = "http://ocsp.example.com/"
        result = validate_ocsp_url(url)
        assert result == url

    def test_localhost_ocsp_blocked(self):
        """Localhost OCSP should be blocked."""
        with pytest.raises(SSRFError):
            validate_ocsp_url("http://localhost/ocsp")


class TestValidateCrlUrl:
    """Test CRL URL validation."""

    def test_valid_http_crl(self):
        """HTTP CRL URL should pass."""
        url = "http://crl.example.com/ca.crl"
        result = validate_crl_url(url)
        assert result == url

    def test_ldap_crl_allowed(self):
        """LDAP CRL URL should be allowed."""
        # CRLs can use LDAP protocol
        url = "ldap://ldap.example.com/cn=CRL,ou=CA,o=Example"
        result = validate_crl_url(url)
        assert result == url


class TestDnsResolution:
    """Test DNS resolution checks."""

    def test_dns_check_catches_private_ip(self, monkeypatch):
        """DNS resolution to private IP should be blocked."""

        # Mock DNS resolution to return private IP
        def mock_getaddrinfo(hostname, port, family):
            return [
                (2, 1, 6, "", ("10.0.0.1", 80)),
            ]

        import socket

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        with pytest.raises(SSRFError, match="private IP"):
            validate_url("https://evil-rebind.example.com/", check_dns=True)

    def test_dns_check_allows_public_ip(self, monkeypatch):
        """DNS resolution to public IP should be allowed."""

        # Mock DNS resolution to return public IP
        def mock_getaddrinfo(hostname, port, family):
            return [
                (2, 1, 6, "", ("93.184.216.34", 80)),
            ]

        import socket

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        result = validate_url("https://example.com/", check_dns=True)
        assert result == "https://example.com/"
