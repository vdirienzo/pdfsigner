"""
url_validator.py - URL validation for SSRF prevention

Validates URLs to prevent Server-Side Request Forgery (SSRF) attacks.
OWASP: Server-Side Request Forgery Prevention Cheat Sheet
CWE-918: Server-Side Request Forgery
"""

import ipaddress
import re
from urllib.parse import urlparse

from loguru import logger


class SSRFError(Exception):
    """SSRF validation error."""

    pass


# Default allowed schemes
ALLOWED_SCHEMES = {"http", "https"}

# Private/internal IP ranges (RFC 1918, RFC 4193, etc.)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("100.64.0.0/10"),  # Shared address space (CGN)
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
]

# Blocked hostnames (case-insensitive)
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",  # GCP metadata
    "metadata.google.com",  # GCP metadata alias
    "169.254.169.254",  # AWS/Azure metadata
    "metadata",  # Generic cloud metadata
}

# Default whitelist for TSA servers (can be extended)
DEFAULT_TSA_WHITELIST = {
    "freetsa.org",
    "timestamp.digicert.com",
    "timestamp.globalsign.com",
    "timestamp.sectigo.com",
    "tsa.safecreative.org",
    "time.certum.pl",
    "timestamp.comodoca.com",
    "rfc3161timestamp.globalsign.com",
}


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is in a private/internal range.

    Args:
        ip_str: IP address string

    Returns:
        True if IP is private/internal, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve hostname to IP addresses.

    Args:
        hostname: Hostname to resolve

    Returns:
        List of resolved IP addresses

    Raises:
        SSRFError: If hostname cannot be resolved
    """
    import socket

    try:
        # Get all address info
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ips = list({str(result[4][0]) for result in results})
        return ips
    except socket.gaierror as e:
        raise SSRFError(f"Cannot resolve hostname '{hostname}': {e}") from e


def validate_url(
    url: str,
    allowed_schemes: set[str] | None = None,
    whitelist: set[str] | None = None,
    allow_private_ips: bool = False,
    check_dns: bool = True,
) -> str:
    """
    Validate URL for SSRF safety.

    Args:
        url: URL to validate
        allowed_schemes: Allowed URL schemes (default: http, https)
        whitelist: Optional whitelist of allowed hostnames
        allow_private_ips: Whether to allow private/internal IPs
        check_dns: Whether to perform DNS resolution check

    Returns:
        Validated URL (unchanged if valid)

    Raises:
        SSRFError: If URL fails validation
    """
    if not url:
        raise SSRFError("URL cannot be empty")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SSRFError(f"Invalid URL format: {e}") from e

    # Validate scheme
    schemes = allowed_schemes or ALLOWED_SCHEMES
    if parsed.scheme.lower() not in schemes:
        raise SSRFError(f"URL scheme '{parsed.scheme}' not allowed. Allowed: {schemes}")

    # Get hostname
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL must have a hostname")

    hostname_lower = hostname.lower()

    # Check blocked hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        raise SSRFError(f"Hostname '{hostname}' is blocked")

    # Check for obfuscated localhost (e.g., 127.0.0.1, [::1], etc.)
    if re.match(r"^(127\.|0\.|::1)", hostname_lower):
        raise SSRFError(f"Hostname '{hostname}' resolves to localhost")

    # Check whitelist if provided
    if whitelist:
        if hostname_lower not in whitelist:
            # Check if it's a subdomain of a whitelisted domain
            is_whitelisted = any(
                hostname_lower.endswith(f".{domain}") or hostname_lower == domain
                for domain in whitelist
            )
            if not is_whitelisted:
                raise SSRFError(f"Hostname '{hostname}' not in whitelist")

    # DNS resolution check
    if check_dns:
        try:
            ips = resolve_hostname(hostname)
        except SSRFError:
            # Re-raise DNS resolution errors
            raise

        # Check if any resolved IP is private
        if not allow_private_ips:
            for ip in ips:
                if is_private_ip(ip):
                    raise SSRFError(
                        f"Hostname '{hostname}' resolves to private IP {ip}. "
                        "This is blocked to prevent SSRF attacks."
                    )

    logger.debug(f"URL validated: {url}")
    return url


def validate_tsa_url(url: str, custom_whitelist: set[str] | None = None) -> str:
    """
    Validate TSA (Time Stamp Authority) URL.

    Uses default TSA whitelist plus any custom whitelist.

    Args:
        url: TSA URL to validate
        custom_whitelist: Additional allowed TSA hostnames

    Returns:
        Validated URL

    Raises:
        SSRFError: If URL fails validation
    """
    whitelist = DEFAULT_TSA_WHITELIST.copy()
    if custom_whitelist:
        whitelist.update(custom_whitelist)

    return validate_url(
        url,
        allowed_schemes={"http", "https"},
        whitelist=whitelist,
        allow_private_ips=False,
        check_dns=True,
    )


def validate_ocsp_url(url: str) -> str:
    """
    Validate OCSP responder URL.

    Args:
        url: OCSP URL to validate

    Returns:
        Validated URL

    Raises:
        SSRFError: If URL fails validation
    """
    return validate_url(
        url,
        allowed_schemes={"http", "https"},
        whitelist=None,  # OCSP URLs come from certificates, whitelist impractical
        allow_private_ips=False,
        check_dns=True,
    )


def validate_crl_url(url: str) -> str:
    """
    Validate CRL distribution point URL.

    Args:
        url: CRL URL to validate

    Returns:
        Validated URL

    Raises:
        SSRFError: If URL fails validation
    """
    return validate_url(
        url,
        allowed_schemes={"http", "https", "ldap"},  # CRLs can use LDAP
        whitelist=None,  # CRL URLs come from certificates
        allow_private_ips=False,
        check_dns=True,
    )


__all__ = [
    "SSRFError",
    "validate_url",
    "validate_tsa_url",
    "validate_ocsp_url",
    "validate_crl_url",
    "is_private_ip",
]
