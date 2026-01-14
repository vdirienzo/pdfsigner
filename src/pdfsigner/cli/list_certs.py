"""
list_certs.py - CLI command to list certificates

Author: Homero Thompson del Lago del Terror

Implements the 'list-certs' command to list certificates from token.
"""

import argparse

from loguru import logger

from pdfsigner.cli.utils import get_pin_from_user
from pdfsigner.core.token.cert_selector import CertificateSelector
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import PDFSignerError


def cmd_list_certs(args: argparse.Namespace) -> int:
    """Command to list certificates."""
    try:
        nss_handler = NSSHandler()
        nss_handler.initialize()

        tokens = nss_handler.get_available_tokens()
        if not tokens:
            print("USB token not detected")
            return 1

        print(f"Token: {tokens[0]}")
        nss_handler.connect_token()

        pin = get_pin_from_user()
        nss_handler.authenticate(pin)

        cert_selector = CertificateSelector(nss_handler)
        certs = cert_selector.get_valid_certificates()

        print(f"\nAvailable certificates ({len(certs)}):\n")
        for i, cert in enumerate(certs, 1):
            status = "⚠ EXPIRING SOON" if cert.is_expiring_soon else ""
            print(f"{i}. {cert.display_name}")
            print(f"   Issuer: {cert.info.issuer.split(',')[0]}")
            print(f"   Serial: {cert.info.serial_number}")
            print(f"   Valid until: {cert.info.not_after} ({cert.days_until_expiry} days) {status}")
            print()

        nss_handler.close()
        return 0

    except PDFSignerError as e:
        logger.error(f"Error: {e}")
        return 1
