"""
list_certs.py - Comando para listar certificados CLI

Autor: Homero Thompson del Lago del Terror

Implementa el comando 'list-certs' para listar certificados del token.
"""

import argparse

from loguru import logger

from pdfsigner.cli.utils import get_pin_from_user
from pdfsigner.core.token.cert_selector import CertificateSelector
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import PDFSignerError


def cmd_list_certs(args: argparse.Namespace) -> int:
    """Comando para listar certificados."""
    try:
        nss_handler = NSSHandler()
        nss_handler.initialize()

        tokens = nss_handler.get_available_tokens()
        if not tokens:
            print("No se detectó token USB")
            return 1

        print(f"Token: {tokens[0]}")
        nss_handler.connect_token()

        pin = get_pin_from_user()
        nss_handler.authenticate(pin)

        cert_selector = CertificateSelector(nss_handler)
        certs = cert_selector.get_valid_certificates()

        print(f"\nCertificados disponibles ({len(certs)}):\n")
        for i, cert in enumerate(certs, 1):
            status = "⚠ EXPIRA PRONTO" if cert.is_expiring_soon else ""
            print(f"{i}. {cert.display_name}")
            print(f"   Emisor: {cert.info.issuer.split(',')[0]}")
            print(f"   Serial: {cert.info.serial_number}")
            print(
                f"   Válido hasta: {cert.info.not_after} ({cert.days_until_expiry} días) {status}"
            )
            print()

        nss_handler.close()
        return 0

    except PDFSignerError as e:
        logger.error(f"Error: {e}")
        return 1
