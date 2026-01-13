"""
sign.py - Comando de firma CLI

Autor: Homero Thompson del Lago del Terror

Implementa el comando 'sign' para firma de PDFs.
Soporta modo real y dry-run.
"""

import argparse
from pathlib import Path

from loguru import logger

from pdfsigner.cli.utils import collect_pdf_files, get_pin_from_user
from pdfsigner.config.settings import get_settings
from pdfsigner.core.signer.batch_manager import BatchManager
from pdfsigner.core.signer.lta_handler import create_lta_handler_from_settings
from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.core.token.cert_selector import CertificateSelector
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.exceptions import PDFSignerError

# Flag global para dry-run (seteado desde main.py)
_dry_run_mode = False


def set_dry_run_mode(enabled: bool) -> None:
    """Activa/desactiva modo dry-run globalmente."""
    global _dry_run_mode
    _dry_run_mode = enabled


def cmd_sign(args: argparse.Namespace) -> int:
    """Comando de firma."""
    try:
        pdf_files = collect_pdf_files(args.files, args.recursive)

        if not pdf_files:
            logger.error("No hay archivos PDF para firmar")
            return 1

        logger.info(f"Archivos a firmar: {len(pdf_files)}")

        # Determinar si estamos en modo dry-run
        dry_run = _dry_run_mode or get_settings().dry_run

        if dry_run:
            return _sign_dry_run(args, pdf_files)
        else:
            return _sign_real(args, pdf_files)

    except PDFSignerError as e:
        logger.error(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nCancelado")
        return 130


def _sign_dry_run(args: argparse.Namespace, pdf_files: list[Path]) -> int:
    """Firma en modo simulación (dry-run)."""
    from pdfsigner.core.mock import MockBatchManager, MockNSSHandler, create_mock_certificate

    print("\n" + "=" * 60)
    print("⚠️  MODO DRY-RUN - SIMULACIÓN SIN TOKEN REAL")
    print("=" * 60)
    print("Los archivos serán copiados con sufijo _firmado")
    print("pero NO contendrán firma digital real.\n")

    logger.info("[DRY-RUN] Simulando conexión con token...")
    nss_handler = MockNSSHandler()
    nss_handler.initialize()

    tokens = nss_handler.get_available_tokens()
    logger.info(f"[DRY-RUN] Token simulado: {tokens[0]}")
    nss_handler.connect_token()

    print("[DRY-RUN] Ingrese cualquier PIN de 4+ dígitos para simular:")
    pin = get_pin_from_user()
    nss_handler.authenticate(pin)
    logger.info("[DRY-RUN] Autenticación simulada exitosa")

    certs = nss_handler.get_certificates()
    cert = certs[0] if certs else create_mock_certificate()
    print(f"\n[DRY-RUN] Usando certificado simulado: {cert.display_name}")

    page = _parse_page(args.page)
    batch_manager = MockBatchManager()

    def progress_callback(progress):
        pct = progress.current / progress.total * 100
        current = progress.current_file or "Completado"
        status = f"[{progress.status}]" if progress.status else ""
        print(f"\r[DRY-RUN] [{pct:5.1f}%] {current:<40} {status}", end="", flush=True)

    print()
    result = batch_manager.sign_batch(
        files=pdf_files,
        pin=pin,
        visible=args.visible,
        page=page,
        progress_callback=progress_callback,
    )
    print()

    nss_handler.close()

    print("\n" + "-" * 60)
    if result.all_successful:
        print(f"✓ [DRY-RUN] {result.successful} archivo(s) copiados con sufijo _firmado")
        print("\n⚠️  Nota: Los archivos NO están realmente firmados.")
        print("   Se crearon copias para simular el proceso.")
        return 0
    else:
        print(f"[DRY-RUN] {result.successful} copiado(s), {result.failed} fallido(s)")
        for path, error in result.get_failed_files():
            print(f"  ✗ {path.name}: {error}")
        return 1


def _sign_real(args: argparse.Namespace, pdf_files: list[Path]) -> int:
    """Firma real con token USB."""
    logger.info("Conectando con token USB...")
    nss_handler = NSSHandler()
    nss_handler.initialize()

    tokens = nss_handler.get_available_tokens()
    if not tokens:
        logger.error("No se detectó token USB")
        return 1

    logger.info(f"Token encontrado: {tokens[0]}")
    nss_handler.connect_token()

    pin = get_pin_from_user()
    nss_handler.authenticate(pin)
    logger.info("Autenticación exitosa")

    cert_selector = CertificateSelector(nss_handler)
    certs = cert_selector.get_valid_certificates()

    if len(certs) > 1 and not args.cert:
        print("\nCertificados disponibles:")
        for i, cert in enumerate(certs, 1):
            status = "⚠" if cert.is_expiring_soon else "✓"
            print(f"  {i}. [{status}] {cert.display_name} ({cert.days_until_expiry} días)")
        print(f"\nUsando certificado por defecto: {certs[0].display_name}")
        print("Use --cert N para seleccionar otro\n")

    cert_index = (args.cert - 1) if args.cert else 0
    if cert_index >= len(certs):
        logger.error(f"Certificado {args.cert} no existe")
        nss_handler.close()
        return 1

    cert = certs[cert_index]
    logger.info(f"Usando certificado: {cert.display_name}")

    try:
        lta_handler = create_lta_handler_from_settings()
    except Exception as e:
        logger.warning(f"TSA no disponible: {e}")
        lta_handler = None

    page = _parse_page(args.page)
    appearance = SignatureAppearance(visible=args.visible, page=page)

    batch_manager = BatchManager(nss_handler, lta_handler)

    def progress_callback(progress):
        pct = (progress.completed + progress.failed) / progress.total * 100
        current = progress.current_file or "Completado"
        print(f"\r[{pct:5.1f}%] {current:<50}", end="", flush=True)

    print()
    result = batch_manager.sign_batch(
        pdf_files=pdf_files,
        appearance=appearance,
        cert_id=cert.info.pkcs11_id,
        progress_callback=progress_callback,
    )
    print()

    nss_handler.close()

    if result.all_successful:
        print(f"\n✓ {result.successful} archivo(s) firmado(s) correctamente")
        return 0
    else:
        print(f"\n{result.successful} exitoso(s), {result.failed} fallido(s)")
        for path, error in result.get_failed_files():
            print(f"  ✗ {path.name}: {error}")
        return 1


def _parse_page(page: str) -> str | int:
    """Parsea el argumento de página."""
    if page in ("last", "first"):
        return page
    try:
        return int(page) - 1
    except ValueError:
        return "last"
