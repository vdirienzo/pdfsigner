"""
validate.py - Comando de validación CLI

Autor: Homero Thompson del Lago del Terror

Implementa el comando 'validate' para validar firmas de PDFs.
"""

import argparse

from loguru import logger

from pdfsigner.cli.utils import collect_pdf_files
from pdfsigner.core.validator.pdf_validator import PDFValidator, SignatureStatus


def cmd_validate(args: argparse.Namespace) -> int:
    """Comando de validación."""
    pdf_files = collect_pdf_files(args.files, args.recursive)

    if not pdf_files:
        logger.error("No hay archivos PDF para validar")
        return 1

    validator = PDFValidator()
    all_valid = True
    total_signatures = 0

    for pdf_path in pdf_files:
        result = validator.validate(pdf_path)

        if result.error:
            print(f"✗ {pdf_path.name}: Error - {result.error}")
            all_valid = False
            continue

        if not result.is_signed:
            print(f"○ {pdf_path.name}: Sin firmas")
            continue

        total_signatures += result.signature_count

        if result.all_valid:
            print(f"✓ {pdf_path.name}: {result.signature_count} firma(s) válida(s)")
        else:
            print(f"⚠ {pdf_path.name}: {result.signature_count} firma(s), algunas inválidas")
            all_valid = False

        # Mostrar detalles si es verbose
        if args.verbose:
            for sig in result.signatures:
                status_icon = "✓" if sig.status == SignatureStatus.VALID else "✗"
                ts_info = ""
                if sig.is_timestamp_valid and sig.signing_time:
                    ts_info = f" ({sig.signing_time.strftime('%d/%m/%Y %H:%M')})"
                print(f"    {status_icon} {sig.signer_name}{ts_info}")

    print(f"\nTotal: {len(pdf_files)} archivo(s), {total_signatures} firma(s)")
    return 0 if all_valid else 1
