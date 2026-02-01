"""
cli - CLI commands module

Author: Homero Thompson del Lago del Terror

Contains CLI commands: sign, validate, list-certs, archive-ts, encrypt, decrypt, scan-pii.
"""

from pdfsigner.cli.archive_ts import cmd_archive_ts
from pdfsigner.cli.encrypt import cmd_decrypt, cmd_encrypt
from pdfsigner.cli.list_certs import cmd_list_certs
from pdfsigner.cli.redact import cmd_redact
from pdfsigner.cli.scan_pii import cmd_scan_pii
from pdfsigner.cli.sign import cmd_sign
from pdfsigner.cli.validate import cmd_validate

__all__ = [
    "cmd_sign",
    "cmd_validate",
    "cmd_list_certs",
    "cmd_archive_ts",
    "cmd_encrypt",
    "cmd_decrypt",
    "cmd_scan_pii",
    "cmd_redact",
]
