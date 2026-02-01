"""
cli - CLI commands module

Author: Homero Thompson del Lago del Terror

Contains CLI commands: sign, validate, list-certs, archive-ts.
"""

from pdfsigner.cli.archive_ts import cmd_archive_ts
from pdfsigner.cli.list_certs import cmd_list_certs
from pdfsigner.cli.sign import cmd_sign
from pdfsigner.cli.validate import cmd_validate

__all__ = ["cmd_sign", "cmd_validate", "cmd_list_certs", "cmd_archive_ts"]
