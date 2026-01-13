"""
cli - Módulo de comandos CLI

Autor: Homero Thompson del Lago del Terror

Contiene los comandos del CLI: sign, validate, list-certs.
"""

from pdfsigner.cli.list_certs import cmd_list_certs
from pdfsigner.cli.sign import cmd_sign
from pdfsigner.cli.validate import cmd_validate

__all__ = ["cmd_sign", "cmd_validate", "cmd_list_certs"]
