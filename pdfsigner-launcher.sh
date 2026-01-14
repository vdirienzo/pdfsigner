#!/bin/bash
# PDFSigner Launcher
# Author: Homero Thompson del Lago del Terror

# Ensure child processes are killed when this script exits
cleanup() {
    pkill -P $$ 2>/dev/null
}
trap cleanup EXIT

cd /home/user/projects/pdfsigner
/home/user/.local/bin/uv run pdfsigner-gui "$@"
