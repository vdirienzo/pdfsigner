#!/bin/bash
# uninstall.sh - Desinstalador de PDFSigner
#
# Autor: Homero Thompson del Lago del Terror
#
# Elimina la extensión de Nautilus (mantiene configuración).

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║     PDFSigner - Desinstalador          ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
echo

EXTENSION_FILE="$HOME/.local/share/nautilus-python/extensions/pdfsigner.py"

# Eliminar extensión
if [ -f "$EXTENSION_FILE" ]; then
    rm "$EXTENSION_FILE"
    echo -e "${GREEN}✓ Extensión eliminada${NC}"
else
    echo -e "${YELLOW}⚠ Extensión no encontrada${NC}"
fi

# Reiniciar Nautilus
echo -e "${YELLOW}→ Reiniciando Nautilus...${NC}"
nautilus -q 2>/dev/null || true

echo
echo -e "${GREEN}✓ Desinstalación completada${NC}"
echo
echo -e "Nota: La configuración se mantiene en:"
echo -e "  ${YELLOW}~/.config/pdfsigner/config.toml${NC}"
echo
echo -e "Para eliminarla también:"
echo -e "  ${YELLOW}rm -rf ~/.config/pdfsigner${NC}"
