#!/bin/bash
# uninstall.sh - PDFSigner Uninstaller
#
# Author: Homero Thompson del Lago del Terror
#
# Removes PDFSigner virtual environment (keeps configuration).

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║       PDFSigner - Uninstaller          ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
echo

# Remove virtual environment
if [ -d ".venv" ]; then
    echo -e "${YELLOW}→ Removing virtual environment...${NC}"
    rm -rf .venv
    echo -e "${GREEN}✓ Virtual environment removed${NC}"
else
    echo -e "${YELLOW}⚠ Virtual environment not found${NC}"
fi

echo
echo -e "${GREEN}✓ Uninstallation completed${NC}"
echo
echo -e "Note: Configuration is preserved at:"
echo -e "  ${YELLOW}~/.config/pdfsigner/config.toml${NC}"
echo
echo -e "To remove configuration as well:"
echo -e "  ${YELLOW}rm -rf ~/.config/pdfsigner${NC}"
echo
echo -e "To remove logs:"
echo -e "  ${YELLOW}rm -rf ~/.local/share/pdfsigner${NC}"
