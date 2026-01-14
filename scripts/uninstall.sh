#!/bin/bash
# uninstall.sh - PDFSigner Uninstaller
#
# Author: Homero Thompson del Lago del Terror
#
# Removes the Nautilus extension (keeps configuration).

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║       PDFSigner - Uninstaller          ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
echo

EXTENSION_FILE="$HOME/.local/share/nautilus-python/extensions/pdfsigner_nautilus.py"
OLD_EXTENSION_FILE="$HOME/.local/share/nautilus-python/extensions/pdfsigner.py"

# Remove extension (both old and new names)
REMOVED=false
if [ -f "$EXTENSION_FILE" ]; then
    rm "$EXTENSION_FILE"
    REMOVED=true
fi
if [ -f "$OLD_EXTENSION_FILE" ]; then
    rm "$OLD_EXTENSION_FILE"
    REMOVED=true
fi

if [ "$REMOVED" = true ]; then
    echo -e "${GREEN}✓ Extension removed${NC}"
else
    echo -e "${YELLOW}⚠ Extension not found${NC}"
fi

# Restart Nautilus
echo -e "${YELLOW}→ Restarting Nautilus...${NC}"
nautilus -q 2>/dev/null || true

echo
echo -e "${GREEN}✓ Uninstallation completed${NC}"
echo
echo -e "Note: Configuration is preserved at:"
echo -e "  ${YELLOW}~/.config/pdfsigner/config.toml${NC}"
echo
echo -e "To remove it as well:"
echo -e "  ${YELLOW}rm -rf ~/.config/pdfsigner${NC}"
