#!/bin/bash
# build-snap.sh - Build Snap package for PDFSigner
# Author: Homero Thompson del Lago del Terror
#
# This script builds a Snap package using snapcraft.
#
# Requirements:
#   - snapcraft (snap install snapcraft --classic)
#   - LXD or Multipass for building (snapcraft will prompt)
#
# Usage: ./build-snap.sh

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}\n"; }

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DIST_DIR="$PROJECT_ROOT/dist/snap"
SNAP_DIR="$PROJECT_ROOT/snap"

# Get version from Python
get_version() {
    python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from pdfsigner import __version__; print(__version__)"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v snapcraft &>/dev/null; then
        log_error "snapcraft not found."
        log_info "Install with: sudo snap install snapcraft --classic"
        exit 1
    fi

    # Check if LXD or Multipass is available
    if ! command -v lxd &>/dev/null && ! command -v multipass &>/dev/null; then
        log_warn "Neither LXD nor Multipass found."
        log_info "Snapcraft will prompt to install one during build."
        log_info "Recommended: sudo snap install lxd && sudo lxd init --auto"
    fi

    # Check snapcraft.yaml exists
    if [[ ! -f "$SNAP_DIR/snapcraft.yaml" ]]; then
        log_error "snap/snapcraft.yaml not found"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Update version in snapcraft.yaml
update_version() {
    local version="$1"

    log_info "Updating version in snapcraft.yaml to $version..."

    # Use sed to update version line
    sed -i "s/^version: .*/version: '$version'/" "$SNAP_DIR/snapcraft.yaml"

    log_info "Version updated"
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous build artifacts..."

    cd "$PROJECT_ROOT"

    # Clean snapcraft build state
    if command -v snapcraft &>/dev/null; then
        snapcraft clean 2>/dev/null || true
    fi

    # Remove old snaps from dist
    rm -f "$DIST_DIR"/*.snap 2>/dev/null || true

    log_info "Clean complete"
}

# Build the snap
build_snap() {
    local version="$1"

    log_header "Building Snap Package"

    cd "$PROJECT_ROOT"

    # Run snapcraft
    log_info "Running snapcraft (this may take a while)..."
    snapcraft --verbose

    # Move snap to dist directory
    mkdir -p "$DIST_DIR"

    local snap_file
    snap_file=$(find "$PROJECT_ROOT" -maxdepth 1 -name "pdfsigner_*.snap" -type f | head -1)

    if [[ -n "$snap_file" ]]; then
        mv "$snap_file" "$DIST_DIR/"
        local basename
        basename=$(basename "$snap_file")
        log_info "Snap package built: $DIST_DIR/$basename"
        ls -lh "$DIST_DIR/$basename"
    else
        log_error "No .snap file found after build"
        exit 1
    fi
}

# Show post-build instructions
show_instructions() {
    local version="$1"
    local snap_file="$DIST_DIR/pdfsigner_${version}_amd64.snap"

    log_header "Build Complete"

    if [[ -f "$snap_file" ]]; then
        local size
        size=$(du -h "$snap_file" | cut -f1)

        echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}Snap Package${NC}                                                    ${GREEN}│${NC}"
        echo -e "${GREEN}├─────────────────────────────────────────────────────────────────┤${NC}"
        echo -e "${GREEN}│${NC} File: $(basename "$snap_file") ($size)"
        echo -e "${GREEN}│${NC} Path: $snap_file"
        echo -e "${GREEN}│${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}Install (local):${NC}"
        echo -e "${GREEN}│${NC}   sudo snap install --dangerous $(basename "$snap_file")"
        echo -e "${GREEN}│${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}Connect USB token access:${NC}"
        echo -e "${GREEN}│${NC}   sudo snap connect pdfsigner:raw-usb"
        echo -e "${GREEN}│${NC}   sudo snap connect pdfsigner:hardware-observe"
        echo -e "${GREEN}│${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}Run:${NC}"
        echo -e "${GREEN}│${NC}   pdfsigner              # GUI"
        echo -e "${GREEN}│${NC}   pdfsigner.cli sign ... # CLI"
        echo -e "${GREEN}│${NC}"
        echo -e "${GREEN}│${NC} ${BOLD}Uninstall:${NC}"
        echo -e "${GREEN}│${NC}   sudo snap remove pdfsigner"
        echo -e "${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
    fi

    echo ""
    echo -e "${BOLD}Publishing to Snap Store:${NC}"
    echo -e "  1. Create account at https://snapcraft.io/account"
    echo -e "  2. snapcraft login"
    echo -e "  3. snapcraft register pdfsigner"
    echo -e "  4. snapcraft upload --release=stable $snap_file"
}

# Main
main() {
    local do_clean=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean)
                do_clean=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [--clean]"
                echo ""
                echo "Options:"
                echo "  --clean    Clean build artifacts before building"
                echo "  -h, --help Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    log_header "PDFSigner Snap Builder"

    cd "$PROJECT_ROOT"

    VERSION=$(get_version)
    log_info "Version: $VERSION"
    log_info "Project: $PROJECT_ROOT"

    check_prerequisites

    if $do_clean; then
        clean_build
    fi

    update_version "$VERSION"
    build_snap "$VERSION"
    show_instructions "$VERSION"
}

main "$@"
