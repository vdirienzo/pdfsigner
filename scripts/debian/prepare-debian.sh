#!/bin/bash
# prepare-debian.sh - Build Debian package for PDFSigner
# Author: Homero Thompson del Lago del Terror
#
# This script builds a .deb package using dpkg-buildpackage.
#
# Requirements:
#   - debhelper
#   - dh-python
#   - python3-build
#   - dpkg-dev
#
# Usage: ./prepare-debian.sh

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_DIR="$PROJECT_ROOT/build/debian"
DIST_DIR="$PROJECT_ROOT/dist/deb"

# Get version
get_version() {
    python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from pdfsigner import __version__; print(__version__)"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing=()

    if ! command -v dpkg-buildpackage &>/dev/null; then
        missing+=("dpkg-dev")
    fi

    if ! command -v dh &>/dev/null; then
        missing+=("debhelper")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing packages: ${missing[*]}"
        log_info "Install with: sudo apt install ${missing[*]} dh-python python3-build"
        exit 1
    fi

    # Check debian/ directory exists
    if [[ ! -d "$PROJECT_ROOT/debian" ]]; then
        log_error "debian/ directory not found"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Build package
build_deb() {
    local version="$1"

    log_info "Building Debian package..."

    cd "$PROJECT_ROOT"

    # Clean previous builds
    rm -rf "$PROJECT_ROOT/debian/.debhelper" \
           "$PROJECT_ROOT/debian/pdfsigner" \
           "$PROJECT_ROOT/debian/files" \
           "$PROJECT_ROOT/debian/debhelper-build-stamp"

    # Build package (unsigned)
    dpkg-buildpackage -us -uc -b

    # Move .deb to dist/
    mkdir -p "$DIST_DIR"

    # Find and move the built .deb
    local deb_file
    deb_file=$(find "$PROJECT_ROOT/.." -maxdepth 1 -name "pdfsigner_*.deb" -type f | head -1)

    if [[ -n "$deb_file" ]]; then
        mv "$deb_file" "$DIST_DIR/"
        local basename
        basename=$(basename "$deb_file")
        log_info "Debian package built: $DIST_DIR/$basename"
        ls -lh "$DIST_DIR/$basename"
    else
        log_error "No .deb file found after build"
        exit 1
    fi

    # Clean up other build artifacts in parent dir
    rm -f "$PROJECT_ROOT/../pdfsigner_"*.{changes,buildinfo}
}

# Main
main() {
    log_info "=== PDFSigner Debian Package Builder ==="

    cd "$PROJECT_ROOT"

    VERSION=$(get_version)
    log_info "Version: $VERSION"

    check_prerequisites
    build_deb "$VERSION"

    log_info "=== Build Complete ==="
    log_info "Install with: sudo dpkg -i $DIST_DIR/pdfsigner_*.deb"
    log_info "Then run: sudo apt install -f  # to install dependencies"
}

main "$@"
