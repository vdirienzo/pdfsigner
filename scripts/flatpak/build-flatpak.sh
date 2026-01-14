#!/bin/bash
# build-flatpak.sh - Build Flatpak for PDFSigner
# Author: Homero Thompson del Lago del Terror
#
# This script builds a Flatpak bundle using flatpak-builder.
#
# Requirements:
#   - flatpak
#   - flatpak-builder
#   - org.gnome.Platform//49 and org.gnome.Sdk//49 runtimes
#
# Usage: ./build-flatpak.sh

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
BUILD_DIR="$PROJECT_ROOT/build/flatpak"
DIST_DIR="$PROJECT_ROOT/dist/flatpak"
MANIFEST="$PROJECT_ROOT/flatpak/com.pdfsigner.app.yaml"

# Get version
get_version() {
    python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from pdfsigner import __version__; print(__version__)"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v flatpak &>/dev/null; then
        log_error "flatpak not found. Please install flatpak."
        exit 1
    fi

    if ! command -v flatpak-builder &>/dev/null; then
        log_error "flatpak-builder not found. Please install flatpak-builder."
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Install runtimes if missing
ensure_runtimes() {
    log_info "Checking GNOME runtimes..."

    local runtime="org.gnome.Platform"
    local sdk="org.gnome.Sdk"
    local version="49"

    if ! flatpak info "$runtime//$version" &>/dev/null; then
        log_info "Installing $runtime//$version..."
        flatpak install -y --user flathub "$runtime//$version"
    fi

    if ! flatpak info "$sdk//$version" &>/dev/null; then
        log_info "Installing $sdk//$version..."
        flatpak install -y --user flathub "$sdk//$version"
    fi

    log_info "Runtimes ready"
}

# Build Flatpak
build_flatpak() {
    local version="$1"
    local repo_dir="$BUILD_DIR/repo"
    local build_dir="$BUILD_DIR/build-dir"
    local output="$DIST_DIR/PDFSigner-${version}.flatpak"

    log_info "Building Flatpak..."

    mkdir -p "$DIST_DIR"
    rm -rf "$build_dir"

    # Build with flatpak-builder
    flatpak-builder \
        --force-clean \
        --user \
        --repo="$repo_dir" \
        --state-dir="$BUILD_DIR/state" \
        "$build_dir" \
        "$MANIFEST"

    # Create bundle
    flatpak build-bundle \
        "$repo_dir" \
        "$output" \
        com.pdfsigner.app

    log_info "Flatpak built: $output"
    ls -lh "$output"
}

# Main
main() {
    log_info "=== PDFSigner Flatpak Builder ==="

    cd "$PROJECT_ROOT"

    VERSION=$(get_version)
    log_info "Version: $VERSION"

    check_prerequisites
    ensure_runtimes
    build_flatpak "$VERSION"

    log_info "=== Build Complete ==="
    log_info "Install with: flatpak install --user $DIST_DIR/PDFSigner-${VERSION}.flatpak"
    log_info "Run with: flatpak run com.pdfsigner.app"
}

main "$@"
