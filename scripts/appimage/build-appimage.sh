#!/bin/bash
# build-appimage.sh - Build AppImage for PDFSigner
# Author: Homero Thompson del Lago del Terror
#
# This script creates an AppImage that bundles Python and pip dependencies.
# GTK4/PyGObject must be installed on the host system.
#
# Requirements:
#   - Python 3.12+
#   - pip/uv
#   - wget or curl (for downloading appimagetool)
#
# Usage: ./build-appimage.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_DIR="$PROJECT_ROOT/build/appimage"
APPDIR="$BUILD_DIR/PDFSigner.AppDir"
DIST_DIR="$PROJECT_ROOT/dist/appimage"
TOOLS_DIR="$BUILD_DIR/tools"

# Get version from Python
get_version() {
    python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from pdfsigner import __version__; print(__version__)"
}

# Download appimagetool if not present
ensure_appimagetool() {
    local tool="$TOOLS_DIR/appimagetool-x86_64.AppImage"

    if [[ -x "$tool" ]]; then
        log_info "appimagetool already available"
        return
    fi

    log_info "Downloading appimagetool..."
    mkdir -p "$TOOLS_DIR"

    local url="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
    if command -v wget &>/dev/null; then
        wget -q "$url" -O "$tool"
    elif command -v curl &>/dev/null; then
        curl -sL "$url" -o "$tool"
    else
        log_error "Neither wget nor curl found. Please install one of them."
        exit 1
    fi

    chmod +x "$tool"
    log_info "appimagetool downloaded"
}

# Create AppDir structure
create_appdir() {
    log_info "Creating AppDir structure..."

    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin"
    mkdir -p "$APPDIR/usr/lib/python3/site-packages"
    mkdir -p "$APPDIR/usr/share/applications"
    mkdir -p "$APPDIR/usr/share/metainfo"

    # Copy AppRun
    cp "$SCRIPT_DIR/AppRun" "$APPDIR/"
    chmod +x "$APPDIR/AppRun"

    # Copy desktop file
    cp "$PROJECT_ROOT/data/com.pdfsigner.app.desktop" "$APPDIR/"
    cp "$PROJECT_ROOT/data/com.pdfsigner.app.desktop" "$APPDIR/usr/share/applications/"

    # Copy metainfo
    cp "$PROJECT_ROOT/data/com.pdfsigner.app.metainfo.xml" "$APPDIR/usr/share/metainfo/"

    # Copy icons
    for size in 16 32 48 64 128 256 512; do
        local icon_dir="$APPDIR/usr/share/icons/hicolor/${size}x${size}/apps"
        mkdir -p "$icon_dir"
        cp "$PROJECT_ROOT/data/icons/${size}x${size}/apps/com.pdfsigner.app.png" "$icon_dir/"
    done

    # Main icon in root
    cp "$PROJECT_ROOT/data/icons/256x256/apps/com.pdfsigner.app.png" "$APPDIR/com.pdfsigner.app.png"

    log_info "AppDir structure created"
}

# Install Python dependencies
install_dependencies() {
    log_info "Installing Python dependencies..."

    local site_packages="$APPDIR/usr/lib/python3/site-packages"

    # Clean old wheels and build new one
    rm -rf "$BUILD_DIR/wheels"
    mkdir -p "$BUILD_DIR/wheels"

    cd "$PROJECT_ROOT"
    python3 -m pip wheel --no-deps -w "$BUILD_DIR/wheels" .

    # Install dependencies to AppDir
    python3 -m pip install \
        --target="$site_packages" \
        --no-compile \
        --upgrade \
        pyhanko[pkcs11] python-pkcs11 pymupdf pydantic-settings \
        loguru cryptography certifi urllib3 babel qrcode pillow

    # Install pdfsigner itself
    python3 -m pip install \
        --target="$site_packages" \
        --no-compile \
        --no-deps \
        "$BUILD_DIR/wheels"/*.whl

    # Clean up unnecessary files
    find "$site_packages" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$site_packages" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
    find "$site_packages" -type f -name "*.pyc" -delete 2>/dev/null || true

    log_info "Dependencies installed"
}

# Build the AppImage
build_appimage() {
    local version="$1"
    local output="$DIST_DIR/PDFSigner-${version}-x86_64.AppImage"

    log_info "Building AppImage..."

    mkdir -p "$DIST_DIR"

    # Set architecture
    export ARCH=x86_64

    # Run appimagetool
    "$TOOLS_DIR/appimagetool-x86_64.AppImage" \
        --appimage-extract-and-run \
        "$APPDIR" \
        "$output"

    chmod +x "$output"

    log_info "AppImage built: $output"
    ls -lh "$output"
}

# Main
main() {
    log_info "=== PDFSigner AppImage Builder ==="

    cd "$PROJECT_ROOT"

    VERSION=$(get_version)
    log_info "Version: $VERSION"

    ensure_appimagetool
    create_appdir
    install_dependencies
    build_appimage "$VERSION"

    log_info "=== Build Complete ==="
}

main "$@"
