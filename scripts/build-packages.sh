#!/bin/bash
# build-packages.sh - Main packaging script for PDFSigner
# Author: Homero Thompson del Lago del Terror
#
# Builds distribution packages: AppImage, .deb, and Flatpak
#
# Usage:
#   ./build-packages.sh --all          # Build all formats
#   ./build-packages.sh --appimage     # Build AppImage only
#   ./build-packages.sh --deb          # Build .deb only
#   ./build-packages.sh --flatpak      # Build Flatpak only
#   ./build-packages.sh --clean        # Clean build directories
#
# Requirements vary by format:
#   AppImage: Python 3.12+, pip
#   Debian:   debhelper, dh-python, dpkg-dev
#   Flatpak:  flatpak, flatpak-builder

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Logging functions
# ============================================================================

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}\n"; }

# ============================================================================
# Helper functions
# ============================================================================

show_usage() {
    cat << EOF
${BOLD}PDFSigner Package Builder${NC}

Build distribution packages for PDFSigner.

${BOLD}Usage:${NC}
    $0 [OPTIONS]

${BOLD}Options:${NC}
    --appimage      Build AppImage
    --deb           Build Debian package (.deb)
    --flatpak       Build Flatpak bundle
    --all           Build all formats
    --clean         Clean build directories
    -h, --help      Show this help message

${BOLD}Examples:${NC}
    $0 --all                    # Build everything
    $0 --appimage --deb         # Build AppImage and .deb
    $0 --flatpak                # Build Flatpak only
    $0 --clean && $0 --all      # Clean rebuild

${BOLD}Output:${NC}
    dist/appimage/PDFSigner-{VERSION}-x86_64.AppImage
    dist/deb/pdfsigner_{VERSION}-1_all.deb
    dist/flatpak/PDFSigner-{VERSION}.flatpak

${BOLD}Requirements:${NC}
    AppImage: Python 3.12+, pip, wget/curl
    Debian:   debhelper, dh-python, python3-build, dpkg-dev
    Flatpak:  flatpak, flatpak-builder, GNOME runtime

EOF
}

get_version() {
    python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT/src'); from pdfsigner import __version__; print(__version__)"
}

check_project_root() {
    if [[ ! -f "$PROJECT_ROOT/pyproject.toml" ]]; then
        log_error "Not in project root. pyproject.toml not found."
        exit 1
    fi
}

clean_build() {
    log_info "Cleaning build directories..."
    rm -rf "$PROJECT_ROOT/build" "$PROJECT_ROOT/dist"
    rm -rf "$PROJECT_ROOT/debian/.debhelper"
    rm -rf "$PROJECT_ROOT/debian/pdfsigner"
    rm -rf "$PROJECT_ROOT/debian/files"
    rm -rf "$PROJECT_ROOT/debian/debhelper-build-stamp"
    log_info "Clean complete"
}

# ============================================================================
# Build functions
# ============================================================================

build_appimage() {
    log_header "Building AppImage"

    if [[ ! -f "$SCRIPT_DIR/appimage/build-appimage.sh" ]]; then
        log_error "AppImage build script not found"
        return 1
    fi

    bash "$SCRIPT_DIR/appimage/build-appimage.sh"
}

build_deb() {
    log_header "Building Debian Package"

    if [[ ! -f "$SCRIPT_DIR/debian/prepare-debian.sh" ]]; then
        log_error "Debian build script not found"
        return 1
    fi

    bash "$SCRIPT_DIR/debian/prepare-debian.sh"
}

build_flatpak() {
    log_header "Building Flatpak"

    if [[ ! -f "$SCRIPT_DIR/flatpak/build-flatpak.sh" ]]; then
        log_error "Flatpak build script not found"
        return 1
    fi

    bash "$SCRIPT_DIR/flatpak/build-flatpak.sh"
}

show_summary() {
    log_header "Build Summary"

    echo -e "${BOLD}Generated packages:${NC}\n"

    local found=0

    if [[ -d "$PROJECT_ROOT/dist" ]]; then
        while IFS= read -r -d '' file; do
            local size
            size=$(du -h "$file" | cut -f1)
            echo -e "  ${GREEN}✓${NC} $(basename "$file") (${size})"
            found=1
        done < <(find "$PROJECT_ROOT/dist" -type f \( -name "*.AppImage" -o -name "*.deb" -o -name "*.flatpak" \) -print0 2>/dev/null)
    fi

    if [[ $found -eq 0 ]]; then
        echo -e "  ${YELLOW}No packages found${NC}"
    fi

    echo ""
    log_info "Packages are in: $PROJECT_ROOT/dist/"
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    local build_appimage=false
    local build_deb=false
    local build_flatpak=false
    local do_clean=false

    if [[ $# -eq 0 ]]; then
        show_usage
        exit 0
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --appimage)
                build_appimage=true
                shift
                ;;
            --deb)
                build_deb=true
                shift
                ;;
            --flatpak)
                build_flatpak=true
                shift
                ;;
            --all)
                build_appimage=true
                build_deb=true
                build_flatpak=true
                shift
                ;;
            --clean)
                do_clean=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Change to project root
    cd "$PROJECT_ROOT"
    check_project_root

    # Handle clean
    if $do_clean; then
        clean_build
        # If only --clean was specified, exit
        if ! $build_appimage && ! $build_deb && ! $build_flatpak; then
            exit 0
        fi
    fi

    # Show version
    log_header "PDFSigner Package Builder"
    VERSION=$(get_version)
    log_info "Version: $VERSION"
    log_info "Project: $PROJECT_ROOT"

    # Create dist directory
    mkdir -p "$PROJECT_ROOT/dist"

    # Track build status
    local failed=0

    # Build requested formats
    if $build_appimage; then
        if ! build_appimage; then
            log_error "AppImage build failed"
            ((failed++))
        fi
    fi

    if $build_deb; then
        if ! build_deb; then
            log_error "Debian package build failed"
            ((failed++))
        fi
    fi

    if $build_flatpak; then
        if ! build_flatpak; then
            log_error "Flatpak build failed"
            ((failed++))
        fi
    fi

    # Show summary
    show_summary

    if [[ $failed -gt 0 ]]; then
        log_error "$failed build(s) failed"
        exit 1
    fi

    log_info "All builds completed successfully!"
}

main "$@"
