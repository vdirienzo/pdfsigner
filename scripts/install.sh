#!/bin/bash
# install.sh - PDFSigner Installer
#
# Author: Homero Thompson del Lago del Terror
#
# Installs dependencies and creates initial configuration.
# Detects distribution and offers to install system dependencies.

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              PDFSigner - Installer v0.9.2                  ║${NC}"
echo -e "${GREEN}║     Digital PDF signing with USB cryptographic tokens     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo

# ============================================================================
# Utility functions
# ============================================================================

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_step() {
    echo -e "${CYAN}→${NC} $1"
}

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_NAME="$NAME"
        DISTRO_VERSION="$VERSION_ID"
        DISTRO_FAMILY="$ID_LIKE"
    elif [ -f /etc/debian_version ]; then
        DISTRO_ID="debian"
        DISTRO_NAME="Debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        DISTRO_FAMILY="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO_ID="rhel"
        DISTRO_NAME="Red Hat"
        DISTRO_FAMILY="rhel fedora"
    else
        DISTRO_ID="unknown"
        DISTRO_NAME="Unknown"
        DISTRO_FAMILY=""
    fi
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Check if a Python package is installed in the system
python_pkg_installed() {
    python3 -c "import $1" 2>/dev/null
}

# ============================================================================
# Install dependencies by distribution
# ============================================================================

install_deps_debian() {
    log_step "Installing dependencies for Debian/Ubuntu..."

    local PACKAGES=(
        "python3-gi"
        "python3-gi-cairo"
        "gir1.2-gtk-4.0"
        "gir1.2-adw-1"
        "libnss3-tools"
        "opensc"
    )

    # Check which are missing
    local MISSING=()
    for pkg in "${PACKAGES[@]}"; do
        if ! dpkg -l "$pkg" &>/dev/null; then
            MISSING+=("$pkg")
        fi
    done

    if [ ${#MISSING[@]} -eq 0 ]; then
        log_success "All system dependencies already installed"
        return 0
    fi

    log_warning "Missing packages: ${MISSING[*]}"
    echo
    read -p "Install dependencies with apt? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]?$ ]]; then
        sudo apt update
        sudo apt install -y "${MISSING[@]}"
        log_success "Dependencies installed"
    else
        log_warning "Skipping system dependencies installation"
        log_info "Install manually: sudo apt install ${MISSING[*]}"
    fi
}

install_deps_fedora() {
    log_step "Installing dependencies for Fedora/RHEL..."

    local PACKAGES=(
        "python3-gobject"
        "gtk4"
        "libadwaita"
        "nss-tools"
        "opensc"
    )

    # Check which are missing
    local MISSING=()
    for pkg in "${PACKAGES[@]}"; do
        if ! rpm -q "$pkg" &>/dev/null; then
            MISSING+=("$pkg")
        fi
    done

    if [ ${#MISSING[@]} -eq 0 ]; then
        log_success "All system dependencies already installed"
        return 0
    fi

    log_warning "Missing packages: ${MISSING[*]}"
    echo
    read -p "Install dependencies with dnf? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]?$ ]]; then
        sudo dnf install -y "${MISSING[@]}"
        log_success "Dependencies installed"
    else
        log_warning "Skipping system dependencies installation"
        log_info "Install manually: sudo dnf install ${MISSING[*]}"
    fi
}

install_deps_arch() {
    log_step "Installing dependencies for Arch Linux..."

    local PACKAGES=(
        "python-gobject"
        "gtk4"
        "libadwaita"
        "nss"
        "opensc"
    )

    # Check which are missing
    local MISSING=()
    for pkg in "${PACKAGES[@]}"; do
        if ! pacman -Qi "$pkg" &>/dev/null; then
            MISSING+=("$pkg")
        fi
    done

    if [ ${#MISSING[@]} -eq 0 ]; then
        log_success "All system dependencies already installed"
        return 0
    fi

    log_warning "Missing packages: ${MISSING[*]}"
    echo
    read -p "Install dependencies with pacman? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]?$ ]]; then
        sudo pacman -S --noconfirm "${MISSING[@]}"
        log_success "Dependencies installed"
    else
        log_warning "Skipping system dependencies installation"
        log_info "Install manually: sudo pacman -S ${MISSING[*]}"
    fi
}

install_deps_opensuse() {
    log_step "Installing dependencies for openSUSE..."

    local PACKAGES=(
        "python3-gobject"
        "python3-gobject-Gdk"
        "gtk4"
        "libadwaita-1-0"
        "mozilla-nss-tools"
        "opensc"
    )

    # Check which are missing
    local MISSING=()
    for pkg in "${PACKAGES[@]}"; do
        if ! rpm -q "$pkg" &>/dev/null; then
            MISSING+=("$pkg")
        fi
    done

    if [ ${#MISSING[@]} -eq 0 ]; then
        log_success "All system dependencies already installed"
        return 0
    fi

    log_warning "Missing packages: ${MISSING[*]}"
    echo
    read -p "Install dependencies with zypper? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]?$ ]]; then
        sudo zypper install -y "${MISSING[@]}"
        log_success "Dependencies installed"
    else
        log_warning "Skipping system dependencies installation"
        log_info "Install manually: sudo zypper install ${MISSING[*]}"
    fi
}

install_system_deps() {
    detect_distro

    log_info "Detected distribution: $DISTRO_NAME ($DISTRO_ID)"
    echo

    case "$DISTRO_ID" in
        debian|ubuntu|linuxmint|pop|elementary|zorin|kali)
            install_deps_debian
            ;;
        fedora|rhel|centos|rocky|alma)
            install_deps_fedora
            ;;
        arch|manjaro|endeavouros|garuda)
            install_deps_arch
            ;;
        opensuse*|sles)
            install_deps_opensuse
            ;;
        *)
            # Try by family
            if [[ "$DISTRO_FAMILY" == *"debian"* ]]; then
                install_deps_debian
            elif [[ "$DISTRO_FAMILY" == *"fedora"* ]] || [[ "$DISTRO_FAMILY" == *"rhel"* ]]; then
                install_deps_fedora
            elif [[ "$DISTRO_FAMILY" == *"arch"* ]]; then
                install_deps_arch
            elif [[ "$DISTRO_FAMILY" == *"suse"* ]]; then
                install_deps_opensuse
            else
                log_warning "Unrecognized distribution: $DISTRO_NAME"
                log_info "Install the following packages manually:"
                echo "  - Python GTK4 bindings (python3-gi, gir1.2-gtk-4.0)"
                echo "  - libadwaita (gir1.2-adw-1)"
                echo "  - NSS tools (libnss3-tools)"
                echo "  - OpenSC (opensc)"
            fi
            ;;
    esac
}

# ============================================================================
# Install uv
# ============================================================================

install_uv() {
    if command_exists uv; then
        log_success "uv already installed: $(uv --version)"
        return 0
    fi

    log_warning "uv is not installed"
    echo
    read -p "Install uv (modern Python package manager)? [Y/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]?$ ]]; then
        log_step "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        # Add to PATH for this session
        export PATH="$HOME/.local/bin:$PATH"

        if command_exists uv; then
            log_success "uv installed successfully"
        else
            log_error "Error installing uv"
            exit 1
        fi
    else
        log_error "uv is required to install PDFSigner"
        exit 1
    fi
}

# ============================================================================
# Configure venv with system site-packages
# ============================================================================

setup_venv() {
    log_step "Configuring virtual environment..."

    # Sync dependencies
    uv sync

    # Add access to system packages (for gi)
    local VENV_SITE_PACKAGES
    VENV_SITE_PACKAGES=$(find .venv/lib -type d -name "site-packages" | head -1)

    if [ -n "$VENV_SITE_PACKAGES" ]; then
        echo "/usr/lib/python3/dist-packages" > "$VENV_SITE_PACKAGES/system-packages.pth"
        log_success "Configured access to system packages (PyGObject)"
    fi
}

# ============================================================================
# Initial configuration
# ============================================================================

setup_config() {
    local CONFIG_DIR="$HOME/.config/pdfsigner"
    local LOG_DIR="$HOME/.local/share/pdfsigner/logs"

    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"

    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        log_step "Creating initial configuration..."
        cp config/pdfsigner.toml.example "$CONFIG_DIR/config.toml"
        log_success "Configuration created in: $CONFIG_DIR/config.toml"
        log_warning "Edit the file to configure TSA and other parameters"
    else
        log_info "Existing configuration preserved: $CONFIG_DIR/config.toml"
    fi
}

# ============================================================================
# Install desktop integration
# ============================================================================

install_desktop() {
    log_step "Installing desktop integration..."

    local DESKTOP_DIR="$HOME/.local/share/applications"
    local ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"

    mkdir -p "$DESKTOP_DIR"
    mkdir -p "$ICON_DIR"

    # Install icon
    if [ -f "data/com.pdfsigner.app.png" ]; then
        cp "data/com.pdfsigner.app.png" "$ICON_DIR/"
        log_success "Icon installed"
    fi

    # Install desktop file (replace INSTALL_PATH with actual path)
    if [ -f "data/pdfsigner.desktop" ]; then
        sed "s|INSTALL_PATH|$PROJECT_DIR|g" "data/pdfsigner.desktop" > "$DESKTOP_DIR/pdfsigner.desktop"
        chmod +x "$DESKTOP_DIR/pdfsigner.desktop"
        log_success "Desktop entry installed"
    fi

    # Make launcher executable
    if [ -f "pdfsigner-launcher.sh" ]; then
        chmod +x "pdfsigner-launcher.sh"
        log_success "Launcher script configured"
    fi

    # Update desktop database
    if command_exists update-desktop-database; then
        update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    fi

    # Update icon cache
    if command_exists gtk-update-icon-cache; then
        gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
    fi

    log_info "You can now find 'PDFSigner' in your application menu"
}

# ============================================================================
# Verify installation
# ============================================================================

verify_installation() {
    echo
    log_step "Verifying installation..."

    local ALL_OK=true

    # Verify gi
    if python_pkg_installed gi; then
        log_success "PyGObject (gi) available"
    else
        log_error "PyGObject (gi) not available"
        ALL_OK=false
    fi

    # Verify GTK4
    if python3 -c "import gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk" 2>/dev/null; then
        log_success "GTK4 available"
    else
        log_error "GTK4 not available"
        ALL_OK=false
    fi

    # Verify libadwaita
    if python3 -c "import gi; gi.require_version('Adw', '1'); from gi.repository import Adw" 2>/dev/null; then
        log_success "libadwaita available"
    else
        log_error "libadwaita not available"
        ALL_OK=false
    fi

    # Verify NSS
    if command_exists certutil; then
        log_success "NSS tools available"
    else
        log_warning "NSS tools not available (certutil)"
    fi

    # Verify CLI
    if uv run pdfsigner --help &>/dev/null; then
        log_success "CLI functional"
    else
        log_warning "CLI not verified"
    fi

    # Verify GUI
    if uv run python -c "from pdfsigner.gui.app import PDFSignerApp" 2>/dev/null; then
        log_success "GUI module available"
    else
        log_warning "GUI module not verified"
    fi

    echo
    if [ "$ALL_OK" = true ]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Verify correct directory
    if [ ! -f "pyproject.toml" ]; then
        log_error "Run from the project root directory"
        exit 1
    fi

    PROJECT_DIR="$(pwd)"

    echo -e "${CYAN}Step 1/5: System dependencies${NC}"
    echo "─────────────────────────────────────────────"
    install_system_deps
    echo

    echo -e "${CYAN}Step 2/5: uv installation${NC}"
    echo "─────────────────────────────────────────────"
    install_uv
    echo

    echo -e "${CYAN}Step 3/5: Python virtual environment${NC}"
    echo "─────────────────────────────────────────────"
    setup_venv
    echo

    echo -e "${CYAN}Step 4/5: Configuration${NC}"
    echo "─────────────────────────────────────────────"
    setup_config
    echo

    echo -e "${CYAN}Step 5/5: Desktop integration${NC}"
    echo "─────────────────────────────────────────────"
    install_desktop
    echo

    # Verify
    verify_installation
    local VERIFY_RESULT=$?

    # Final summary
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    if [ $VERIFY_RESULT -eq 0 ]; then
        echo -e "${GREEN}║           ✓ Installation completed successfully           ║${NC}"
    else
        echo -e "${YELLOW}║        ⚠ Installation completed with warnings            ║${NC}"
    fi
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}Next steps:${NC}"
    echo
    echo -e "  1. ${YELLOW}Configure TSA:${NC}"
    echo -e "     nano ~/.config/pdfsigner/config.toml"
    echo
    echo -e "  2. ${YELLOW}Verify USB token:${NC}"
    echo -e "     certutil -L -d ~/.nss"
    echo
    echo -e "  3. ${YELLOW}Run GUI:${NC}"
    echo -e "     uv run pdfsigner-gui"
    echo
    echo -e "  4. ${YELLOW}Run CLI:${NC}"
    echo -e "     uv run pdfsigner sign file.pdf"
    echo -e "     uv run pdfsigner validate document_signed.pdf"
    echo
    echo -e "${CYAN}To uninstall:${NC} ./scripts/uninstall.sh"
    echo
}

# Run
main "$@"
