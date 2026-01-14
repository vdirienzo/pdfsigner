#!/bin/bash
# install.sh - Instalador de PDFSigner para Nautilus
#
# Autor: Homero Thompson del Lago del Terror
#
# Instala la extensión de Nautilus y crea la configuración inicial.
# Detecta la distribución y ofrece instalar dependencias del sistema.

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              PDFSigner - Installer v0.2.0                  ║${NC}"
echo -e "${GREEN}║     Digital PDF signing with SafeNet 5110 USB token       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo

# ============================================================================
# Funciones de utilidad
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

# Detectar distribución
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

# Verificar si un comando existe
command_exists() {
    command -v "$1" &> /dev/null
}

# Verificar si un paquete Python está instalado en el sistema
python_pkg_installed() {
    python3 -c "import $1" 2>/dev/null
}

# ============================================================================
# Instalación de dependencias por distribución
# ============================================================================

install_deps_debian() {
    log_step "Installing dependencies for Debian/Ubuntu..."

    local PACKAGES=(
        "python3-gi"
        "python3-gi-cairo"
        "gir1.2-gtk-4.0"
        "gir1.2-adw-1"
        "python3-nautilus"
        "libnss3-tools"
        "opensc"
    )

    # Verificar cuáles faltan
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
        "nautilus-python"
        "nss-tools"
        "opensc"
    )

    # Verificar cuáles faltan
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
        "python-nautilus"
        "nss"
        "opensc"
    )

    # Verificar cuáles faltan
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
        "nautilus-extension-python"
        "mozilla-nss-tools"
        "opensc"
    )

    # Verificar cuáles faltan
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
            # Intentar por familia
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
                echo "  - Nautilus Python extension (python3-nautilus)"
                echo "  - NSS tools (libnss3-tools)"
                echo "  - OpenSC (opensc)"
            fi
            ;;
    esac
}

# ============================================================================
# Instalación de uv
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
# Configuración del venv con system site-packages
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
# Instalación de la extensión de Nautilus
# ============================================================================

install_nautilus_extension() {
    log_step "Installing Nautilus extension..."

    local EXTENSION_DIR="$HOME/.local/share/nautilus-python/extensions"
    mkdir -p "$EXTENSION_DIR"

    # Crear wrapper de extensión
    cat > "$EXTENSION_DIR/pdfsigner.py" << EXTENSION_EOF
"""
PDFSigner - Extensión de Nautilus para firma digital de PDFs

Autor: Homero Thompson del Lago del Terror

Wrapper que carga el módulo principal desde el proyecto instalado.
"""

import sys
from pathlib import Path

# Agregar el proyecto al path
PROJECT_PATH = Path("$PROJECT_DIR")
VENV_PATH = PROJECT_PATH / ".venv" / "lib"

# Encontrar versión de Python en venv
for pyver in VENV_PATH.glob("python3.*"):
    site_packages = pyver / "site-packages"
    if site_packages.exists():
        sys.path.insert(0, str(site_packages))
        break

sys.path.insert(0, str(PROJECT_PATH / "src"))

# Importar la extensión real
try:
    from pdfsigner.nautilus_extension.sign_extension import PDFSignerExtension
except ImportError as e:
    import gi
    gi.require_version("GObject", "2.0")
    from gi.repository import GObject

    class PDFSignerExtension(GObject.GObject):
        """Placeholder cuando el módulo no está disponible."""
        def __init__(self):
            print(f"PDFSigner: Error de importación - {e}")
EXTENSION_EOF

    log_success "Nautilus extension installed in: $EXTENSION_DIR"
}

# ============================================================================
# Configuración inicial
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
# Reinicio de Nautilus
# ============================================================================

restart_nautilus() {
    log_step "Restarting Nautilus..."
    nautilus -q 2>/dev/null || true
    sleep 1
    log_success "Nautilus restarted"
}

# ============================================================================
# Verificación de instalación
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

    # Verify extension
    if [ -f "$HOME/.local/share/nautilus-python/extensions/pdfsigner.py" ]; then
        log_success "Nautilus extension installed"
    else
        log_error "Nautilus extension not installed"
        ALL_OK=false
    fi

    # Verify CLI
    if uv run pdfsigner --help &>/dev/null; then
        log_success "CLI functional"
    else
        log_warning "CLI not verified"
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

    echo -e "${CYAN}Step 4/5: Nautilus extension${NC}"
    echo "─────────────────────────────────────────────"
    install_nautilus_extension
    echo

    echo -e "${CYAN}Step 5/5: Configuration${NC}"
    echo "─────────────────────────────────────────────"
    setup_config
    restart_nautilus
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
    echo -e "  3. ${YELLOW}Test standalone GUI:${NC}"
    echo -e "     uv run pdfsigner-gui"
    echo
    echo -e "  4. ${YELLOW}Test from Nautilus:${NC}"
    echo -e "     Open Nautilus → Right-click on PDF → 'Sign digitally'"
    echo
    echo -e "  5. ${YELLOW}Test CLI:${NC}"
    echo -e "     uv run pdfsigner sign file.pdf"
    echo -e "     uv run pdfsigner validate document_signed.pdf"
    echo
    echo -e "${CYAN}To uninstall:${NC} ./scripts/uninstall.sh"
    echo
}

# Ejecutar
main "$@"
