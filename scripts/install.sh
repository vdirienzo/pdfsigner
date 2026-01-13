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
echo -e "${GREEN}║              PDFSigner - Instalador v0.1.0                 ║${NC}"
echo -e "${GREEN}║     Firma digital de PDFs con token USB SafeNet 5110      ║${NC}"
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
    log_step "Instalando dependencias para Debian/Ubuntu..."

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
        log_success "Todas las dependencias del sistema ya están instaladas"
        return 0
    fi

    log_warning "Paquetes faltantes: ${MISSING[*]}"
    echo
    read -p "¿Instalar dependencias con apt? [S/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Ss]?$ ]]; then
        sudo apt update
        sudo apt install -y "${MISSING[@]}"
        log_success "Dependencias instaladas"
    else
        log_warning "Omitiendo instalación de dependencias del sistema"
        log_info "Instalar manualmente: sudo apt install ${MISSING[*]}"
    fi
}

install_deps_fedora() {
    log_step "Instalando dependencias para Fedora/RHEL..."

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
        log_success "Todas las dependencias del sistema ya están instaladas"
        return 0
    fi

    log_warning "Paquetes faltantes: ${MISSING[*]}"
    echo
    read -p "¿Instalar dependencias con dnf? [S/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Ss]?$ ]]; then
        sudo dnf install -y "${MISSING[@]}"
        log_success "Dependencias instaladas"
    else
        log_warning "Omitiendo instalación de dependencias del sistema"
        log_info "Instalar manualmente: sudo dnf install ${MISSING[*]}"
    fi
}

install_deps_arch() {
    log_step "Instalando dependencias para Arch Linux..."

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
        log_success "Todas las dependencias del sistema ya están instaladas"
        return 0
    fi

    log_warning "Paquetes faltantes: ${MISSING[*]}"
    echo
    read -p "¿Instalar dependencias con pacman? [S/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Ss]?$ ]]; then
        sudo pacman -S --noconfirm "${MISSING[@]}"
        log_success "Dependencias instaladas"
    else
        log_warning "Omitiendo instalación de dependencias del sistema"
        log_info "Instalar manualmente: sudo pacman -S ${MISSING[*]}"
    fi
}

install_deps_opensuse() {
    log_step "Instalando dependencias para openSUSE..."

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
        log_success "Todas las dependencias del sistema ya están instaladas"
        return 0
    fi

    log_warning "Paquetes faltantes: ${MISSING[*]}"
    echo
    read -p "¿Instalar dependencias con zypper? [S/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Ss]?$ ]]; then
        sudo zypper install -y "${MISSING[@]}"
        log_success "Dependencias instaladas"
    else
        log_warning "Omitiendo instalación de dependencias del sistema"
        log_info "Instalar manualmente: sudo zypper install ${MISSING[*]}"
    fi
}

install_system_deps() {
    detect_distro

    log_info "Distribución detectada: $DISTRO_NAME ($DISTRO_ID)"
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
                log_warning "Distribución no reconocida: $DISTRO_NAME"
                log_info "Instalar manualmente los siguientes paquetes:"
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
        log_success "uv ya está instalado: $(uv --version)"
        return 0
    fi

    log_warning "uv no está instalado"
    echo
    read -p "¿Instalar uv (gestor de paquetes Python moderno)? [S/n] " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Ss]?$ ]]; then
        log_step "Instalando uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        # Agregar al PATH para esta sesión
        export PATH="$HOME/.local/bin:$PATH"

        if command_exists uv; then
            log_success "uv instalado correctamente"
        else
            log_error "Error instalando uv"
            exit 1
        fi
    else
        log_error "uv es requerido para instalar PDFSigner"
        exit 1
    fi
}

# ============================================================================
# Configuración del venv con system site-packages
# ============================================================================

setup_venv() {
    log_step "Configurando entorno virtual..."

    # Sincronizar dependencias
    uv sync

    # Agregar acceso a paquetes del sistema (para gi)
    local VENV_SITE_PACKAGES
    VENV_SITE_PACKAGES=$(find .venv/lib -type d -name "site-packages" | head -1)

    if [ -n "$VENV_SITE_PACKAGES" ]; then
        echo "/usr/lib/python3/dist-packages" > "$VENV_SITE_PACKAGES/system-packages.pth"
        log_success "Configurado acceso a paquetes del sistema (PyGObject)"
    fi
}

# ============================================================================
# Instalación de la extensión de Nautilus
# ============================================================================

install_nautilus_extension() {
    log_step "Instalando extensión de Nautilus..."

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

    log_success "Extensión de Nautilus instalada en: $EXTENSION_DIR"
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
        log_step "Creando configuración inicial..."
        cp config/pdfsigner.toml.example "$CONFIG_DIR/config.toml"
        log_success "Configuración creada en: $CONFIG_DIR/config.toml"
        log_warning "Editar el archivo para configurar TSA y otros parámetros"
    else
        log_info "Configuración existente preservada: $CONFIG_DIR/config.toml"
    fi
}

# ============================================================================
# Reinicio de Nautilus
# ============================================================================

restart_nautilus() {
    log_step "Reiniciando Nautilus..."
    nautilus -q 2>/dev/null || true
    sleep 1
    log_success "Nautilus reiniciado"
}

# ============================================================================
# Verificación de instalación
# ============================================================================

verify_installation() {
    echo
    log_step "Verificando instalación..."

    local ALL_OK=true

    # Verificar gi
    if python_pkg_installed gi; then
        log_success "PyGObject (gi) disponible"
    else
        log_error "PyGObject (gi) no disponible"
        ALL_OK=false
    fi

    # Verificar GTK4
    if python3 -c "import gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk" 2>/dev/null; then
        log_success "GTK4 disponible"
    else
        log_error "GTK4 no disponible"
        ALL_OK=false
    fi

    # Verificar libadwaita
    if python3 -c "import gi; gi.require_version('Adw', '1'); from gi.repository import Adw" 2>/dev/null; then
        log_success "libadwaita disponible"
    else
        log_error "libadwaita no disponible"
        ALL_OK=false
    fi

    # Verificar NSS
    if command_exists certutil; then
        log_success "NSS tools disponibles"
    else
        log_warning "NSS tools no disponibles (certutil)"
    fi

    # Verificar extensión
    if [ -f "$HOME/.local/share/nautilus-python/extensions/pdfsigner.py" ]; then
        log_success "Extensión de Nautilus instalada"
    else
        log_error "Extensión de Nautilus no instalada"
        ALL_OK=false
    fi

    # Verificar CLI
    if uv run pdfsigner --help &>/dev/null; then
        log_success "CLI funcional"
    else
        log_warning "CLI no verificado"
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
    # Verificar directorio correcto
    if [ ! -f "pyproject.toml" ]; then
        log_error "Ejecutar desde el directorio raíz del proyecto"
        exit 1
    fi

    PROJECT_DIR="$(pwd)"

    echo -e "${CYAN}Paso 1/5: Dependencias del sistema${NC}"
    echo "─────────────────────────────────────────────"
    install_system_deps
    echo

    echo -e "${CYAN}Paso 2/5: Instalación de uv${NC}"
    echo "─────────────────────────────────────────────"
    install_uv
    echo

    echo -e "${CYAN}Paso 3/5: Entorno virtual Python${NC}"
    echo "─────────────────────────────────────────────"
    setup_venv
    echo

    echo -e "${CYAN}Paso 4/5: Extensión de Nautilus${NC}"
    echo "─────────────────────────────────────────────"
    install_nautilus_extension
    echo

    echo -e "${CYAN}Paso 5/5: Configuración${NC}"
    echo "─────────────────────────────────────────────"
    setup_config
    restart_nautilus
    echo

    # Verificar
    verify_installation
    local VERIFY_RESULT=$?

    # Resumen final
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    if [ $VERIFY_RESULT -eq 0 ]; then
        echo -e "${GREEN}║           ✓ Instalación completada con éxito              ║${NC}"
    else
        echo -e "${YELLOW}║        ⚠ Instalación completada con advertencias         ║${NC}"
    fi
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}Próximos pasos:${NC}"
    echo
    echo -e "  1. ${YELLOW}Configurar TSA:${NC}"
    echo -e "     nano ~/.config/pdfsigner/config.toml"
    echo
    echo -e "  2. ${YELLOW}Verificar token USB:${NC}"
    echo -e "     certutil -L -d ~/.nss"
    echo
    echo -e "  3. ${YELLOW}Probar GUI standalone:${NC}"
    echo -e "     uv run pdfsigner-gui"
    echo
    echo -e "  4. ${YELLOW}Probar desde Nautilus:${NC}"
    echo -e "     Abrir Nautilus → Click derecho en PDF → 'Firmar digitalmente'"
    echo
    echo -e "  5. ${YELLOW}Probar CLI:${NC}"
    echo -e "     uv run pdfsigner sign archivo.pdf"
    echo -e "     uv run pdfsigner validate archivo_firmado.pdf"
    echo
    echo -e "${CYAN}Para desinstalar:${NC} ./scripts/uninstall.sh"
    echo
}

# Ejecutar
main "$@"
