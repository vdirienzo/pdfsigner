# PDFSigner

**Firma digital de PDFs con token USB SafeNet 5110**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GTK4](https://img.shields.io/badge/GTK-4.0-green.svg)](https://gtk.org/)

PDFSigner es una herramienta para firmar digitalmente documentos PDF usando tokens USB criptográficos (SafeNet 5110) con firma PAdES-LTV de validez legal.

## ✨ Características

- **Firma PAdES-LTV** - Long Term Validation con timestamp TSA
- **Token SafeNet 5110** - Soporte completo vía NSS/PKCS#11
- **Integración Nautilus** - Click derecho → "Firmar digitalmente"
- **GUI Standalone** - Aplicación GTK4 independiente con drag & drop
- **CLI Completo** - Para scripts y automatización
- **Modo Dry-Run** - Simular firma sin token para testing
- **Firma visible/invisible** - Con posicionamiento inteligente
- **Firma en lote** - Múltiples PDFs con un solo PIN
- **Validación** - Verificar firmas existentes
- **Multi-firma** - Agregar firmas adicionales a PDFs ya firmados

---

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#-requisitos-previos)
2. [Instalación de Drivers SafeNet](#-instalación-de-drivers-safenet-5110)
3. [Creación de Base de Datos NSS](#-creación-de-base-de-datos-nss)
4. [Instalación de PDFSigner](#-instalación-de-pdfsigner)
5. [Configuración](#️-configuración)
6. [Uso](#️-uso)
7. [Modo Dry-Run (Testing)](#-modo-dry-run-testing)
8. [Solución de Problemas](#-solución-de-problemas)
9. [Desarrollo](#-desarrollo)

---

## 🔧 Requisitos Previos

Antes de instalar PDFSigner, necesitas:

| Requisito | Descripción |
|-----------|-------------|
| **Token USB** | SafeNet 5110 (eToken) o compatible PKCS#11 |
| **Certificado** | Certificado de firma digital instalado en el token |
| **Linux** | Debian 12+, Ubuntu 22.04+, Fedora 38+, Arch, openSUSE |
| **Drivers** | SafeNet Authentication Client |
| **NSS Database** | Base de datos NSS con el módulo PKCS#11 registrado |

### Verificar tu entorno

```bash
# ¿Tienes el token conectado?
lsusb | grep -i "safenet\|gemalto\|thales"

# Salida esperada (ejemplo):
# Bus 001 Device 003: ID 0529:0620 Aladdin Knowledge Systems Token JC
```

---

## 🔑 Instalación de Drivers SafeNet 5110

### Paso 1: Descargar el driver

Los drivers de SafeNet (ahora Thales) se obtienen de:

1. **Opción A - Proveedor oficial:** Contactar a tu proveedor de certificados
2. **Opción B - Portal Thales:** https://supportportal.thalesgroup.com (requiere cuenta)
3. **Opción C - Tu organización:** El departamento de IT usualmente proporciona el instalador

El archivo típicamente se llama: `SafenetAuthenticationClient-*.deb` o `SAC*.rpm`

### Paso 2: Instalar el driver

#### Debian / Ubuntu

```bash
# Si tienes el .deb
sudo dpkg -i SafenetAuthenticationClient-*.deb
sudo apt-get install -f  # Resolver dependencias

# Verificar instalación
ls -la /usr/lib/libeToken.so
# Debería existir el archivo
```

#### Fedora / RHEL

```bash
# Si tienes el .rpm
sudo rpm -ivh SafenetAuthenticationClient-*.rpm

# O con dnf
sudo dnf install ./SafenetAuthenticationClient-*.rpm

# Verificar
ls -la /usr/lib64/libeToken.so
```

#### Arch Linux (AUR)

```bash
# Usando yay
yay -S safenet-authentication-client

# O manualmente desde AUR
git clone https://aur.archlinux.org/safenet-authentication-client.git
cd safenet-authentication-client
makepkg -si
```

### Paso 3: Configurar permisos USB

```bash
# Crear regla udev para el token
sudo tee /etc/udev/rules.d/90-safenet.rules << 'EOF'
# SafeNet eToken 5110
SUBSYSTEM=="usb", ATTR{idVendor}=="0529", MODE="0666"
# Gemalto/Thales (algunos modelos)
SUBSYSTEM=="usb", ATTR{idVendor}=="08e6", MODE="0666"
EOF

# Recargar reglas
sudo udevadm control --reload-rules
sudo udevadm trigger

# Desconectar y reconectar el token
```

### Paso 4: Verificar driver instalado

```bash
# Verificar que el módulo existe
ls -la /usr/lib/libeToken.so /usr/lib64/libeToken.so 2>/dev/null

# Verificar con pkcs11-tool (de opensc)
pkcs11-tool --module /usr/lib/libeToken.so -L

# Salida esperada:
# Available slots:
# Slot 0 (0x0): SafeNet eToken 5110 [Main Interface] 00 00
#   token label        : Tu Nombre
#   token manufacturer : SafeNet, Inc.
#   ...
```

---

## 🗄️ Creación de Base de Datos NSS

NSS (Network Security Services) es la base de datos que Mozilla usa para certificados. PDFSigner usa NSS para comunicarse con el token.

### Paso 1: Instalar herramientas NSS

```bash
# Debian/Ubuntu
sudo apt install libnss3-tools

# Fedora/RHEL
sudo dnf install nss-tools

# Arch
sudo pacman -S nss

# openSUSE
sudo zypper install mozilla-nss-tools
```

### Paso 2: Crear directorio NSS

```bash
# Crear directorio para la base de datos
mkdir -p ~/.nss

# Verificar que está vacío
ls -la ~/.nss
```

### Paso 3: Inicializar base de datos NSS

```bash
# Crear base de datos NSS (formato SQL, recomendado)
certutil -N -d sql:$HOME/.nss

# Te pedirá una contraseña para la base de datos
# IMPORTANTE: Esta NO es la contraseña del token, es para proteger la DB local
# Puedes dejarla vacía para desarrollo (Enter dos veces)

# Verificar que se creó correctamente
ls -la ~/.nss
# Deberías ver: cert9.db, key4.db, pkcs11.txt
```

### Paso 4: Registrar módulo SafeNet en NSS

```bash
# Agregar el módulo PKCS#11 del SafeNet
# IMPORTANTE: Usar el path correcto según tu sistema

# Para sistemas de 64 bits con lib en /usr/lib:
modutil -add "SafeNet" -libfile /usr/lib/libeToken.so -dbdir sql:$HOME/.nss

# Para sistemas con lib en /usr/lib64:
modutil -add "SafeNet" -libfile /usr/lib64/libeToken.so -dbdir sql:$HOME/.nss

# Verificar que se agregó
modutil -list -dbdir sql:$HOME/.nss

# Salida esperada:
# Listing of PKCS #11 Modules
# -----------------------------------------------------------
#   1. NSS Internal PKCS #11 Module
#   ...
#   2. SafeNet
#        library name: /usr/lib/libeToken.so
#        ...
```

### Paso 5: Verificar acceso al token

```bash
# Listar slots disponibles (con token conectado)
modutil -list -dbdir sql:$HOME/.nss

# Listar certificados en el token
# NOTA: Te pedirá el PIN del token
certutil -L -d sql:$HOME/.nss -h "SafeNet eToken 5110"

# Salida esperada:
# Certificate Nickname                              Trust Attributes
#                                                   SSL,S/MIME,JAR/XPI
# SafeNet eToken 5110:Tu Nombre                     u,u,u
```

### Paso 6: Verificar certificado de firma

```bash
# Ver detalles del certificado
certutil -L -d sql:$HOME/.nss -n "SafeNet eToken 5110:Tu Nombre"

# Verificar que tiene capacidad de firma (Key Usage)
# Buscar: "Digital Signature" o "Non-Repudiation" en la salida
```

### Troubleshooting NSS

```bash
# Error: "SEC_ERROR_BAD_DATABASE"
# Solución: Reiniciar la base de datos
rm -rf ~/.nss/*
certutil -N -d sql:$HOME/.nss

# Error: "SEC_ERROR_PKCS11_DEVICE_ERROR"
# Solución: El token no está conectado o el driver no funciona
pkcs11-tool --module /usr/lib/libeToken.so -L

# Error: "SEC_ERROR_TOKEN_NOT_LOGGED_IN"
# Solución: Necesitas proporcionar el PIN del token

# Error: Módulo no encontrado
# Solución: Verificar el path del módulo
find /usr -name "libeToken.so" 2>/dev/null
```

---

## 📦 Instalación de PDFSigner

### Instalación Rápida (Recomendada)

```bash
# Clonar repositorio
git clone https://github.com/vdiriern/pdfsigner.git
cd pdfsigner

# Ejecutar instalador automático
./scripts/install.sh
```

### Instalación Manual

#### Debian / Ubuntu / Linux Mint

```bash
# 1. Dependencias del sistema
sudo apt update
sudo apt install -y \
    python3-gi \
    python3-gi-cairo \
    gir1.2-gtk-4.0 \
    gir1.2-adw-1 \
    python3-nautilus \
    libnss3-tools \
    opensc

# 2. Instalar uv (gestor de paquetes Python)
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc

# 3. Clonar e instalar
git clone https://github.com/vdiriern/pdfsigner.git
cd pdfsigner
uv sync

# 4. Configurar acceso a PyGObject del sistema
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth

# 5. Copiar configuración
mkdir -p ~/.config/pdfsigner
cp config/pdfsigner.toml.example ~/.config/pdfsigner/config.toml

# 6. Editar configuración con tu path NSS
nano ~/.config/pdfsigner/config.toml
# Cambiar: nss_db_path = "/home/TU_USUARIO/.nss"
```

#### Fedora / RHEL 9+

```bash
# 1. Dependencias
sudo dnf install -y \
    python3-gobject \
    gtk4 \
    libadwaita \
    nautilus-python \
    nss-tools \
    opensc

# 2-6. Igual que Debian, pero el path de sistema es diferente:
echo "/usr/lib64/python3.*/site-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
```

#### Arch Linux

```bash
# 1. Dependencias
sudo pacman -S --noconfirm \
    python-gobject \
    gtk4 \
    libadwaita \
    python-nautilus \
    nss \
    opensc

# 2-6. Igual que Debian
echo "/usr/lib/python3.*/site-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
```

### Verificar instalación

```bash
# Verificar que PDFSigner funciona
uv run pdfsigner --help

# Salida esperada:
# usage: pdfsigner [-h] [-v] [--dry-run] {sign,validate,list-certs} ...
# PDFSigner - Firma digital de PDFs con token USB
```

---

## ⚙️ Configuración

### Archivo de configuración

Ubicación: `~/.config/pdfsigner/config.toml`

```toml
# PDFSigner - Configuración
# Autor: Homero Thompson del Lago del Terror

# ============================================================================
# NSS Database (Token USB)
# ============================================================================
# IMPORTANTE: Cambiar a tu directorio de usuario
nss_db_path = "/home/TU_USUARIO/.nss"

# ============================================================================
# TSA (Timestamp Authority) - REQUERIDO para firmas con validez legal
# ============================================================================
# Opción 1: TSA Gratuito (para pruebas)
tsa_url = "https://freetsa.org/tsr"

# Opción 2: TSA Corporativo
# tsa_url = "https://tsa.tuempresa.com/timestamp"
# tsa_username = "usuario"
# tsa_password = "password"

# ============================================================================
# Firma Visible
# ============================================================================
default_visible = false          # true = mostrar sello de firma
signature_width_mm = 50          # Ancho del sello
signature_height_mm = 20         # Alto del sello
default_page = "last"            # "last", "first", o número de página

# ============================================================================
# Archivos de Salida
# ============================================================================
output_suffix = "_firmado"       # documento.pdf → documento_firmado.pdf

# ============================================================================
# Cache de PIN
# ============================================================================
pin_cache_enabled = true
pin_cache_timeout_seconds = 300  # 5 minutos

# ============================================================================
# Modo Dry-Run (para testing sin token)
# ============================================================================
dry_run = false                  # true = simular firma sin token real

# ============================================================================
# Logging
# ============================================================================
log_level = "INFO"               # DEBUG, INFO, WARNING, ERROR
```

### TSAs Públicos Gratuitos

| Proveedor | URL | Uso |
|-----------|-----|-----|
| FreeTSA | `https://freetsa.org/tsr` | Pruebas, uso personal |
| DigiCert | `http://timestamp.digicert.com` | Producción |
| Sectigo | `http://timestamp.sectigo.com` | Producción |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | Producción |

---

## 🖥️ Uso

### GUI (Aplicación Gráfica)

```bash
# Iniciar la aplicación
uv run pdfsigner-gui

# Con modo dry-run (sin token)
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui
```

**Funcionalidades:**
- 📂 Arrastrar y soltar PDFs
- ⚙️ Configuración desde la interfaz
- 📝 Ver estado de cada archivo
- ✅ Firmar en lote
- 🔍 Validar firmas

**Atajos:**
- `Ctrl+O` - Abrir archivos
- `Ctrl+,` - Configuración
- `Ctrl+Q` - Salir

### CLI (Línea de Comandos)

```bash
# ═══════════════════════════════════════════════════════════
# FIRMAR DOCUMENTOS
# ═══════════════════════════════════════════════════════════

# Firmar un archivo (te pedirá el PIN)
uv run pdfsigner sign documento.pdf

# Firmar con firma visible en última página
uv run pdfsigner sign documento.pdf --visible --page last

# Firmar en primera página
uv run pdfsigner sign documento.pdf --visible --page first

# Firmar en página específica (ej: página 3)
uv run pdfsigner sign documento.pdf --visible --page 3

# Firmar múltiples archivos
uv run pdfsigner sign archivo1.pdf archivo2.pdf archivo3.pdf

# Firmar todos los PDFs en un directorio
uv run pdfsigner sign ./documentos/

# Firmar recursivamente
uv run pdfsigner sign ./documentos/ -r

# ═══════════════════════════════════════════════════════════
# VALIDAR FIRMAS
# ═══════════════════════════════════════════════════════════

# Validar un documento firmado
uv run pdfsigner validate documento_firmado.pdf

# Validar con detalles
uv run pdfsigner -v validate documento_firmado.pdf

# Validar múltiples documentos
uv run pdfsigner validate *.pdf

# ═══════════════════════════════════════════════════════════
# CERTIFICADOS
# ═══════════════════════════════════════════════════════════

# Listar certificados disponibles en el token
uv run pdfsigner list-certs

# ═══════════════════════════════════════════════════════════
# MODO DRY-RUN (TESTING)
# ═══════════════════════════════════════════════════════════

# Simular firma sin token real
uv run pdfsigner --dry-run sign documento.pdf
```

### Integración Nautilus

```bash
# Instalar extensión
./scripts/install.sh

# Reiniciar Nautilus
nautilus -q

# Uso: Click derecho en PDF → "Firmar digitalmente"
```

---

## 🧪 Modo Dry-Run (Testing)

El modo dry-run permite probar PDFSigner sin tener el token USB conectado.

### ¿Qué hace el modo dry-run?

- ✅ Simula conexión con token
- ✅ Acepta cualquier PIN de 4+ dígitos
- ✅ Usa certificados ficticios
- ✅ Copia archivos con sufijo `_firmado`
- ⚠️ **NO** firma realmente los documentos

### Activar dry-run

```bash
# Método 1: Flag en CLI
uv run pdfsigner --dry-run sign documento.pdf

# Método 2: Variable de entorno
PDFSIGNER_DRY_RUN=true uv run pdfsigner sign documento.pdf

# Método 3: En config.toml
# dry_run = true

# Método 4: GUI
PDFSIGNER_DRY_RUN=true uv run pdfsigner-gui
```

### Ejemplo de salida dry-run

```
============================================================
⚠️  MODO DRY-RUN - SIMULACIÓN SIN TOKEN REAL
============================================================
Los archivos serán copiados con sufijo _firmado
pero NO contendrán firma digital real.

[DRY-RUN] Simulando conexión con token...
[DRY-RUN] Token simulado: SafeNet 5110 (SIMULADO)
[DRY-RUN] Ingrese cualquier PIN de 4+ dígitos para simular:
Ingrese PIN del token: ****
[DRY-RUN] Autenticación simulada exitosa
[DRY-RUN] Usando certificado simulado: Juan Pérez (PRUEBA)

[DRY-RUN] [100.0%] documento.pdf                     [success]

------------------------------------------------------------
✓ [DRY-RUN] 1 archivo(s) copiados con sufijo _firmado

⚠️  Nota: Los archivos NO están realmente firmados.
   Se crearon copias para simular el proceso.
```

---

## 🐛 Solución de Problemas

### "No module named 'gi'"

```bash
# El venv necesita acceso a PyGObject del sistema
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
```

### "No se detectó token USB"

```bash
# 1. Verificar conexión física
lsusb | grep -i safenet

# 2. Verificar driver
ls -la /usr/lib/libeToken.so

# 3. Verificar módulo en NSS
modutil -list -dbdir sql:$HOME/.nss

# 4. Probar con pkcs11-tool
pkcs11-tool --module /usr/lib/libeToken.so -L
```

### "SEC_ERROR_PKCS11_DEVICE_ERROR"

El driver no puede comunicarse con el token:

```bash
# Verificar permisos USB
ls -la /dev/bus/usb/*/*

# Recargar reglas udev
sudo udevadm control --reload-rules
sudo udevadm trigger

# Desconectar y reconectar token
```

### "Certificado no encontrado"

```bash
# Listar certificados disponibles
certutil -L -d sql:$HOME/.nss -h all

# Si no aparecen, verificar que el módulo está cargado
modutil -list -dbdir sql:$HOME/.nss
```

### "Error de TSA / Timeout"

```bash
# Verificar conectividad
curl -v https://freetsa.org/tsr

# Probar otro TSA en config.toml
# tsa_url = "http://timestamp.digicert.com"
```

### La GUI no inicia

```bash
# Verificar GTK4
python3 -c "import gi; gi.require_version('Gtk', '4.0'); print('OK')"

# Verificar libadwaita
python3 -c "import gi; gi.require_version('Adw', '1'); print('OK')"
```

---

## 🔧 Desarrollo

### Setup

```bash
git clone https://github.com/vdiriern/pdfsigner.git
cd pdfsigner
uv sync --all-extras
echo "/usr/lib/python3/dist-packages" > .venv/lib/python3.*/site-packages/system-packages.pth
```

### Comandos

```bash
# Tests
uv run pytest -v

# Linter
uv run ruff check --fix .
uv run ruff format .

# Type checking
uv run mypy src/pdfsigner

# Seguridad
uv run bandit -r src/
```

### Estructura

```
pdfsigner/
├── src/pdfsigner/
│   ├── cli/                 # Comandos CLI
│   ├── config/              # Configuración
│   ├── core/
│   │   ├── mock/            # Modo dry-run
│   │   ├── pdf_analyzer/    # Análisis de PDFs
│   │   ├── signer/          # Firma PAdES
│   │   ├── token/           # NSS/PKCS#11
│   │   └── validator/       # Validación
│   ├── gui/                 # Aplicación GTK4
│   ├── nautilus_extension/  # Plugin Nautilus
│   └── ui/                  # Diálogos y widgets
├── tests/
├── scripts/
└── config/
```

---

## 📜 Licencia

MIT License - Ver [LICENSE](LICENSE)

---

## 👤 Autor

**Homero Thompson del Lago del Terror**

---

## 📝 Changelog

### [0.1.0] - 2025-01-13

#### Added
- Firma PAdES-LTV con timestamp TSA
- Soporte SafeNet 5110 vía NSS/PKCS#11
- GUI standalone GTK4/libadwaita
- CLI con subcomandos (sign, validate, list-certs)
- **Modo dry-run** para testing sin token
- Firma visible con posicionamiento inteligente
- Firma en lote con cache de PIN
- Validación de firmas
- Integración Nautilus
- Instalador multi-distribución
