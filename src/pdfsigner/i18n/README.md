# Internationalization (i18n)

Sistema de internacionalización de PDFSigner usando gettext.

## Idiomas Soportados

| Código | Idioma | Estado |
|--------|--------|--------|
| `en` | English | ✓ Completo (idioma base) |
| `es` | Español | ✓ Completo |
| `pt` | Português | ⚠️ Parcial |
| `fr` | Français | ⚠️ Parcial |
| `de` | Deutsch | ⚠️ Parcial |

## Estructura de Archivos

```
i18n/
├── __init__.py                 # Módulo principal con función _()
├── extract_strings.py          # Script de extracción/compilación
├── test_i18n.py               # Script de prueba
└── locales/
    ├── es/LC_MESSAGES/
    │   ├── pdfsigner.po       # Traducciones español (texto)
    │   └── pdfsigner.mo       # Traducciones español (compilado)
    ├── pt/LC_MESSAGES/
    ├── fr/LC_MESSAGES/
    └── de/LC_MESSAGES/
```

## Uso en Código

### Traducir cadenas simples

```python
from pdfsigner.i18n import _

# En cualquier módulo
title = _("Sign PDF")
message = _("Signing complete")
```

### Traducir cadenas con plurales

```python
from pdfsigner.i18n import ngettext

count = 5
message = ngettext("1 file", "{n} files", count).format(n=count)
```

### Cambiar idioma manualmente

```python
from pdfsigner.i18n import set_language

set_language("es")  # Cambiar a español
```

### Obtener idioma actual

```python
from pdfsigner.i18n import get_current_language

lang = get_current_language()  # "es", "en", etc.
```

## Flujo de Trabajo para Traducciones

### 1. Extraer cadenas del código

```bash
# Extraer todas las cadenas marcadas con _() y actualizar .po
python src/pdfsigner/i18n/extract_strings.py
```

Esto:
- Busca todas las cadenas en `_()` y `ngettext()`
- Crea `pdfsigner.pot` (plantilla)
- Actualiza todos los archivos `.po` con nuevas cadenas

### 2. Traducir

Editar los archivos `.po` en `locales/<idioma>/LC_MESSAGES/pdfsigner.po`:

```po
# Antes de traducir
msgid "Sign PDF"
msgstr ""

# Después de traducir
msgid "Sign PDF"
msgstr "Firmar PDF"
```

### 3. Compilar a formato binario

```bash
# Compilar todos los idiomas
python src/pdfsigner/i18n/extract_strings.py --compile

# Compilar solo español
python src/pdfsigner/i18n/extract_strings.py --compile --lang es
```

Esto genera los archivos `.mo` que usa la aplicación.

### 4. Probar traducciones

```bash
# Probar idioma del sistema
python src/pdfsigner/i18n/test_i18n.py

# Probar español específicamente
LANGUAGE=es python src/pdfsigner/i18n/test_i18n.py

# Probar todos los idiomas
python src/pdfsigner/i18n/test_i18n.py --all

# Probar en la aplicación completa
LANGUAGE=es uv run pdfsigner-gui
```

## Opciones del Script extract_strings.py

```bash
# Extraer y actualizar todos los idiomas
python extract_strings.py

# Solo compilar (no extraer)
python extract_strings.py --compile

# Solo actualizar español
python extract_strings.py --lang es

# Compilar solo español
python extract_strings.py --compile --lang es

# Solo actualizar .po (sin extraer nuevamente)
python extract_strings.py --skip-extract
```

## Agregar un Nuevo Idioma

1. **Agregar a la lista de idiomas soportados** en `__init__.py`:

```python
SUPPORTED_LANGUAGES = {
    "en": "English",
    "es": "Español",
    "it": "Italiano",  # ← Nuevo idioma
}
```

2. **Crear el directorio y archivos**:

```bash
mkdir -p locales/it/LC_MESSAGES
python extract_strings.py --lang it
```

3. **Traducir** el archivo `locales/it/LC_MESSAGES/pdfsigner.po`

4. **Compilar**:

```bash
python extract_strings.py --compile --lang it
```

5. **Probar**:

```bash
LANGUAGE=it python test_i18n.py
```

## Detección Automática de Idioma

PDFSigner detecta automáticamente el idioma del sistema usando:

1. Variable de entorno `LANGUAGE`
2. Variable de entorno `PDFSIGNER_LANGUAGE`
3. Configuración de locale del sistema
4. Fallback a inglés si no hay traducción

Para forzar un idioma:

```bash
# Opción 1: Variable de entorno
LANGUAGE=es pdfsigner-gui

# Opción 2: Variable específica de PDFSigner
PDFSIGNER_LANGUAGE=es pdfsigner-gui
```

## Herramientas Necesarias

El sistema requiere las herramientas gettext:

```bash
# Ubuntu/Debian
sudo apt install gettext

# Fedora/RHEL
sudo dnf install gettext

# macOS
brew install gettext

# Verificar instalación
which xgettext msgfmt msgmerge
```

## Buenas Prácticas

### 1. Marcar cadenas traducibles

```python
# ✓ Correcto
title = _("Sign PDF")
message = _("File signed successfully")

# ✗ Incorrecto (concatenación)
message = _("File") + " " + filename + " " + _("signed")

# ✓ Correcto (formato)
message = _("File {filename} signed").format(filename=filename)
```

### 2. Contexto en cadenas

```python
# ✓ Incluir contexto cuando sea ambiguo
button = _("Close")           # ¿Cerrar ventana o cerrar archivo?
button = _("Close window")    # Mejor: más contexto
```

### 3. No traducir nombres propios

```python
# ✓ Correcto
row.set_title("AFIP")  # Nombre propio, no traducir

# ✓ Correcto
row.set_subtitle(_("For taxpayers with CUIT"))  # Descripción, sí traducir
```

### 4. Plurales

```python
# ✗ Incorrecto
message = _("files") if count != 1 else _("file")

# ✓ Correcto
message = ngettext("file", "files", count)
```

## Solución de Problemas

### Traducciones no aparecen

1. **Verificar que el archivo .mo existe**:
   ```bash
   ls -la locales/es/LC_MESSAGES/pdfsigner.mo
   ```

2. **Recompilar**:
   ```bash
   python extract_strings.py --compile
   ```

3. **Verificar variable de entorno**:
   ```bash
   echo $LANGUAGE
   LANGUAGE=es python test_i18n.py
   ```

### Cadena no se traduce

1. **Verificar que está en el .po**:
   ```bash
   grep "cadena" locales/es/LC_MESSAGES/pdfsigner.po
   ```

2. **Si no está, extraer nuevamente**:
   ```bash
   python extract_strings.py
   ```

3. **Agregar traducción y recompilar**:
   ```bash
   # Editar locales/es/LC_MESSAGES/pdfsigner.po
   python extract_strings.py --compile
   ```

### Error "xgettext not found"

Instalar herramientas gettext (ver sección "Herramientas Necesarias").

## Referencias

- **gettext**: https://www.gnu.org/software/gettext/
- **Python gettext**: https://docs.python.org/3/library/gettext.html
- **Formato .po**: https://www.gnu.org/software/gettext/manual/html_node/PO-Files.html
