"""
help_dialog.py - Help dialog for PDFSigner

Author: Homero Thompson del Lago del Terror

Provides user-friendly help information about how to use PDFSigner.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk


class HelpDialog(Adw.Window):
    """
    Help dialog with user documentation.

    Provides clear instructions for users who are not
    familiar with digital signatures or the application.
    """

    def __init__(self, **kwargs):
        """Initializes the help dialog."""
        super().__init__(**kwargs)

        self.set_title("Help - PDFSigner")
        self.set_default_size(600, 700)
        self.set_modal(True)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Configures the user interface."""
        # Header bar
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        # Main layout
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # Scrollable content
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        # Content box
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)

        # Add help sections
        content.append(self._create_intro_section())
        content.append(self._create_requirements_section())
        content.append(self._create_howto_section())
        content.append(self._create_options_section())
        content.append(self._create_validation_section())
        content.append(self._create_troubleshooting_section())
        content.append(self._create_about_section())

        scroll.set_child(content)
        toolbar.set_content(scroll)
        self.set_content(toolbar)

    def _create_section(self, title: str, content: str) -> Gtk.Box:
        """Creates a help section with title and content."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        # Title
        title_label = Gtk.Label(label=title)
        title_label.set_xalign(0)
        title_label.add_css_class("title-2")
        box.append(title_label)

        # Content
        content_label = Gtk.Label(label=content)
        content_label.set_xalign(0)
        content_label.set_wrap(True)
        content_label.set_wrap_mode(2)  # WORD_CHAR
        content_label.set_selectable(True)
        box.append(content_label)

        return box

    def _create_intro_section(self) -> Gtk.Box:
        """Creates the introduction section."""
        return self._create_section(
            "¿Qué es PDFSigner?",
            "PDFSigner es una aplicación para firmar digitalmente documentos PDF "
            "utilizando un token USB criptográfico (como SafeNet 5110).\n\n"
            "Las firmas digitales garantizan:\n"
            "• Autenticidad: Confirma quién firmó el documento\n"
            "• Integridad: Detecta si el documento fue modificado\n"
            "• No repudio: El firmante no puede negar haber firmado",
        )

    def _create_requirements_section(self) -> Gtk.Box:
        """Creates the requirements section."""
        return self._create_section(
            "Requisitos",
            "Para firmar documentos necesitas:\n\n"
            "1. Token USB criptográfico\n"
            "   - SafeNet 5110 u otro token compatible\n"
            "   - Debe estar conectado al equipo\n\n"
            "2. Certificado digital\n"
            "   - Instalado en el token\n"
            "   - Emitido por una autoridad certificante válida\n\n"
            "3. PIN del token\n"
            "   - Código secreto para acceder al token\n"
            "   - ¡No lo compartas con nadie!\n\n"
            "4. Base de datos NSS configurada\n"
            "   - Generalmente en ~/.nss\n"
            "   - Se configura en Preferencias",
        )

    def _create_howto_section(self) -> Gtk.Box:
        """Creates the how-to section."""
        return self._create_section(
            "¿Cómo firmar un documento?",
            "Paso 1: Agregar archivos\n"
            "   - Arrastra PDFs a la ventana, o\n"
            "   - Usa el botón '+' para seleccionar archivos\n\n"
            "Paso 2: Configurar opciones\n"
            "   - Click en 'Sign' (Firmar)\n"
            "   - Elige si quieres firma visible o invisible\n"
            "   - Si es visible, selecciona página y posición\n\n"
            "Paso 3: Ingresar PIN\n"
            "   - Ingresa el PIN de tu token\n"
            "   - El PIN se usa solo para esta sesión\n\n"
            "Paso 4: ¡Listo!\n"
            "   - Se crea un nuevo archivo: documento_firmado.pdf\n"
            "   - El original no se modifica",
        )

    def _create_options_section(self) -> Gtk.Box:
        """Creates the options explanation section."""
        return self._create_section(
            "Opciones de firma",
            "Firma visible vs invisible:\n\n"
            "• Firma VISIBLE:\n"
            "  - Muestra un sello/estampa en el documento\n"
            "  - Incluye nombre del firmante y fecha\n"
            "  - Útil para documentos que se imprimirán\n\n"
            "• Firma INVISIBLE:\n"
            "  - No se ve en el documento\n"
            "  - Igual de válida legalmente\n"
            "  - Se verifica con un visor de PDF\n\n"
            "Posición de la firma:\n"
            "  - Inferior derecha (default)\n"
            "  - Superior izquierda/derecha\n"
            "  - Centro\n"
            "  - Automático: busca espacio libre\n\n"
            "Página:\n"
            "  - Última página (default)\n"
            "  - Primera página\n"
            "  - Todas las páginas\n"
            "  - Páginas específicas (ej: 1,3,5)",
        )

    def _create_validation_section(self) -> Gtk.Box:
        """Creates the validation section."""
        return self._create_section(
            "Validar firmas",
            "Para verificar si un PDF está firmado correctamente:\n\n"
            "1. Agrega el PDF firmado a la lista\n"
            "2. Click en 'Validate' (Validar)\n"
            "3. Se mostrará información sobre:\n"
            "   - Quién firmó\n"
            "   - Cuándo se firmó\n"
            "   - Si el documento fue modificado\n"
            "   - Estado del certificado\n\n"
            "También puedes abrir el PDF en:\n"
            "• Adobe Reader: Panel de firmas\n"
            "• Okular: Propiedades > Firmas\n"
            "• Evince: Archivo > Propiedades",
        )

    def _create_troubleshooting_section(self) -> Gtk.Box:
        """Creates the troubleshooting section."""
        return self._create_section(
            "Problemas comunes",
            "❌ 'Token no encontrado'\n"
            "   → Verifica que el token USB esté conectado\n"
            "   → Revisa la configuración de NSS en Preferencias\n\n"
            "❌ 'PIN incorrecto'\n"
            "   → Verifica el PIN (cuidado con mayúsculas)\n"
            "   → Después de varios intentos el token se bloquea\n\n"
            "❌ 'PDF protegido'\n"
            "   → El PDF tiene restricciones de edición\n"
            "   → Contacta al creador del documento\n\n"
            "❌ 'Error de timestamp'\n"
            "   → Servidor TSA no disponible\n"
            "   → Verifica conexión a internet\n"
            "   → Prueba con 'Hora local' en Preferencias\n\n"
            "❌ La firma no aparece\n"
            "   → Abre el PDF en Adobe Reader\n"
            "   → Las firmas invisibles no se ven pero son válidas",
        )

    def _create_about_section(self) -> Gtk.Box:
        """Creates the about/links section."""
        return self._create_section(
            "Acerca de PDFSigner",
            "PDFSigner es software libre y de código abierto.\n\n"
            "📦 Repositorio:\n"
            "   https://github.com/vdirienzo/pdfsigner\n\n"
            "🐛 Reportar problemas:\n"
            "   https://github.com/vdirienzo/pdfsigner/issues\n\n"
            "📖 Documentación y actualizaciones disponibles en GitHub.\n\n"
            "Desarrollado con ❤️ usando Python, GTK4 y pyHanko.",
        )
