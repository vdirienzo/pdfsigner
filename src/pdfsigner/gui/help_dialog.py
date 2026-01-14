"""
help_dialog.py - Help dialog for PDFSigner

Author: Homero Thompson del Lago del Terror

Provides user-friendly help information about how to use PDFSigner.
"""

import gi

from pdfsigner.i18n import _

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

        self.set_title(_("Help - PDFSigner"))
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
            _("What is PDFSigner?"),
            _(
                "PDFSigner is an application for digitally signing PDF documents "
                "using a cryptographic USB token (such as SafeNet 5110).\n\n"
                "Digital signatures guarantee:\n"
                "• Authenticity: Confirms who signed the document\n"
                "• Integrity: Detects if the document was modified\n"
                "• Non-repudiation: The signer cannot deny having signed"
            ),
        )

    def _create_requirements_section(self) -> Gtk.Box:
        """Creates the requirements section."""
        return self._create_section(
            _("Requirements"),
            _("To sign documents you need:\n\n"
            "1. Cryptographic USB Token\n"
            "   - SafeNet 5110 or other compatible token\n"
            "   - Must be connected to the computer\n\n"
            "2. Digital Certificate\n"
            "   - Installed on the token\n"
            "   - Issued by a valid certificate authority\n\n"
            "3. Token PIN\n"
            "   - Secret code to access the token\n"
            "   - Never share it with anyone!\n\n"
            "4. NSS Database configured\n"
            "   - Usually at ~/.nss\n"
            "   - Configure in Preferences"),
        )

    def _create_howto_section(self) -> Gtk.Box:
        """Creates the how-to section."""
        return self._create_section(
            _("How to sign a document?"),
            _("Step 1: Add files\n"
            "   - Drag PDFs to the window, or\n"
            "   - Use the '+' button to select files\n\n"
            "Step 2: Configure options\n"
            "   - Click on 'Sign'\n"
            "   - Choose visible or invisible signature\n"
            "   - If visible, select page and position\n\n"
            "Step 3: Enter PIN\n"
            "   - Enter your token PIN\n"
            "   - The PIN is used only for this session\n\n"
            "Step 4: Done!\n"
            "   - A new file is created: document_signed.pdf\n"
            "   - The original is not modified"),
        )

    def _create_options_section(self) -> Gtk.Box:
        """Creates the options explanation section."""
        return self._create_section(
            _("Signature Options"),
            _("Visible vs invisible signature:\n\n"
            "• VISIBLE signature:\n"
            "  - Shows a stamp/seal on the document\n"
            "  - Includes signer name and date\n"
            "  - Useful for documents that will be printed\n\n"
            "• INVISIBLE signature:\n"
            "  - Not visible on the document\n"
            "  - Equally valid legally\n"
            "  - Verified with a PDF viewer\n\n"
            "Signature position:\n"
            "  - Bottom right (default)\n"
            "  - Top left/right\n"
            "  - Center\n"
            "  - Automatic: finds free space\n\n"
            "Page:\n"
            "  - Last page (default)\n"
            "  - First page\n"
            "  - All pages\n"
            "  - Specific pages (e.g.: 1,3,5)"),
        )

    def _create_validation_section(self) -> Gtk.Box:
        """Creates the validation section."""
        return self._create_section(
            _("Validate Signatures"),
            _("To verify if a PDF is correctly signed:\n\n"
            "1. Add the signed PDF to the list\n"
            "2. Click on 'Validate'\n"
            "3. Information will be shown about:\n"
            "   - Who signed\n"
            "   - When it was signed\n"
            "   - If the document was modified\n"
            "   - Certificate status\n\n"
            "You can also open the PDF in:\n"
            "• Adobe Reader: Signatures panel\n"
            "• Okular: Properties > Signatures\n"
            "• Evince: File > Properties"),
        )

    def _create_troubleshooting_section(self) -> Gtk.Box:
        """Creates the troubleshooting section."""
        return self._create_section(
            _("Common Problems"),
            _("❌ 'Token not found'\n"
            "   → Verify the USB token is connected\n"
            "   → Check NSS configuration in Preferences\n\n"
            "❌ 'Incorrect PIN'\n"
            "   → Check the PIN (watch for caps lock)\n"
            "   → After several attempts the token locks\n\n"
            "❌ 'Protected PDF'\n"
            "   → The PDF has editing restrictions\n"
            "   → Contact the document creator\n\n"
            "❌ 'Timestamp error'\n"
            "   → TSA server unavailable\n"
            "   → Check internet connection\n"
            "   → Try 'Local time' in Preferences\n\n"
            "❌ Signature doesn't appear\n"
            "   → Open the PDF in Adobe Reader\n"
            "   → Invisible signatures are valid but not visible"),
        )

    def _create_about_section(self) -> Gtk.Box:
        """Creates the about/links section."""
        return self._create_section(
            _("About PDFSigner"),
            _("PDFSigner is free and open source software.\n\n"
            "Repository:\n"
            "   https://github.com/vdirienzo/pdfsigner\n\n"
            "Report issues:\n"
            "   https://github.com/vdirienzo/pdfsigner/issues\n\n"
            "Documentation and updates available on GitHub.\n\n"
            "Built with Python, GTK4 and pyHanko."),
        )
