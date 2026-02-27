"""Signature options dialog for configuring stamp, position and metadata."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from pdfsigner.config.settings import get_settings
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance
from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def _get_template_choices() -> list[tuple[str, str]]:
    """Get available template choices as (value, display_name) tuples."""
    try:
        from pdfsigner.core.signature import list_all_templates

        templates = list_all_templates()
    except ImportError:
        templates = []

    # Start with "invisible" option (no stamp)
    choices = [("", _("Invisible (metadata only)"))]

    template_labels = {
        "default": _("Default (simple text)"),
        "corporate": _("Corporate"),
        "minimal": _("Minimal"),
        "with_qr": _("With QR Code"),
    }

    for name, source in templates:
        label = template_labels.get(name, name.replace("_", " ").title())
        if source == "user":
            label = f"{label} ({_('custom')})"
        choices.append((name, label))

    return choices


class SignatureOptionsDialog(Gtk.Dialog):
    """Dialog to configure signature template, position and metadata before signing."""

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        total_pages: int = 1,
        default_appearance: SignatureAppearance | None = None,
    ):
        """Initialize the options dialog."""
        super().__init__(
            title=_("Signature Options"),
            transient_for=parent,
            modal=True,
        )

        self.total_pages = total_pages
        self.default_appearance = default_appearance or SignatureAppearance()

        settings = get_settings()
        self.default_template = settings.signature_template or ""
        self._template_choices = _get_template_choices()

        self.set_default_size(420, -1)

        cancel_button = self.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
        set_accessible(cancel_button, _("Cancel"))
        ok_button = self.add_button(_("Sign"), Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")
        set_accessible(ok_button, _("Sign files"))

        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(16)
        content.set_margin_bottom(8)
        content.set_margin_start(16)
        content.set_margin_end(16)

        self.options_grid = Gtk.Grid()
        self.options_grid.set_row_spacing(12)
        self.options_grid.set_column_spacing(16)

        self._build_template_section()
        self._build_position_section()
        content.append(self.options_grid)
        self._build_metadata_section(content, settings)

        # Connect template change signal AFTER all widgets exist
        self.template_combo.connect("changed", self._on_template_changed)
        self._update_position_options_visibility()

    def _build_template_section(self) -> None:
        """Build the stamp template selector (grid row 0)."""
        template_label = Gtk.Label(label=_("Stamp"))
        template_label.set_xalign(0)
        template_label.add_css_class("dim-label")
        self.options_grid.attach(template_label, 0, 0, 1, 1)

        self.template_combo = Gtk.ComboBoxText()
        for value, label in self._template_choices:
            self.template_combo.append(value, label)
        self.template_combo.set_hexpand(True)
        set_accessible(
            self.template_combo,
            _("Stamp template"),
            _("Select the visual stamp template"),
        )

        self.template_combo.set_active_id(self.default_template)
        if self.template_combo.get_active_id() is None:
            self.template_combo.set_active(0)

        self.options_grid.attach(self.template_combo, 1, 0, 1, 1)

    def _build_position_section(self) -> None:
        """Build the page and position selectors (grid rows 1-3)."""
        self._build_page_selector()
        self._build_position_selector()

    def _build_page_selector(self) -> None:
        """Build page selection combo and custom entry (grid rows 1-2)."""
        self.page_label = Gtk.Label(label=_("Page"))
        self.page_label.set_xalign(0)
        self.page_label.add_css_class("dim-label")
        self.options_grid.attach(self.page_label, 0, 1, 1, 1)

        self.page_combo = Gtk.ComboBoxText()
        self.page_combo.append("last", _("Last page"))
        self.page_combo.append("first", _("First page"))
        self.page_combo.append("all", _("All pages"))
        self.page_combo.append("custom", _("Custom..."))
        self.page_combo.set_hexpand(True)
        set_accessible(self.page_combo, _("Page selection"), _("Select which pages to sign"))
        self.page_combo.connect("changed", self._on_page_combo_changed)
        self.options_grid.attach(self.page_combo, 1, 1, 1, 1)

        # Custom page entry (initially hidden)
        self.custom_label = Gtk.Label(label=_("Pages"))
        self.custom_label.set_xalign(0)
        self.custom_label.add_css_class("dim-label")
        self.custom_label.set_visible(False)
        self.options_grid.attach(self.custom_label, 0, 2, 1, 1)

        self.custom_page_entry = Gtk.Entry()
        self.custom_page_entry.set_placeholder_text(_("e.g., 1,3,5 or 1-3"))
        self.custom_page_entry.set_hexpand(True)
        set_accessible(self.custom_page_entry, _("Custom pages"), _("Enter page numbers or ranges"))
        self.custom_page_entry.set_visible(False)
        self.options_grid.attach(self.custom_page_entry, 1, 2, 1, 1)

        # Set default page selection
        default_page = self.default_appearance.page
        if default_page in ("last", "first", "all"):
            self.page_combo.set_active_id(default_page)
        elif isinstance(default_page, str) and any(c in default_page for c in ",-"):
            self.page_combo.set_active_id("custom")
            self.custom_page_entry.set_text(default_page)
            self.custom_label.set_visible(True)
            self.custom_page_entry.set_visible(True)
        else:
            self.page_combo.set_active_id("last")

    def _build_position_selector(self) -> None:
        """Build position preference combo (grid row 3)."""
        self.pos_label = Gtk.Label(label=_("Position"))
        self.pos_label.set_xalign(0)
        self.pos_label.add_css_class("dim-label")
        self.options_grid.attach(self.pos_label, 0, 3, 1, 1)

        self.position_combo = Gtk.ComboBoxText()
        self.position_combo.append("auto", _("Automatic (find free space)"))
        self.position_combo.append("bottom_right", _("Bottom right"))
        self.position_combo.append("bottom_left", _("Bottom left"))
        self.position_combo.append("bottom_center", _("Bottom center"))
        self.position_combo.append("top_right", _("Top right"))
        self.position_combo.append("top_left", _("Top left"))
        self.position_combo.set_hexpand(True)
        set_accessible(
            self.position_combo,
            _("Signature position"),
            _("Select where to place the signature on the page"),
        )
        self.position_combo.set_active_id(self.default_appearance.position_preference.value)
        self.options_grid.attach(self.position_combo, 1, 3, 1, 1)

    def _build_metadata_section(self, content: Gtk.Box, settings: object) -> None:
        """Build the collapsible signature metadata section."""
        info_grid = Gtk.Grid()
        info_grid.set_row_spacing(8)
        info_grid.set_column_spacing(12)
        info_grid.set_margin_top(8)
        info_grid.set_margin_start(8)

        self.reason_entry = self._add_info_field(
            info_grid,
            0,
            _("Reason"),
            _("e.g., I approve this document"),
            _("Signature reason"),
            _("Enter the reason for signing"),
            settings.default_signature_reason,
        )
        self.location_entry = self._add_info_field(
            info_grid,
            1,
            _("Location"),
            _("e.g., New York, NY"),
            _("Signature location"),
            _("Enter the location where you are signing"),
            settings.default_signature_location,
        )
        self.contact_entry = self._add_info_field(
            info_grid,
            2,
            _("Contact Info"),
            _("e.g., email@company.com"),
            _("Contact information"),
            _("Enter your contact information"),
            settings.default_signature_contact,
        )

        self.info_expander = Gtk.Expander(label=_("Additional Information"))
        self.info_expander.set_expanded(False)
        self.info_expander.set_child(info_grid)
        self.info_expander.set_margin_top(8)
        self.info_expander.connect("notify::expanded", self._on_expander_toggled)
        content.append(self.info_expander)

    def _add_info_field(
        self,
        grid: Gtk.Grid,
        row: int,
        label_text: str,
        placeholder: str,
        a11y_label: str,
        a11y_desc: str,
        default_value: str = "",
    ) -> Gtk.Entry:
        """Add a labeled entry field to the info grid and return the entry widget."""
        label = Gtk.Label(label=label_text)
        label.set_xalign(0)
        label.add_css_class("dim-label")
        grid.attach(label, 0, row, 1, 1)

        entry = Gtk.Entry()
        entry.set_placeholder_text(placeholder)
        entry.set_hexpand(True)
        set_accessible(entry, a11y_label, a11y_desc)
        if default_value:
            entry.set_text(default_value)
        grid.attach(entry, 1, row, 1, 1)
        return entry

    def _on_expander_toggled(self, expander: Gtk.Expander, _pspec: object) -> None:
        """Handle expander toggle to resize dialog appropriately."""
        if not expander.get_expanded():
            self.set_default_size(420, -1)
            self.queue_resize()

    def _on_template_changed(self, combo: Gtk.ComboBoxText) -> None:
        """Handle template selection change."""
        self._update_position_options_visibility()

    def _update_position_options_visibility(self) -> None:
        """Show/hide position options based on template selection."""
        template_id = self.template_combo.get_active_id()
        is_visible = bool(template_id)  # Empty = invisible signature

        self.page_label.set_visible(is_visible)
        self.page_combo.set_visible(is_visible)
        self.pos_label.set_visible(is_visible)
        self.position_combo.set_visible(is_visible)

        if not is_visible:
            self.custom_label.set_visible(False)
            self.custom_page_entry.set_visible(False)

    def _on_page_combo_changed(self, combo: Gtk.ComboBoxText) -> None:
        """Show/hide custom page entry based on selection."""
        is_custom = combo.get_active_id() == "custom"
        self.custom_label.set_visible(is_custom)
        self.custom_page_entry.set_visible(is_custom)
        if is_custom:
            self.custom_page_entry.grab_focus()

    def get_selected_template(self) -> str:
        """Get the selected template name."""
        return self.template_combo.get_active_id() or ""

    def get_signature_metadata(self) -> dict[str, str]:
        """Get signature metadata (reason, location, contact_info)."""
        return {
            "reason": self.reason_entry.get_text().strip(),
            "location": self.location_entry.get_text().strip(),
            "contact_info": self.contact_entry.get_text().strip(),
        }

    def get_appearance(self) -> SignatureAppearance:
        """Get the selected configuration."""
        template_id = self.get_selected_template()
        is_visible = bool(template_id)

        if not is_visible:
            return SignatureAppearance(
                visible=False,
                page="last",
                width_mm=self.default_appearance.width_mm,
                height_mm=self.default_appearance.height_mm,
            )

        page_id = self.page_combo.get_active_id() or "last"
        if page_id == "custom":
            page = self.custom_page_entry.get_text().strip() or "last"
        else:
            page = page_id

        pos_id = self.position_combo.get_active_id()
        position = PositionPreference(pos_id)

        return SignatureAppearance(
            visible=True,
            page=page,
            width_mm=self.default_appearance.width_mm,
            height_mm=self.default_appearance.height_mm,
            position_preference=position,
            image_path=self.default_appearance.image_path,
            qr_enabled=False,  # QR is controlled by template
        )


def ask_signature_options(
    parent: Gtk.Window | None = None,
    total_pages: int = 1,
    default_appearance: SignatureAppearance | None = None,
) -> tuple[SignatureAppearance, str, dict[str, str]] | None:
    """Show options dialog. Returns (appearance, template, metadata) or None if cancelled."""
    dialog = SignatureOptionsDialog(
        parent=parent,
        total_pages=total_pages,
        default_appearance=default_appearance,
    )

    response = dialog.run()
    if response == Gtk.ResponseType.OK:
        result = (
            dialog.get_appearance(),
            dialog.get_selected_template(),
            dialog.get_signature_metadata(),
        )
    else:
        result = None

    dialog.destroy()
    return result
