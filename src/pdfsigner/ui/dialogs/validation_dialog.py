"""
validation_dialog.py - Signature validation dialog

Author: Homero Thompson del Lago del Terror

GTK4/Adwaita dialog that shows validation results
of existing signatures in a PDF.
Design inspired by GNOME Document Viewer.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.core.validator.pdf_validator import (
    SignatureInfo,
    SignatureStatus,
    ValidationResult,
)
from pdfsigner.i18n import _


class ValidationResultDialog(Adw.Dialog):
    """
    Dialog that shows signature validation results.

    Design based on GNOME Document Viewer's signature panel.
    Features a dropdown to select between signers and shows
    detailed certificate information.
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        result: ValidationResult | None = None,
    ):
        """
        Initializes the dialog.

        Args:
            parent: Parent window
            result: Validation result
        """
        super().__init__()

        self.result = result
        self._current_signature: SignatureInfo | None = None
        self._details_expanded = False

        self.set_title(_("Signatures"))
        self.set_content_width(400)
        self.set_content_height(500)

        # Main content
        self._build_ui()

        if parent:
            self.present(parent)

    def _build_ui(self) -> None:
        """Builds the user interface."""
        # Main container with toolbar
        toolbar_view = Adw.ToolbarView()

        # Header bar
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)
        header.set_show_start_title_buttons(False)
        toolbar_view.add_top_bar(header)

        # Close button on the left
        close_button = Gtk.Button(icon_name="window-close-symbolic")
        close_button.connect("clicked", lambda b: self.close())
        header.pack_start(close_button)

        # Content
        if self.result is None or self.result.error:
            content = self._build_error_view()
        elif not self.result.is_signed:
            content = self._build_not_signed_view()
        else:
            content = self._build_signatures_view()

        toolbar_view.set_content(content)
        self.set_child(toolbar_view)

    def _build_error_view(self) -> Gtk.Widget:
        """Builds error view."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("error")
        box.append(icon)

        error_msg = self.result.error if self.result else _("Unknown error")
        label = Gtk.Label(label=_("Error validating document"))
        label.add_css_class("title-2")
        box.append(label)

        detail = Gtk.Label(label=error_msg)
        detail.set_wrap(True)
        detail.add_css_class("dim-label")
        box.append(detail)

        return box

    def _build_not_signed_view(self) -> Gtk.Widget:
        """Builds view for unsigned documents."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_valign(Gtk.Align.CENTER)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        icon = Gtk.Image.new_from_icon_name("document-edit-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("dim-label")
        box.append(icon)

        label = Gtk.Label(label=_("No Signatures"))
        label.add_css_class("title-2")
        box.append(label)

        detail = Gtk.Label(label=_("This document has no digital signatures."))
        detail.add_css_class("dim-label")
        box.append(detail)

        return box

    def _build_signatures_view(self) -> Gtk.Widget:
        """Builds the main signatures view (GNOME style)."""
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        main_box.set_margin_top(16)
        main_box.set_margin_bottom(16)
        main_box.set_margin_start(16)
        main_box.set_margin_end(16)

        # "Signed by:" label
        signed_by_label = Gtk.Label(label=_("Signed by:"))
        signed_by_label.set_xalign(0)
        signed_by_label.add_css_class("heading")
        main_box.append(signed_by_label)

        # Signer dropdown (ComboBox style)
        self._signer_dropdown = self._create_signer_dropdown()
        main_box.append(self._signer_dropdown)

        # Status group
        self._status_group = Adw.PreferencesGroup()
        main_box.append(self._status_group)

        # Signature Information group
        info_label = Gtk.Label(label=_("Signature Information"))
        info_label.set_xalign(0)
        info_label.add_css_class("heading")
        info_label.set_margin_top(8)
        main_box.append(info_label)

        self._info_group = Adw.PreferencesGroup()
        main_box.append(self._info_group)

        # Details section (expandable)
        self._details_revealer = Gtk.Revealer()
        self._details_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)

        self._details_group = Adw.PreferencesGroup()
        self._details_revealer.set_child(self._details_group)
        main_box.append(self._details_revealer)

        # View Details button
        details_button = Gtk.Button(label=_("View Details..."))
        details_button.set_halign(Gtk.Align.CENTER)
        details_button.set_margin_top(8)
        details_button.connect("clicked", self._on_toggle_details)
        self._details_button = details_button
        main_box.append(details_button)

        scrolled.set_child(main_box)

        # Show first signature
        if self.result and self.result.signatures:
            self._show_signature(self.result.signatures[0])

        return scrolled

    def _create_signer_dropdown(self) -> Gtk.Widget:
        """Creates the signer selection dropdown."""
        # Create a ListBox styled as dropdown
        frame = Gtk.Frame()
        frame.add_css_class("view")

        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        listbox.add_css_class("boxed-list")

        # Store reference for selection handling
        self._signer_listbox = listbox

        for i, sig in enumerate(self.result.signatures):
            row = Gtk.ListBoxRow()
            row.sig_index = i

            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            box.set_margin_top(10)
            box.set_margin_bottom(10)
            box.set_margin_start(12)
            box.set_margin_end(12)

            # Signer name
            name_label = Gtk.Label(label=sig.signer_name)
            name_label.set_hexpand(True)
            name_label.set_xalign(0)
            name_label.set_ellipsize(True)
            box.append(name_label)

            # Status icon
            if sig.status == SignatureStatus.VALID:
                icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                icon.add_css_class("success")
            elif sig.status == SignatureStatus.INVALID:
                icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
                icon.add_css_class("error")
            else:
                icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                icon.add_css_class("warning")
            box.append(icon)

            row.set_child(box)
            listbox.append(row)

        listbox.connect("row-selected", self._on_signer_selected)

        # Select first row
        first_row = listbox.get_row_at_index(0)
        if first_row:
            listbox.select_row(first_row)

        frame.set_child(listbox)
        return frame

    def _on_signer_selected(self, listbox: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        """Handles signer selection change."""
        if row and hasattr(row, "sig_index"):
            sig = self.result.signatures[row.sig_index]
            self._show_signature(sig)

    def _show_signature(self, sig: SignatureInfo) -> None:
        """Updates the view with selected signature info."""
        self._current_signature = sig

        # Clear existing content
        self._clear_group(self._status_group)
        self._clear_group(self._info_group)
        self._clear_group(self._details_group)

        # Status rows
        if sig.status == SignatureStatus.VALID:
            valid_row = self._create_status_row(
                "emblem-ok-symbolic",
                _("Signature is valid."),
                "success",
            )
            self._status_group.add(valid_row)
        elif sig.status == SignatureStatus.INVALID:
            invalid_row = self._create_status_row(
                "dialog-error-symbolic",
                _("Signature is invalid."),
                "error",
            )
            self._status_group.add(invalid_row)
        else:
            unknown_row = self._create_status_row(
                "dialog-question-symbolic",
                _("Signature validity unknown."),
                "warning",
            )
            self._status_group.add(unknown_row)

        # Warning if certificate from untrusted issuer (common case)
        if sig.status_message and "untrusted" in sig.status_message.lower():
            warning_row = self._create_status_row(
                "dialog-warning-symbolic",
                _("Signed with a certificate issued by untrusted issuer."),
                "warning",
            )
            self._status_group.add(warning_row)
        elif sig.status_message and sig.status != SignatureStatus.VALID:
            warning_row = self._create_status_row(
                "dialog-warning-symbolic",
                sig.status_message,
                "warning",
            )
            self._status_group.add(warning_row)

        # Basic info - Date and Time
        if sig.signing_time:
            time_str = sig.signing_time.strftime("%a %d %b %Y %H:%M:%S")
            date_row = self._create_info_row(_("Date and Time"), time_str)
            self._info_group.add(date_row)

        # Details section (shown when expanded)
        # Certificate Issuer
        if sig.certificate_issuer:
            issuer_row = self._create_info_row(_("Certificate Issuer"), sig.certificate_issuer)
            self._details_group.add(issuer_row)

        # Certificate's Issuance Time
        if sig.certificate_valid_from:
            from_str = sig.certificate_valid_from.strftime("%a %d %b %Y %H:%M:%S")
            from_row = self._create_info_row(_("Certificate's Issuance Time"), from_str)
            self._details_group.add(from_row)

        # Certificate's Expiration Time
        if sig.certificate_valid_to:
            to_str = sig.certificate_valid_to.strftime("%a %d %b %Y %H:%M:%S")
            to_row = self._create_info_row(_("Certificate's Expiration Time"), to_str)
            self._details_group.add(to_row)

        # Document coverage
        if sig.covers_whole_document:
            coverage_row = self._create_info_row(
                _("Document Coverage"), _("Covers entire document")
            )
        else:
            coverage_row = self._create_info_row(
                _("Document Coverage"), _("Covers partial revision")
            )
        self._details_group.add(coverage_row)

    def _create_status_row(self, icon_name: str, text: str, css_class: str) -> Adw.ActionRow:
        """Creates a status row with icon."""
        row = Adw.ActionRow()
        row.set_title(text)

        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.add_css_class(css_class)
        row.add_prefix(icon)

        return row

    def _create_info_row(self, label: str, value: str) -> Adw.ActionRow:
        """Creates an info row with label and value."""
        row = Adw.ActionRow()
        row.set_title(label)
        row.set_subtitle(value)
        row.add_css_class("property")

        return row

    def _clear_group(self, group: Adw.PreferencesGroup) -> None:
        """Removes all rows from a preferences group."""
        # Get the listbox child and remove all rows
        child = group.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            if isinstance(child, Gtk.ListBox):
                row = child.get_first_child()
                while row:
                    next_row = row.get_next_sibling()
                    child.remove(row)
                    row = next_row
            child = next_child

    def _on_toggle_details(self, button: Gtk.Button) -> None:
        """Toggles the details section visibility."""
        self._details_expanded = not self._details_expanded
        self._details_revealer.set_reveal_child(self._details_expanded)

        if self._details_expanded:
            button.set_label(_("Hide Details"))
        else:
            button.set_label(_("View Details..."))


def show_validation_result(
    parent: Gtk.Window | None = None,
    result: ValidationResult | None = None,
) -> None:
    """
    Shows validation dialog.

    Args:
        parent: Parent window
        result: Validation result
    """
    dialog = ValidationResultDialog(parent=parent, result=result)
    if parent:
        dialog.present(parent)
