"""
certificate_details_dialog.py - Certificate details viewer dialog

Author: Homero Thompson del Lago del Terror

Displays detailed X.509 certificate information in a professional,
multi-tab interface using libadwaita components.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk
from loguru import logger

from pdfsigner.core.certificate import X509Details, X509Parser
from pdfsigner.i18n import _


class CertificateDetailsDialog(Adw.Window):
    """
    Certificate details viewer dialog.

    Displays comprehensive X.509 certificate information organized
    in tabs: General, Details, Extensions, and Thumbprints.
    """

    def __init__(
        self,
        cert_bytes: bytes | None = None,
        cert_details: X509Details | None = None,
        **kwargs,
    ):
        """
        Initialize the certificate details dialog.

        Args:
            cert_bytes: DER-encoded certificate bytes (will be parsed)
            cert_details: Pre-parsed X509Details object
            **kwargs: Additional arguments passed to Adw.Window

        Note: Either cert_bytes or cert_details must be provided.
        """
        super().__init__(**kwargs)

        if cert_details is None and cert_bytes is None:
            raise ValueError("Either cert_bytes or cert_details must be provided")

        if cert_details is None:
            assert cert_bytes is not None  # for type checker
            try:
                self._details = X509Parser.parse(cert_bytes)
            except Exception as e:
                logger.error(f"Failed to parse certificate: {e}")
                raise
        else:
            self._details = cert_details

        self.set_title(_("Certificate Details"))
        self.set_default_size(650, 700)
        self.set_modal(True)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Configure the user interface."""
        # Header bar
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)

        # Main layout with toolbar
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)

        # ViewSwitcher for tabs
        view_stack = Adw.ViewStack()

        # Create all tabs
        view_stack.add_titled(self._create_general_tab(), "general", _("General"))
        view_stack.add_titled(self._create_details_tab(), "details", _("Details"))
        view_stack.add_titled(self._create_extensions_tab(), "extensions", _("Extensions"))
        view_stack.add_titled(self._create_thumbprints_tab(), "thumbprints", _("Thumbprints"))

        # ViewSwitcherBar for bottom tab switching
        switcher_bar = Adw.ViewSwitcherBar()
        switcher_bar.set_stack(view_stack)

        # ViewSwitcherTitle for top (responsive)
        switcher_title = Adw.ViewSwitcherTitle()
        switcher_title.set_stack(view_stack)
        switcher_title.set_title(_("Certificate Details"))
        header.set_title_widget(switcher_title)

        # Bind visibility
        switcher_bar.bind_property(
            "reveal", switcher_title, "title-visible", Adw.PropertyBindingFlags.INVERT_BOOLEAN
        )

        # Main content box
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.append(view_stack)
        content_box.append(switcher_bar)

        toolbar.set_content(content_box)
        self.set_content(toolbar)

    def _create_general_tab(self) -> Gtk.Widget:
        """Create the General information tab."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Issued To section
        issued_to_group = Adw.PreferencesGroup()
        issued_to_group.set_title(_("Issued To"))

        cn = self._details.subject_dn.get("CN", _("Unknown"))
        o = self._details.subject_dn.get("O", "")
        ou = self._details.subject_dn.get("OU", "")

        cn_row = Adw.ActionRow()
        cn_row.set_title(_("Common Name (CN)"))
        cn_row.set_subtitle(cn)
        cn_row.add_css_class("property")
        issued_to_group.add(cn_row)

        if o:
            o_row = Adw.ActionRow()
            o_row.set_title(_("Organization (O)"))
            o_row.set_subtitle(o)
            o_row.add_css_class("property")
            issued_to_group.add(o_row)

        if ou:
            ou_row = Adw.ActionRow()
            ou_row.set_title(_("Organizational Unit (OU)"))
            ou_row.set_subtitle(ou)
            ou_row.add_css_class("property")
            issued_to_group.add(ou_row)

        content.append(issued_to_group)

        # Issued By section
        issued_by_group = Adw.PreferencesGroup()
        issued_by_group.set_title(_("Issued By"))

        issuer_cn = self._details.issuer_dn.get("CN", _("Unknown"))
        issuer_o = self._details.issuer_dn.get("O", "")

        issuer_cn_row = Adw.ActionRow()
        issuer_cn_row.set_title(_("Common Name (CN)"))
        issuer_cn_row.set_subtitle(issuer_cn)
        issuer_cn_row.add_css_class("property")
        issued_by_group.add(issuer_cn_row)

        if issuer_o:
            issuer_o_row = Adw.ActionRow()
            issuer_o_row.set_title(_("Organization (O)"))
            issuer_o_row.set_subtitle(issuer_o)
            issuer_o_row.add_css_class("property")
            issued_by_group.add(issuer_o_row)

        content.append(issued_by_group)

        # Validity section
        validity_group = Adw.PreferencesGroup()
        validity_group.set_title(_("Validity Period"))

        valid_from_row = Adw.ActionRow()
        valid_from_row.set_title(_("Valid From"))
        valid_from_row.set_subtitle(self._format_datetime(self._details.not_before))
        valid_from_row.add_css_class("property")
        validity_group.add(valid_from_row)

        valid_to_row = Adw.ActionRow()
        valid_to_row.set_title(_("Valid To"))
        valid_to_row.set_subtitle(self._format_datetime(self._details.not_after))
        valid_to_row.add_css_class("property")
        validity_group.add(valid_to_row)

        content.append(validity_group)

        # Key Usage section
        if self._details.key_usage:
            usage_group = Adw.PreferencesGroup()
            usage_group.set_title(_("Key Usage"))

            usage_row = Adw.ActionRow()
            usage_row.set_title(_("Permitted Uses"))

            # Create badges/pills for each usage
            usage_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            usage_box.set_wrap(True)

            for usage in self._details.key_usage:
                badge = Gtk.Label(label=usage)
                badge.add_css_class("pill")
                badge.add_css_class("accent")
                usage_box.append(badge)

            usage_row.set_child(usage_box)
            usage_group.add(usage_row)

            content.append(usage_group)

        scroll.set_child(content)
        return scroll

    def _create_details_tab(self) -> Gtk.Widget:
        """Create the Details tab with all certificate properties."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Subject DN section
        subject_group = Adw.PreferencesGroup()
        subject_group.set_title(_("Subject"))

        for key, value in self._details.subject_dn.items():
            row = self._create_copyable_row(key, value)
            subject_group.add(row)

        content.append(subject_group)

        # Issuer DN section
        issuer_group = Adw.PreferencesGroup()
        issuer_group.set_title(_("Issuer"))

        for key, value in self._details.issuer_dn.items():
            row = self._create_copyable_row(key, value)
            issuer_group.add(row)

        content.append(issuer_group)

        # Serial Number section
        serial_group = Adw.PreferencesGroup()
        serial_group.set_title(_("Serial Number"))

        serial_hex_row = self._create_copyable_row(_("Hexadecimal"), self._details.serial_number)
        serial_group.add(serial_hex_row)

        serial_dec_row = self._create_copyable_row(
            _("Decimal"), self._details.serial_number_decimal
        )
        serial_group.add(serial_dec_row)

        content.append(serial_group)

        # Public Key section
        key_group = Adw.PreferencesGroup()
        key_group.set_title(_("Public Key"))

        algo_row = Adw.ActionRow()
        algo_row.set_title(_("Algorithm"))
        algo_row.set_subtitle(self._details.public_key_algorithm)
        algo_row.add_css_class("property")
        key_group.add(algo_row)

        size_row = Adw.ActionRow()
        size_row.set_title(_("Size"))
        size_row.set_subtitle(f"{self._details.public_key_size} bits")
        size_row.add_css_class("property")
        key_group.add(size_row)

        sig_row = Adw.ActionRow()
        sig_row.set_title(_("Signature Algorithm"))
        sig_row.set_subtitle(self._details.signature_algorithm)
        sig_row.add_css_class("property")
        key_group.add(sig_row)

        content.append(key_group)

        # Extended Key Usage
        if self._details.extended_key_usage:
            eku_group = Adw.PreferencesGroup()
            eku_group.set_title(_("Extended Key Usage"))

            for usage in self._details.extended_key_usage:
                row = Adw.ActionRow()
                row.set_title(usage)
                row.add_css_class("property")
                eku_group.add(row)

            content.append(eku_group)

        # Subject Alternative Names
        if self._details.subject_alt_names:
            san_group = Adw.PreferencesGroup()
            san_group.set_title(_("Subject Alternative Names"))

            for san in self._details.subject_alt_names:
                row = Adw.ActionRow()
                row.set_title(san)
                row.add_css_class("property")
                san_group.add(row)

            content.append(san_group)

        # CRL Distribution Points
        if self._details.crl_distribution_points:
            crl_group = Adw.PreferencesGroup()
            crl_group.set_title(_("CRL Distribution Points"))

            for crl_url in self._details.crl_distribution_points:
                row = self._create_copyable_row(_("URL"), crl_url)
                crl_group.add(row)

            content.append(crl_group)

        # OCSP Responders
        if self._details.ocsp_responders:
            ocsp_group = Adw.PreferencesGroup()
            ocsp_group.set_title(_("OCSP Responders"))

            for ocsp_url in self._details.ocsp_responders:
                row = self._create_copyable_row(_("URL"), ocsp_url)
                ocsp_group.add(row)

            content.append(ocsp_group)

        scroll.set_child(content)
        return scroll

    def _create_extensions_tab(self) -> Gtk.Widget:
        """Create the Extensions tab."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Extensions list
        ext_group = Adw.PreferencesGroup()
        ext_group.set_title(_("X.509 Extensions"))
        ext_group.set_description(
            _("All extensions present in this certificate with their OIDs and values")
        )

        if not self._details.all_extensions:
            no_ext_row = Adw.ActionRow()
            no_ext_row.set_title(_("No extensions found"))
            no_ext_row.add_css_class("dim-label")
            ext_group.add(no_ext_row)
        else:
            for ext_dict in self._details.all_extensions:
                # Expandable row for each extension
                expander = Adw.ExpanderRow()
                expander.set_title(ext_dict["name"])
                expander.set_subtitle(f"OID: {ext_dict['oid']}")

                # Critical flag badge
                if ext_dict["critical"] == "Yes":
                    critical_label = Gtk.Label(label=_("Critical"))
                    critical_label.add_css_class("pill")
                    critical_label.add_css_class("error")
                    expander.add_suffix(critical_label)

                # Add value as child row
                if "value" in ext_dict:
                    value_row = Adw.ActionRow()
                    value_row.set_title(_("Value"))

                    # Create selectable label for value
                    value_label = Gtk.Label(label=ext_dict["value"])
                    value_label.set_wrap(True)
                    value_label.set_wrap_mode(2)  # WORD_CHAR
                    value_label.set_selectable(True)
                    value_label.set_halign(Gtk.Align.START)
                    value_label.add_css_class("caption")
                    value_label.add_css_class("dim-label")
                    value_label.set_margin_top(8)
                    value_label.set_margin_bottom(8)

                    value_row.set_child(value_label)
                    expander.add_row(value_row)

                ext_group.add(expander)

        # Certificate Policies (special section)
        if self._details.certificate_policies:
            policies_group = Adw.PreferencesGroup()
            policies_group.set_title(_("Certificate Policies"))

            for policy in self._details.certificate_policies:
                policy_row = Adw.ExpanderRow()
                policy_row.set_title(_("Policy OID"))
                policy_row.set_subtitle(policy["oid"])

                if "qualifiers" in policy:
                    qual_row = Adw.ActionRow()
                    qual_row.set_title(_("Qualifiers"))
                    qual_row.set_subtitle(policy["qualifiers"])
                    policy_row.add_row(qual_row)

                policies_group.add(policy_row)

            content.append(policies_group)

        content.append(ext_group)
        scroll.set_child(content)
        return scroll

    def _create_thumbprints_tab(self) -> Gtk.Widget:
        """Create the Thumbprints tab."""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Thumbprints section
        thumbprints_group = Adw.PreferencesGroup()
        thumbprints_group.set_title(_("Certificate Thumbprints"))
        thumbprints_group.set_description(
            _("Thumbprints are cryptographic hashes that uniquely identify this certificate")
        )

        # SHA-256
        sha256_row = self._create_copyable_row(
            "SHA-256", self._format_thumbprint(self._details.thumbprint_sha256)
        )
        thumbprints_group.add(sha256_row)

        # SHA-1
        sha1_row = self._create_copyable_row(
            "SHA-1", self._format_thumbprint(self._details.thumbprint_sha1)
        )
        thumbprints_group.add(sha1_row)

        content.append(thumbprints_group)

        scroll.set_child(content)
        return scroll

    def _create_copyable_row(self, title: str, value: str) -> Adw.ActionRow:
        """Create a row with a copy button."""
        row = Adw.ActionRow()
        row.set_title(title)
        row.set_subtitle(value)
        row.add_css_class("property")

        # Copy button
        copy_btn = Gtk.Button()
        copy_btn.set_icon_name("edit-copy-symbolic")
        copy_btn.add_css_class("flat")
        copy_btn.add_css_class("circular")
        copy_btn.set_valign(Gtk.Align.CENTER)
        copy_btn.set_tooltip_text(_("Copy to clipboard"))
        copy_btn.connect("clicked", lambda _: self._copy_to_clipboard(value))
        row.add_suffix(copy_btn)

        return row

    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard."""
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(text)

        logger.debug(f"Copied to clipboard: {text[:50]}...")

    def _format_datetime(self, dt) -> str:
        """Format datetime for display."""
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def _format_thumbprint(self, thumbprint: str) -> str:
        """Format thumbprint with colons every 2 characters."""
        return ":".join(thumbprint[i : i + 2] for i in range(0, len(thumbprint), 2))
