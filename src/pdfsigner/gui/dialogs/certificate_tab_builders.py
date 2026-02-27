"""
certificate_tab_builders.py - Tab builder functions for CertificateDetailsDialog

Author: Homero Thompson del Lago del Terror

Standalone functions that build each tab widget for the certificate details
dialog. Each function receives the dialog instance to access certificate data
and helper methods.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.i18n import _

if TYPE_CHECKING:
    from pdfsigner.gui.dialogs.certificate_details_dialog import CertificateDetailsDialog


def create_general_tab(dialog: CertificateDetailsDialog) -> Gtk.Widget:
    """Create the General information tab."""
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_vexpand(True)

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    content.set_margin_top(16)
    content.set_margin_bottom(16)
    content.set_margin_start(16)
    content.set_margin_end(16)

    details = dialog._details

    # Issued To section
    issued_to_group = Adw.PreferencesGroup()
    issued_to_group.set_title(_("Issued To"))

    cn = details.subject_dn.get("CN", _("Unknown"))
    o = details.subject_dn.get("O", "")
    ou = details.subject_dn.get("OU", "")

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

    issuer_cn = details.issuer_dn.get("CN", _("Unknown"))
    issuer_o = details.issuer_dn.get("O", "")

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
    valid_from_row.set_subtitle(dialog._format_datetime(details.not_before))
    valid_from_row.add_css_class("property")
    validity_group.add(valid_from_row)

    valid_to_row = Adw.ActionRow()
    valid_to_row.set_title(_("Valid To"))
    valid_to_row.set_subtitle(dialog._format_datetime(details.not_after))
    valid_to_row.add_css_class("property")
    validity_group.add(valid_to_row)

    content.append(validity_group)

    # Key Usage section
    if details.key_usage:
        usage_group = Adw.PreferencesGroup()
        usage_group.set_title(_("Key Usage"))

        usage_row = Adw.ActionRow()
        usage_row.set_title(_("Permitted Uses"))

        usage_box = Gtk.FlowBox()
        usage_box.set_selection_mode(Gtk.SelectionMode.NONE)
        usage_box.set_homogeneous(False)
        usage_box.set_row_spacing(6)
        usage_box.set_column_spacing(6)

        for usage in details.key_usage:
            badge = Gtk.Label(label=usage)
            badge.add_css_class("pill")
            badge.add_css_class("accent")
            usage_box.insert(badge, -1)

        usage_row.set_child(usage_box)
        usage_group.add(usage_row)

        content.append(usage_group)

    scroll.set_child(content)
    return scroll


def create_details_tab(dialog: CertificateDetailsDialog) -> Gtk.Widget:
    """Create the Details tab with all certificate properties."""
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_vexpand(True)

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    content.set_margin_top(16)
    content.set_margin_bottom(16)
    content.set_margin_start(16)
    content.set_margin_end(16)

    details = dialog._details

    # Subject DN section
    subject_group = Adw.PreferencesGroup()
    subject_group.set_title(_("Subject"))

    for key, value in details.subject_dn.items():
        row = dialog._create_copyable_row(key, value)
        subject_group.add(row)

    content.append(subject_group)

    # Issuer DN section
    issuer_group = Adw.PreferencesGroup()
    issuer_group.set_title(_("Issuer"))

    for key, value in details.issuer_dn.items():
        row = dialog._create_copyable_row(key, value)
        issuer_group.add(row)

    content.append(issuer_group)

    # Serial Number section
    serial_group = Adw.PreferencesGroup()
    serial_group.set_title(_("Serial Number"))

    serial_hex_row = dialog._create_copyable_row(_("Hexadecimal"), details.serial_number)
    serial_group.add(serial_hex_row)

    serial_dec_row = dialog._create_copyable_row(_("Decimal"), details.serial_number_decimal)
    serial_group.add(serial_dec_row)

    content.append(serial_group)

    # Public Key section
    key_group = Adw.PreferencesGroup()
    key_group.set_title(_("Public Key"))

    algo_row = Adw.ActionRow()
    algo_row.set_title(_("Algorithm"))
    algo_row.set_subtitle(details.public_key_algorithm)
    algo_row.add_css_class("property")
    key_group.add(algo_row)

    size_row = Adw.ActionRow()
    size_row.set_title(_("Size"))
    size_row.set_subtitle(f"{details.public_key_size} bits")
    size_row.add_css_class("property")
    key_group.add(size_row)

    sig_row = Adw.ActionRow()
    sig_row.set_title(_("Signature Algorithm"))
    sig_row.set_subtitle(details.signature_algorithm)
    sig_row.add_css_class("property")
    key_group.add(sig_row)

    content.append(key_group)

    # Extended Key Usage
    if details.extended_key_usage:
        eku_group = Adw.PreferencesGroup()
        eku_group.set_title(_("Extended Key Usage"))

        for usage in details.extended_key_usage:
            row = Adw.ActionRow()
            row.set_title(usage)
            row.add_css_class("property")
            eku_group.add(row)

        content.append(eku_group)

    # Subject Alternative Names
    if details.subject_alt_names:
        san_group = Adw.PreferencesGroup()
        san_group.set_title(_("Subject Alternative Names"))

        for san in details.subject_alt_names:
            row = Adw.ActionRow()
            row.set_title(san)
            row.add_css_class("property")
            san_group.add(row)

        content.append(san_group)

    # CRL Distribution Points
    if details.crl_distribution_points:
        crl_group = Adw.PreferencesGroup()
        crl_group.set_title(_("CRL Distribution Points"))

        for crl_url in details.crl_distribution_points:
            row = dialog._create_copyable_row(_("URL"), crl_url)
            crl_group.add(row)

        content.append(crl_group)

    # OCSP Responders
    if details.ocsp_responders:
        ocsp_group = Adw.PreferencesGroup()
        ocsp_group.set_title(_("OCSP Responders"))

        for ocsp_url in details.ocsp_responders:
            row = dialog._create_copyable_row(_("URL"), ocsp_url)
            ocsp_group.add(row)

        content.append(ocsp_group)

    scroll.set_child(content)
    return scroll


def create_extensions_tab(dialog: CertificateDetailsDialog) -> Gtk.Widget:
    """Create the Extensions tab."""
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_vexpand(True)

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    content.set_margin_top(16)
    content.set_margin_bottom(16)
    content.set_margin_start(16)
    content.set_margin_end(16)

    details = dialog._details

    # Extensions list
    ext_group = Adw.PreferencesGroup()
    ext_group.set_title(_("X.509 Extensions"))
    ext_group.set_description(
        _("All extensions present in this certificate with their OIDs and values")
    )

    if not details.all_extensions:
        no_ext_row = Adw.ActionRow()
        no_ext_row.set_title(_("No extensions found"))
        no_ext_row.add_css_class("dim-label")
        ext_group.add(no_ext_row)
    else:
        for ext_dict in details.all_extensions:
            expander = Adw.ExpanderRow()
            expander.set_title(ext_dict["name"])
            expander.set_subtitle(f"OID: {ext_dict['oid']}")

            if ext_dict["critical"] == "Yes":
                critical_label = Gtk.Label(label=_("Critical"))
                critical_label.add_css_class("pill")
                critical_label.add_css_class("error")
                expander.add_suffix(critical_label)

            if "value" in ext_dict:
                value_row = Adw.ActionRow()
                value_row.set_title(_("Value"))

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
    if details.certificate_policies:
        policies_group = Adw.PreferencesGroup()
        policies_group.set_title(_("Certificate Policies"))

        for policy in details.certificate_policies:
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
