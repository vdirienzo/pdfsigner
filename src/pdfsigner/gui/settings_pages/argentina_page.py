"""
argentina_page.py - Argentina Compliance settings page

Author: Homero Thompson del Lago del Terror

Creates the Argentina Compliance (Ley 25.506) settings page with licensed
certifier information and validation options.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def create_argentina_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the Argentina Compliance settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for storing widget references

    Returns:
        Configured PreferencesPage for Argentine compliance (Ley 25.506)
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Argentina"))
    page.set_icon_name("emblem-documents-symbolic")

    # --- Group 1: Compliance Ley 25.506 ---
    compliance_group = Adw.PreferencesGroup()
    compliance_group.set_title(_("Ley 25.506 Compliance"))
    compliance_group.set_description(
        _(
            "Settings for Argentine digital signature law compliance. "
            "Enables validation of certificates from licensed certifiers."
        )
    )

    # Switch: Enable Argentine compliance
    argentine_enabled = Adw.SwitchRow()
    argentine_enabled.set_title(_("Enable Argentine compliance"))
    argentine_enabled.set_subtitle(
        _("Validate certificates against licensed certifiers (AFIP, RENAPER, etc.)")
    )
    argentine_enabled.set_active(getattr(settings, "argentine_compliance_enabled", False))
    set_accessible(
        argentine_enabled,
        _("Enable Argentine compliance"),
        _("Activate validation for Argentine licensed certifiers"),
    )
    compliance_group.add(argentine_enabled)

    # Switch: Strict mode (only Argentine CAs)
    strict_mode = Adw.SwitchRow()
    strict_mode.set_title(_("Strict mode"))
    strict_mode.set_subtitle(_("Only accept certificates from licensed Argentine certifiers"))
    strict_mode.set_active(getattr(settings, "argentine_strict_mode", False))
    set_accessible(
        strict_mode,
        _("Strict mode"),
        _("Reject certificates not issued by licensed Argentine certifiers"),
    )
    compliance_group.add(strict_mode)

    page.add(compliance_group)

    # --- Group 2: Governmental Certifiers (Free) ---
    gov_group = Adw.PreferencesGroup()
    gov_group.set_title(_("Governmental Certifiers (Free)"))
    gov_group.set_description(
        _("Licensed certifiers that provide free certificates to citizens and taxpayers")
    )

    # AFIP
    afip_row = Adw.ActionRow()
    afip_row.set_title("AFIP")
    afip_row.set_subtitle(_("For taxpayers with CUIT - Token/Software - Free"))
    afip_link = Gtk.LinkButton(uri="https://www.afip.gob.ar/cl_fiscal/")
    afip_link.set_label(_("Website"))
    set_accessible(
        afip_link,
        _("AFIP website"),
        _("Visit AFIP Clave Fiscal website for certificate information"),
    )
    afip_row.add_suffix(afip_link)
    gov_group.add(afip_row)

    # RENAPER
    renaper_row = Adw.ActionRow()
    renaper_row.set_title("RENAPER")
    renaper_row.set_subtitle(_("Digital DNI - Remote signature - Free for citizens"))
    renaper_link = Gtk.LinkButton(uri="https://www.argentina.gob.ar/interior/renaper")
    renaper_link.set_label(_("Website"))
    set_accessible(
        renaper_link,
        _("RENAPER website"),
        _("Visit RENAPER website for Digital DNI information"),
    )
    renaper_row.add_suffix(renaper_link)
    gov_group.add(renaper_row)

    # FDR
    fdr_row = Adw.ActionRow()
    fdr_row.set_title("FDR (Firma Digital Remota)")
    fdr_row.set_subtitle(_("Remote signature with HSM - Free for citizens"))
    fdr_link = Gtk.LinkButton(uri="https://fdr.psi.gob.ar/")
    fdr_link.set_label(_("Website"))
    set_accessible(
        fdr_link,
        _("FDR website"),
        _("Visit FDR website for remote signature service"),
    )
    fdr_row.add_suffix(fdr_link)
    gov_group.add(fdr_row)

    # IOSFA
    iosfa_row = Adw.ActionRow()
    iosfa_row.set_title("IOSFA")
    iosfa_row.set_subtitle(_("Social security works - Token - Free"))
    gov_group.add(iosfa_row)

    page.add(gov_group)

    # --- Group 3: Private Certifiers ---
    private_group = Adw.PreferencesGroup()
    private_group.set_title(_("Private Certifiers"))
    private_group.set_description(_("Licensed certifiers with annual subscription fees"))

    # Andreani
    andreani_row = Adw.ActionRow()
    andreani_row.set_title("Andreani")
    andreani_row.set_subtitle(_("Token - USD 80-200/year"))
    andreani_link = Gtk.LinkButton(uri="https://www.andreani.com/")
    andreani_link.set_label(_("Website"))
    set_accessible(
        andreani_link,
        _("Andreani website"),
        _("Visit Andreani website for certificate information"),
    )
    andreani_row.add_suffix(andreani_link)
    private_group.add(andreani_row)

    # E-CERT
    ecert_row = Adw.ActionRow()
    ecert_row.set_title("E-CERT")
    ecert_row.set_subtitle(_("Token/Software - USD 100-300/year"))
    ecert_link = Gtk.LinkButton(uri="https://www.e-cert.com.ar/")
    ecert_link.set_label(_("Website"))
    set_accessible(
        ecert_link,
        _("E-CERT website"),
        _("Visit E-CERT website for certificate information"),
    )
    ecert_row.add_suffix(ecert_link)
    private_group.add(ecert_row)

    # Certant
    certant_row = Adw.ActionRow()
    certant_row.set_title("Certant")
    certant_row.set_subtitle(_("Token - USD 100-250/year"))
    certant_link = Gtk.LinkButton(uri="https://www.certant.com/")
    certant_link.set_label(_("Website"))
    set_accessible(
        certant_link,
        _("Certant website"),
        _("Visit Certant website for certificate information"),
    )
    certant_row.add_suffix(certant_link)
    private_group.add(certant_row)

    # Escribanos CABA
    escribanos_row = Adw.ActionRow()
    escribanos_row.set_title(_("College of Notaries CABA"))
    escribanos_row.set_subtitle(_("For notaries - Token - Annual fee"))
    private_group.add(escribanos_row)

    page.add(private_group)

    # --- Group 4: Legal Information ---
    legal_group = Adw.PreferencesGroup()
    legal_group.set_title(_("Legal Information"))

    # Disclaimer
    disclaimer_row = Adw.ActionRow()
    disclaimer_row.set_title(_("Important Notice"))
    disclaimer_row.set_subtitle(
        _(
            "PDFSigner does NOT issue digital certificates. "
            "For full legal validity under Ley 25.506, you must use a certificate "
            "from a licensed certifier (AFIP, RENAPER, FDR, or any private certifier)."
        )
    )
    disclaimer_row.add_css_class("warning")
    set_accessible(
        disclaimer_row,
        _("Legal disclaimer"),
        _("Important notice about certificate requirements for legal validity"),
    )
    legal_group.add(disclaimer_row)

    # Link AAIP
    aaip_row = Adw.ActionRow()
    aaip_row.set_title(_("Official Certifier List"))
    aaip_row.set_subtitle(
        _("AAIP - National Agency for Access to Public Information (Supervisory Authority)")
    )
    aaip_link = Gtk.LinkButton(uri="https://www.argentina.gob.ar/aaip")
    aaip_link.set_label(_("View"))
    set_accessible(
        aaip_link,
        _("AAIP website"),
        _("Visit AAIP website for official list of licensed certifiers"),
    )
    aaip_row.add_suffix(aaip_link)
    legal_group.add(aaip_row)

    # Link Ley 25.506
    law_row = Adw.ActionRow()
    law_row.set_title(_("Digital Signature Law"))
    law_row.set_subtitle(_("Ley 25.506 - Full legal text"))
    law_link = Gtk.LinkButton(
        uri="http://servicios.infoleg.gob.ar/infolegInternet/anexos/70000-74999/70749/norma.htm"
    )
    law_link.set_label(_("View"))
    set_accessible(
        law_link,
        _("Ley 25.506 text"),
        _("View full text of Argentine Digital Signature Law"),
    )
    law_row.add_suffix(law_link)
    legal_group.add(law_row)

    page.add(legal_group)

    # Store widget references for auto-save
    dialog.argentine_enabled = argentine_enabled
    dialog.argentine_strict_mode = strict_mode

    return page
