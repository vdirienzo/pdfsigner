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

from pdfsigner.core.presets import get_preset_manager
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

    # --- Group 2: Configuration Preset ---
    preset_group = Adw.PreferencesGroup()
    preset_group.set_title(_("Quick Configuration"))
    preset_group.set_description(
        _(
            "Apply recommended settings for Argentine compliance with one click. "
            "Enables PAdES B-LT/LTA, FIPS mode, and audit trail."
        )
    )

    # Button: Apply Argentina preset
    preset_row = Adw.ActionRow()
    preset_row.set_title(_("Apply Argentina preset"))
    preset_row.set_subtitle(
        _(
            "LTV + Archive TS + FIPS mode + Audit trail. "
            "Recommended for legal documents under Ley 25.506."
        )
    )
    preset_button = Gtk.Button()
    preset_button.set_label(_("Apply"))
    preset_button.add_css_class("suggested-action")
    preset_button.connect("clicked", _on_apply_preset_clicked, settings, dialog)
    set_accessible(
        preset_button,
        _("Apply Argentina preset"),
        _("Apply recommended configuration for Argentine digital signature compliance"),
    )
    preset_row.add_suffix(preset_button)
    preset_row.set_activatable_widget(preset_button)
    preset_group.add(preset_row)

    page.add(preset_group)

    # --- Group 3: Governmental Certifiers (Free) ---
    gov_group = Adw.PreferencesGroup()
    gov_group.set_title(_("Governmental Certifiers (Free)"))
    gov_group.set_description(
        _("Licensed certifiers that provide free certificates to citizens and taxpayers")
    )

    # AFIP
    afip_row = Adw.ActionRow()
    afip_row.set_title("AFIP")
    afip_row.set_subtitle(_("For taxpayers with CUIT - Token/Software - Free"))
    afip_row.set_tooltip_text(
        "AFIP - Administración Federal de Ingresos Públicos\n"
        "Certificados gratuitos para contribuyentes con CUIT.\n"
        "Requiere Clave Fiscal nivel 3 o superior.\n"
        "Modalidad: Token USB (SafeNet eToken) o Software.\n"
        "Renovación anual gratuita."
    )
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
    renaper_row.set_tooltip_text(
        "RENAPER - Registro Nacional de las Personas\n"
        "Certificado digital integrado en el DNI argentino.\n"
        "Disponible para todos los ciudadanos argentinos.\n"
        "Modalidad: Token USB integrado en el DNI.\n"
        "Gratuito, requiere DNI actualizado (emitido después de 2019)."
    )
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
    fdr_row.set_tooltip_text(
        "FDR - Firma Digital Remota (Secretaría de Innovación Pública)\n"
        "Firma remota con módulo de seguridad hardware (HSM).\n"
        "No requiere token físico - 100% online.\n"
        "Autenticación mediante DNI y video-selfie.\n"
        "Ideal para usuarios sin token USB."
    )
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
    iosfa_row.set_tooltip_text(
        "IOSFA - Instituto de Obra Social de las Fuerzas Armadas\n"
        "Certificados digitales para personal de las fuerzas armadas.\n"
        "Gratuito para afiliados a IOSFA.\n"
        "Modalidad: Token USB (PKCS#11 compatible)."
    )
    gov_group.add(iosfa_row)

    page.add(gov_group)

    # --- Group 4: Private Certifiers ---
    private_group = Adw.PreferencesGroup()
    private_group.set_title(_("Private Certifiers"))
    private_group.set_description(_("Licensed certifiers with annual subscription fees"))

    # Andreani
    andreani_row = Adw.ActionRow()
    andreani_row.set_title("Andreani")
    andreani_row.set_subtitle(_("Token - USD 80-200/year"))
    andreani_row.set_tooltip_text(
        "Andreani - Certificadora Digital Privada\n"
        "Token SafeNet eToken certificado por ONTI.\n"
        "Compatible con PDFSigner y Linux/GNOME.\n"
        "Costo: USD 80-200/año según nivel de certificación.\n"
        "Renovación anual con soporte técnico incluido."
    )
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
    ecert_row.set_tooltip_text(
        "E-CERT - NIC Argentina\n"
        "Múltiples niveles de certificación disponibles.\n"
        "Modalidad: Token USB o Certificado Software.\n"
        "Costo: USD 100-300/año según nivel.\n"
        "Certificados con validación de identidad presencial o remota."
    )
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
    certant_row.set_tooltip_text(
        "Certant - Certificadora Digital Privada\n"
        "Tokens PKCS#11 compatibles con Linux.\n"
        "Costo: USD 100-250/año.\n"
        "Validación presencial de identidad.\n"
        "Soporte técnico especializado."
    )
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
    escribanos_row.set_tooltip_text(
        "Colegio de Escribanos de la Ciudad de Buenos Aires\n"
        "Exclusivo para escribanos matriculados en CABA.\n"
        "Token USB PKCS#11 compatible.\n"
        "Costo: USD 150/año aproximadamente.\n"
        "Incluye cobertura legal y soporte especializado."
    )
    private_group.add(escribanos_row)

    page.add(private_group)

    # --- Group 5: Legal Information ---
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
    dialog.argentina_preset_button = preset_button

    return page


def _on_apply_preset_clicked(button: Gtk.Button, settings, dialog) -> None:
    """
    Handle Argentina preset button click.

    Applies the Argentina preset configuration to current settings and
    updates UI widgets to reflect the changes.

    Args:
        button: Button that triggered the action
        settings: Settings object to modify
        dialog: Parent dialog with widget references
    """
    from loguru import logger

    preset_manager = get_preset_manager()

    # Apply preset to settings object
    success = preset_manager.apply_preset("argentina", settings)

    if not success:
        logger.error("Failed to apply Argentina preset")
        return

    # Update UI widgets to reflect preset values
    if hasattr(dialog, "argentine_enabled"):
        dialog.argentine_enabled.set_active(settings.argentine_compliance_enabled)

    if hasattr(dialog, "argentine_strict_mode"):
        dialog.argentine_strict_mode.set_active(settings.argentine_strict_mode)

    if hasattr(dialog, "ltv_switch"):
        dialog.ltv_switch.set_active(settings.ltv_enabled)

    if hasattr(dialog, "ltv_fail_open_switch"):
        dialog.ltv_fail_open_switch.set_active(settings.ltv_fail_open)

    # Trigger auto-save to persist changes
    if hasattr(dialog, "_on_setting_changed"):
        dialog._on_setting_changed()

    logger.info("Argentina preset applied successfully")
