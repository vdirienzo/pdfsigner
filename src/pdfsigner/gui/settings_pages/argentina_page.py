"""
argentina_page.py - Argentina Compliance settings page (Ley 25.506)

Licensed certifier information and validation options.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.core.presets import get_preset_manager
from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def _build_compliance_group(settings, dialog) -> Adw.PreferencesGroup:
    """Build the Ley 25.506 compliance switches group."""
    compliance_group = Adw.PreferencesGroup()
    compliance_group.set_title(_("Ley 25.506 Compliance"))
    compliance_group.set_description(
        _(
            "Settings for Argentine digital signature law compliance. "
            "Enables validation of certificates from licensed certifiers."
        )
    )

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

    dialog.argentine_enabled = argentine_enabled
    dialog.argentine_strict_mode = strict_mode

    return compliance_group


def _build_preset_group(settings, dialog) -> Adw.PreferencesGroup:
    """Build the quick configuration preset group."""
    preset_group = Adw.PreferencesGroup()
    preset_group.set_title(_("Quick Configuration"))
    preset_group.set_description(
        _(
            "Apply recommended settings for Argentine compliance with one click. "
            "Enables PAdES B-LT/LTA, FIPS mode, and audit trail."
        )
    )

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

    dialog.argentina_preset_button = preset_button

    return preset_group


def _build_certifier_row(
    title: str, subtitle: str, tooltip: str, url: str | None = None, a11y_name: str = ""
) -> Adw.ActionRow:
    """Build a single certifier information row with optional link."""
    row = Adw.ActionRow()
    row.set_title(title)
    row.set_subtitle(subtitle)
    row.set_tooltip_text(tooltip)
    if url:
        link = Gtk.LinkButton(uri=url)
        link.set_label(_("Website"))
        set_accessible(link, _(f"{a11y_name} website"), _(f"Visit {a11y_name} website"))
        row.add_suffix(link)
    return row


def _build_gov_certifiers_group() -> Adw.PreferencesGroup:
    """Build the governmental (free) certifiers information group."""
    gov_group = Adw.PreferencesGroup()
    gov_group.set_title(_("Governmental Certifiers (Free)"))
    gov_group.set_description(
        _("Licensed certifiers that provide free certificates to citizens and taxpayers")
    )

    gov_group.add(
        _build_certifier_row(
            "AFIP",
            _("For taxpayers with CUIT - Token/Software - Free"),
            "AFIP - Administraci\u00f3n Federal de Ingresos P\u00fablicos\n"
            "Certificados gratuitos para contribuyentes con CUIT.\n"
            "Requiere Clave Fiscal nivel 3 o superior.\n"
            "Modalidad: Token USB (SafeNet eToken) o Software.\n"
            "Renovaci\u00f3n anual gratuita.",
            "https://www.afip.gob.ar/cl_fiscal/",
            "AFIP",
        )
    )
    gov_group.add(
        _build_certifier_row(
            "RENAPER",
            _("Digital DNI - Remote signature - Free for citizens"),
            "RENAPER - Registro Nacional de las Personas\n"
            "Certificado digital integrado en el DNI argentino.\n"
            "Disponible para todos los ciudadanos argentinos.\n"
            "Modalidad: Token USB integrado en el DNI.\n"
            "Gratuito, requiere DNI actualizado (emitido despu\u00e9s de 2019).",
            "https://www.argentina.gob.ar/interior/renaper",
            "RENAPER",
        )
    )
    gov_group.add(
        _build_certifier_row(
            "FDR (Firma Digital Remota)",
            _("Remote signature with HSM - Free for citizens"),
            "FDR - Firma Digital Remota (Secretar\u00eda de Innovaci\u00f3n P\u00fablica)\n"
            "Firma remota con m\u00f3dulo de seguridad hardware (HSM).\n"
            "No requiere token f\u00edsico - 100% online.\n"
            "Autenticaci\u00f3n mediante DNI y video-selfie.\n"
            "Ideal para usuarios sin token USB.",
            "https://fdr.psi.gob.ar/",
            "FDR",
        )
    )
    gov_group.add(
        _build_certifier_row(
            "IOSFA",
            _("Social security works - Token - Free"),
            "IOSFA - Instituto de Obra Social de las Fuerzas Armadas\n"
            "Certificados digitales para personal de las fuerzas armadas.\n"
            "Gratuito para afiliados a IOSFA.\n"
            "Modalidad: Token USB (PKCS#11 compatible).",
        )
    )
    return gov_group


def _build_private_certifiers_group() -> Adw.PreferencesGroup:
    """Build the private certifiers information group."""
    private_group = Adw.PreferencesGroup()
    private_group.set_title(_("Private Certifiers"))
    private_group.set_description(_("Licensed certifiers with annual subscription fees"))

    private_group.add(
        _build_certifier_row(
            "Andreani",
            _("Token - USD 80-200/year"),
            "Andreani - Certificadora Digital Privada\n"
            "Token SafeNet eToken certificado por ONTI.\n"
            "Compatible con PDFSigner y Linux/GNOME.\n"
            "Costo: USD 80-200/a\u00f1o seg\u00fan nivel de certificaci\u00f3n.\n"
            "Renovaci\u00f3n anual con soporte t\u00e9cnico incluido.",
            "https://www.andreani.com/",
            "Andreani",
        )
    )
    private_group.add(
        _build_certifier_row(
            "E-CERT",
            _("Token/Software - USD 100-300/year"),
            "E-CERT - NIC Argentina\n"
            "M\u00faltiples niveles de certificaci\u00f3n disponibles.\n"
            "Modalidad: Token USB o Certificado Software.\n"
            "Costo: USD 100-300/a\u00f1o seg\u00fan nivel.\n"
            "Certificados con validaci\u00f3n de identidad presencial o remota.",
            "https://www.e-cert.com.ar/",
            "E-CERT",
        )
    )
    private_group.add(
        _build_certifier_row(
            "Certant",
            _("Token - USD 100-250/year"),
            "Certant - Certificadora Digital Privada\n"
            "Tokens PKCS#11 compatibles con Linux.\n"
            "Costo: USD 100-250/a\u00f1o.\n"
            "Validaci\u00f3n presencial de identidad.\n"
            "Soporte t\u00e9cnico especializado.",
            "https://www.certant.com/",
            "Certant",
        )
    )
    private_group.add(
        _build_certifier_row(
            _("College of Notaries CABA"),
            _("For notaries - Token - Annual fee"),
            "Colegio de Escribanos de la Ciudad de Buenos Aires\n"
            "Exclusivo para escribanos matriculados en CABA.\n"
            "Token USB PKCS#11 compatible.\n"
            "Costo: USD 150/a\u00f1o aproximadamente.\n"
            "Incluye cobertura legal y soporte especializado.",
        )
    )
    return private_group


def _build_legal_group() -> Adw.PreferencesGroup:
    """Build the legal information and disclaimers group."""
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

    return legal_group


def add_argentina_groups(page: Adw.PreferencesPage, settings, dialog) -> None:
    """Add Argentina compliance groups to an existing page."""
    page.add(_build_compliance_group(settings, dialog))
    page.add(_build_preset_group(settings, dialog))
    page.add(_build_gov_certifiers_group())
    page.add(_build_private_certifiers_group())
    page.add(_build_legal_group())


def create_argentina_page(settings, dialog) -> Adw.PreferencesPage:
    """Creates the Argentina Compliance (Ley 25.506) settings page."""
    page = Adw.PreferencesPage()
    page.set_title(_("Argentina"))
    page.set_icon_name("emblem-documents-symbolic")

    add_argentina_groups(page, settings, dialog)

    return page


def _on_apply_preset_clicked(button: Gtk.Button, settings, dialog) -> None:
    """Apply Argentina preset and update UI widgets."""
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
