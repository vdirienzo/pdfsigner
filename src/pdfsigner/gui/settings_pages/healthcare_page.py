"""
healthcare_page.py - Healthcare Compliance settings page

Author: Homero Thompson del Lago del Terror

Creates the Healthcare Compliance (HIPAA) settings page with session management,
emergency access, and encryption configuration.
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from pdfsigner.gui.a11y import set_accessible
from pdfsigner.i18n import _


def create_healthcare_page(settings, dialog) -> Adw.PreferencesPage:
    """
    Creates the Healthcare Compliance settings page.

    Args:
        settings: Settings object with current configuration
        dialog: Parent dialog for widget reference storage

    Returns:
        Configured PreferencesPage with HIPAA compliance options
    """
    page = Adw.PreferencesPage()
    page.set_title(_("Healthcare"))
    page.set_icon_name("hospital-symbolic")

    # --- Group 1: Master Switch ---
    master_group = Adw.PreferencesGroup()
    master_group.set_title(_("Healthcare Compliance Mode"))
    master_group.set_description(
        _(
            "Enable HIPAA-compliant features for healthcare environments. "
            "When disabled, the application works in standard mode."
        )
    )

    healthcare_switch = Adw.SwitchRow()
    healthcare_switch.set_title(_("Enable Healthcare Mode"))
    healthcare_switch.set_subtitle(
        _("Activates RBAC, session management, audit controls, and emergency access")
    )
    healthcare_switch.set_active(settings.healthcare_mode)
    set_accessible(
        healthcare_switch,
        _("Enable Healthcare Mode"),
        _("Master switch to enable all HIPAA compliance features"),
    )
    master_group.add(healthcare_switch)

    page.add(master_group)

    # --- Group 2: Session Management ---
    session_group = Adw.PreferencesGroup()
    session_group.set_title(_("Session Management"))
    session_group.set_description(
        _("HIPAA §164.312(a)(2)(iii) - Automatic logoff after inactivity")
    )

    # Session timeout (5-60 minutes)
    timeout_adjustment = Gtk.Adjustment.new(
        value=float(settings.healthcare_session_timeout_minutes),
        lower=5.0,
        upper=60.0,
        step_increment=1.0,
        page_increment=5.0,
        page_size=0.0,
    )
    session_timeout_spin = Adw.SpinRow.new(timeout_adjustment, 1.0, 0)
    session_timeout_spin.set_title(_("Auto-logoff timeout (minutes)"))
    session_timeout_spin.set_subtitle(_("Inactive sessions expire after this time (5-60)"))
    set_accessible(
        session_timeout_spin,
        _("Session timeout"),
        _("Minutes of inactivity before automatic logout"),
    )
    session_group.add(session_timeout_spin)

    # Max concurrent sessions (1-10)
    max_sessions_adjustment = Gtk.Adjustment.new(
        value=float(settings.healthcare_max_sessions),
        lower=1.0,
        upper=10.0,
        step_increment=1.0,
        page_increment=1.0,
        page_size=0.0,
    )
    max_sessions_spin = Adw.SpinRow.new(max_sessions_adjustment, 1.0, 0)
    max_sessions_spin.set_title(_("Maximum concurrent sessions"))
    max_sessions_spin.set_subtitle(_("Limit sessions per user (1-10)"))
    set_accessible(
        max_sessions_spin,
        _("Maximum sessions"),
        _("Maximum number of concurrent sessions per user"),
    )
    session_group.add(max_sessions_spin)

    page.add(session_group)

    # --- Group 3: Emergency Access (Break-Glass) ---
    emergency_group = Adw.PreferencesGroup()
    emergency_group.set_title(_("Emergency Access"))
    emergency_group.set_description(
        _("HIPAA §164.312(a)(2)(ii) - Break-glass procedure for urgent access")
    )

    # Emergency duration (1-24 hours)
    emergency_adjustment = Gtk.Adjustment.new(
        value=float(settings.healthcare_emergency_duration_hours),
        lower=1.0,
        upper=24.0,
        step_increment=1.0,
        page_increment=4.0,
        page_size=0.0,
    )
    emergency_duration_spin = Adw.SpinRow.new(emergency_adjustment, 1.0, 0)
    emergency_duration_spin.set_title(_("Emergency access duration (hours)"))
    emergency_duration_spin.set_subtitle(_("Temporary access period (1-24)"))
    set_accessible(
        emergency_duration_spin,
        _("Emergency duration"),
        _("Hours of temporary access during emergency"),
    )
    emergency_group.add(emergency_duration_spin)

    # Require approval
    emergency_approval_switch = Adw.SwitchRow()
    emergency_approval_switch.set_title(_("Require admin approval"))
    emergency_approval_switch.set_subtitle(
        _("Emergency access requests must be approved by an administrator")
    )
    emergency_approval_switch.set_active(settings.healthcare_emergency_require_approval)
    set_accessible(
        emergency_approval_switch,
        _("Require approval"),
        _("Require administrator approval for emergency access"),
    )
    emergency_group.add(emergency_approval_switch)

    page.add(emergency_group)

    # --- Group 4: Encryption Settings ---
    encryption_group = Adw.PreferencesGroup()
    encryption_group.set_title(_("Encryption"))
    encryption_group.set_description(
        _("HIPAA §164.312(a)(2)(iv) - Encryption and decryption of PHI")
    )

    # HIPAA encryption mode
    encryption_hipaa_switch = Adw.SwitchRow()
    encryption_hipaa_switch.set_title(_("Enforce HIPAA encryption"))
    encryption_hipaa_switch.set_subtitle(
        _("Require AES-256 and disable printing for encrypted documents")
    )
    encryption_hipaa_switch.set_active(settings.encryption_hipaa_mode)
    set_accessible(
        encryption_hipaa_switch,
        _("HIPAA encryption mode"),
        _("Enforce HIPAA-compliant encryption settings"),
    )
    encryption_group.add(encryption_hipaa_switch)

    # Encryption strength
    strength_model = Gtk.StringList.new([_("AES-128"), _("AES-256 (Recommended)")])
    strength_combo = Adw.ComboRow()
    strength_combo.set_title(_("Encryption strength"))
    strength_combo.set_subtitle(_("AES-256 required for HIPAA compliance"))
    strength_combo.set_model(strength_model)
    # Set selected based on current setting
    strength_combo.set_selected(0 if settings.encryption_default_strength == "aes128" else 1)
    set_accessible(
        strength_combo,
        _("Encryption strength"),
        _("Select encryption algorithm strength"),
    )
    encryption_group.add(strength_combo)

    # Store in keyring
    keyring_switch = Adw.SwitchRow()
    keyring_switch.set_title(_("Store passwords in keyring"))
    keyring_switch.set_subtitle(_("Securely store encryption passwords in system keyring"))
    keyring_switch.set_active(settings.encryption_store_in_keyring)
    set_accessible(
        keyring_switch,
        _("Use keyring"),
        _("Store encryption passwords in system keyring"),
    )
    encryption_group.add(keyring_switch)

    page.add(encryption_group)

    # --- Group 5: Document Permissions (when encrypted) ---
    permissions_group = Adw.PreferencesGroup()
    permissions_group.set_title(_("Default Permissions"))
    permissions_group.set_description(
        _("Default permissions for encrypted documents (HIPAA recommends restricting both)")
    )

    # Allow printing
    allow_print_switch = Adw.SwitchRow()
    allow_print_switch.set_title(_("Allow printing"))
    allow_print_switch.set_subtitle(_("Allow printing encrypted documents"))
    allow_print_switch.set_active(settings.encryption_default_allow_print)
    set_accessible(
        allow_print_switch,
        _("Allow printing"),
        _("Allow printing of encrypted PDF documents"),
    )
    permissions_group.add(allow_print_switch)

    # Allow copying
    allow_copy_switch = Adw.SwitchRow()
    allow_copy_switch.set_title(_("Allow content copying"))
    allow_copy_switch.set_subtitle(_("Allow copying text and images from encrypted documents"))
    allow_copy_switch.set_active(settings.encryption_default_allow_copy)
    set_accessible(
        allow_copy_switch,
        _("Allow copying"),
        _("Allow copying content from encrypted PDF documents"),
    )
    permissions_group.add(allow_copy_switch)

    page.add(permissions_group)

    # Store widget references for auto-save
    dialog.healthcare_switch = healthcare_switch
    dialog.healthcare_session_timeout_spin = session_timeout_spin
    dialog.healthcare_max_sessions_spin = max_sessions_spin
    dialog.healthcare_emergency_duration_spin = emergency_duration_spin
    dialog.healthcare_emergency_approval_switch = emergency_approval_switch
    dialog.encryption_hipaa_switch = encryption_hipaa_switch
    dialog.encryption_strength_combo = strength_combo
    dialog.encryption_keyring_switch = keyring_switch
    dialog.encryption_allow_print_switch = allow_print_switch
    dialog.encryption_allow_copy_switch = allow_copy_switch

    return page
