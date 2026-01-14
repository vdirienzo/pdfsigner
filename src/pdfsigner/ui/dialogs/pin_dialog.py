"""
pin_dialog.py - Diálogo para ingreso de PIN

Author: Homero Thompson del Lago del Terror

GTK4 dialog to request the USB token PIN
with validation and visibility toggle.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class PinDialog(Gtk.Dialog):
    """
    Dialog for token PIN entry.

    Features:
    - Password field with visibility toggle
    - Non-empty PIN validation
    - Support for multiple attempts
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        title: str = "Enter Token PIN",
        message: str = "Enter the PIN of your USB token to sign:",
        attempts_remaining: int | None = None,
    ):
        """
        Initializes the PIN dialog.

        Args:
            parent: Parent window
            title: Título del diálogo
            message: Mensaje a mostrar
            attempts_remaining: Intentos restantes (None = no mostrar)
        """
        super().__init__(
            title=title,
            transient_for=parent,
            modal=True,
        )

        self.set_default_size(400, 150)

        # Configurar botones
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok_button = self.add_button("Accept", Gtk.ResponseType.OK)
        ok_button.add_css_class("suggested-action")

        # Área de contenido
        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)

        # Mensaje principal
        self.message_label = Gtk.Label(label=message)
        self.message_label.set_wrap(True)
        self.message_label.set_xalign(0)
        content.append(self.message_label)

        # Mensaje de intentos restantes
        if attempts_remaining is not None:
            attempts_label = Gtk.Label(label=f"Intentos restantes: {attempts_remaining}")
            attempts_label.add_css_class("warning" if attempts_remaining <= 2 else "dim-label")
            attempts_label.set_xalign(0)
            content.append(attempts_label)

        # Box para entry y toggle
        entry_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)

        # Campo de PIN
        self.pin_entry = Gtk.PasswordEntry()
        self.pin_entry.set_hexpand(True)
        self.pin_entry.set_show_peek_icon(True)
        self.pin_entry.connect("activate", self._on_entry_activate)
        self.pin_entry.connect("changed", self._on_entry_changed)
        entry_box.append(self.pin_entry)

        content.append(entry_box)

        # Mensaje de error (oculto inicialmente)
        self.error_label = Gtk.Label()
        self.error_label.add_css_class("error")
        self.error_label.set_visible(False)
        self.error_label.set_xalign(0)
        content.append(self.error_label)

        # Deshabilitar OK hasta que haya PIN
        self._ok_button = ok_button
        self._ok_button.set_sensitive(False)

        # Focus en el campo de PIN
        self.pin_entry.grab_focus()

    def _on_entry_activate(self, entry: Gtk.Entry) -> None:
        """Handles Enter in PIN field."""
        if self.pin_entry.get_text():
            self.response(Gtk.ResponseType.OK)

    def _on_entry_changed(self, entry: Gtk.Entry) -> None:
        """Updates OK button status according to content."""
        has_pin = bool(self.pin_entry.get_text())
        self._ok_button.set_sensitive(has_pin)
        self.error_label.set_visible(False)

    def get_pin(self) -> str:
        """Gets the entered PIN."""
        return self.pin_entry.get_text()

    def show_error(self, message: str) -> None:
        """Shows error message."""
        self.error_label.set_label(message)
        self.error_label.set_visible(True)
        self.pin_entry.grab_focus()
        self.pin_entry.select_region(0, -1)

    def clear(self) -> None:
        """Clears the PIN field."""
        self.pin_entry.set_text("")


def ask_pin(
    parent: Gtk.Window | None = None,
    message: str = "Enter the PIN of your USB token:",
    attempts_remaining: int | None = None,
) -> str | None:
    """
    Convenience function to request PIN.

    Args:
        parent: Parent window
        message: Mensaje a mostrar
        attempts_remaining: Intentos restantes

    Returns:
        Entered PIN or None if cancelled
    """
    dialog = PinDialog(
        parent=parent,
        message=message,
        attempts_remaining=attempts_remaining,
    )

    response = dialog.run()
    pin = dialog.get_pin() if response == Gtk.ResponseType.OK else None
    dialog.destroy()

    return pin
