"""
pin_dialog.py - Diálogo para ingreso de PIN

Autor: Homero Thompson del Lago del Terror

Diálogo GTK4 para solicitar el PIN del token USB
con validación y toggle de visibilidad.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


class PinDialog(Gtk.Dialog):
    """
    Diálogo para ingreso de PIN del token.

    Características:
    - Campo de contraseña con toggle de visibilidad
    - Validación de PIN no vacío
    - Soporte para múltiples intentos
    """

    def __init__(
        self,
        parent: Gtk.Window | None = None,
        title: str = "Ingrese PIN del Token",
        message: str = "Ingrese el PIN de su token USB para firmar:",
        attempts_remaining: int | None = None,
    ):
        """
        Inicializa el diálogo de PIN.

        Args:
            parent: Ventana padre
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
        self.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        ok_button = self.add_button("Aceptar", Gtk.ResponseType.OK)
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
        """Maneja Enter en el campo de PIN."""
        if self.pin_entry.get_text():
            self.response(Gtk.ResponseType.OK)

    def _on_entry_changed(self, entry: Gtk.Entry) -> None:
        """Actualiza estado del botón OK según contenido."""
        has_pin = bool(self.pin_entry.get_text())
        self._ok_button.set_sensitive(has_pin)
        self.error_label.set_visible(False)

    def get_pin(self) -> str:
        """Obtiene el PIN ingresado."""
        return self.pin_entry.get_text()

    def show_error(self, message: str) -> None:
        """Muestra mensaje de error."""
        self.error_label.set_label(message)
        self.error_label.set_visible(True)
        self.pin_entry.grab_focus()
        self.pin_entry.select_region(0, -1)

    def clear(self) -> None:
        """Limpia el campo de PIN."""
        self.pin_entry.set_text("")


def ask_pin(
    parent: Gtk.Window | None = None,
    message: str = "Ingrese el PIN de su token USB:",
    attempts_remaining: int | None = None,
) -> str | None:
    """
    Función de conveniencia para solicitar PIN.

    Args:
        parent: Ventana padre
        message: Mensaje a mostrar
        attempts_remaining: Intentos restantes

    Returns:
        PIN ingresado o None si se cancela
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
