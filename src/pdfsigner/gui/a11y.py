"""
a11y.py - Accessibility helpers for GTK4

Author: Homero Thompson del Lago del Terror

GTK4 accessibility utilities for setting accessible names and descriptions.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


def set_accessible_name(widget: Gtk.Widget, name: str) -> None:
    """
    Set the accessible name for a GTK4 widget.

    Args:
        widget: The GTK widget to set accessibility for
        name: The accessible name for screen readers
    """
    widget.update_property(
        [Gtk.AccessibleProperty.LABEL],
        [name],
    )


def set_accessible_description(widget: Gtk.Widget, description: str) -> None:
    """
    Set the accessible description for a GTK4 widget.

    Args:
        widget: The GTK widget to set accessibility for
        description: The accessible description for screen readers
    """
    widget.update_property(
        [Gtk.AccessibleProperty.DESCRIPTION],
        [description],
    )


def set_accessible(
    widget: Gtk.Widget,
    name: str | None = None,
    description: str | None = None,
) -> None:
    """
    Set accessible name and/or description for a GTK4 widget.

    Args:
        widget: The GTK widget to set accessibility for
        name: Optional accessible name for screen readers
        description: Optional accessible description for screen readers
    """
    props = []
    values = []

    if name is not None:
        props.append(Gtk.AccessibleProperty.LABEL)
        values.append(name)

    if description is not None:
        props.append(Gtk.AccessibleProperty.DESCRIPTION)
        values.append(description)

    if props:
        widget.update_property(props, values)
