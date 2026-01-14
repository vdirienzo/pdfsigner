"""
signature_preview.py - Widget de preview de firma visible

Author: Homero Thompson del Lago del Terror

GTK4 widget that shows a thumbnail of the PDF page
with the position where the signature will be placed.
"""

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
import fitz  # PyMuPDF
from gi.repository import Gdk, GdkPixbuf, Gtk

from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
from pdfsigner.core.pdf_analyzer.position_finder import (
    PositionFinder,
    PositionPreference,
    SignaturePosition,
)


class SignaturePreviewWidget(Gtk.Box):
    """
    Visible signature preview widget.

    Shows page thumbnail with rectangle
    indicating where the signature will be placed.
    """

    PREVIEW_WIDTH = 300
    PREVIEW_HEIGHT = 400

    def __init__(self):
        """Initializes the widget."""
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        self._pdf_path: Path | None = None
        self._page_number: int = 0
        self._signature_position: SignaturePosition | None = None

        # Título
        title = Gtk.Label(label="Preview")
        title.add_css_class("heading")
        self.append(title)

        # Área de dibujo
        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_size_request(self.PREVIEW_WIDTH, self.PREVIEW_HEIGHT)
        self.drawing_area.set_draw_func(self._on_draw)

        # Frame para el preview
        frame = Gtk.Frame()
        frame.set_child(self.drawing_area)
        self.append(frame)

        # Info de posición
        self.position_label = Gtk.Label()
        self.position_label.set_wrap(True)
        self.position_label.add_css_class("dim-label")
        self.append(self.position_label)

        # Pixbuf de la página
        self._page_pixbuf: GdkPixbuf.Pixbuf | None = None

    def set_pdf(
        self,
        pdf_path: Path,
        page_number: int,
        sig_width_mm: float = 50,
        sig_height_mm: float = 20,
        preference: PositionPreference = PositionPreference.AUTO,
    ) -> None:
        """
        Configures the PDF and calculates signature position.

        Args:
            pdf_path: Path to the PDF
            page_number: Page number (0-indexed)
            sig_width_mm: Signature width in mm
            sig_height_mm: Signature height in mm
            preference: Position preference
        """
        self._pdf_path = pdf_path
        self._page_number = page_number

        # Renderizar página
        self._render_page()

        # Calcular posición de firma
        with ContentAnalyzer(pdf_path) as analyzer:
            finder = PositionFinder(analyzer)
            sig_width, sig_height = finder.get_signature_size_points(sig_width_mm, sig_height_mm)
            self._signature_position = finder.find_position(
                page_number, sig_width, sig_height, preference
            )

        # Actualizar label
        if self._signature_position:
            pos = self._signature_position
            status = "✓ Free space" if pos.is_optimal else "⚠ Fallback position"
            self.position_label.set_label(
                f"Página {page_number + 1} - {status}\nPosición: ({pos.x:.0f}, {pos.y:.0f})"
            )

        # Redibujar
        self.drawing_area.queue_draw()

    def _render_page(self) -> None:
        """Renders the PDF page as pixbuf."""
        if self._pdf_path is None:
            return

        try:
            doc = fitz.open(str(self._pdf_path))
            page = doc[self._page_number]

            # Calcular zoom para ajustar al preview
            page_rect = page.rect
            zoom_x = self.PREVIEW_WIDTH / page_rect.width
            zoom_y = self.PREVIEW_HEIGHT / page_rect.height
            zoom = min(zoom_x, zoom_y) * 0.9  # 90% para dejar margen

            # Renderizar
            mat = fitz.Matrix(zoom, zoom)
            pix = page.get_pixmap(matrix=mat, alpha=False)

            # Convertir a GdkPixbuf
            self._page_pixbuf = GdkPixbuf.Pixbuf.new_from_data(
                pix.samples,
                GdkPixbuf.Colorspace.RGB,
                False,
                8,
                pix.width,
                pix.height,
                pix.stride,
            )

            # Guardar factor de escala para dibujar firma
            self._scale = zoom
            self._page_width = page_rect.width
            self._page_height = page_rect.height

            doc.close()

        except Exception as e:
            self._page_pixbuf = None
            self.position_label.set_label(f"Error: {e}")

    def _on_draw(
        self,
        area: Gtk.DrawingArea,
        cr,  # cairo context
        width: int,
        height: int,
    ) -> None:
        """Drawing callback."""
        # Fondo gris
        cr.set_source_rgb(0.9, 0.9, 0.9)
        cr.paint()

        if self._page_pixbuf is None:
            # Mensaje de "sin preview"
            cr.set_source_rgb(0.5, 0.5, 0.5)
            cr.select_font_face("Sans")
            cr.set_font_size(14)
            cr.move_to(width / 2 - 50, height / 2)
            cr.show_text("No preview")
            return

        # Calcular posición centrada
        pix_width = self._page_pixbuf.get_width()
        pix_height = self._page_pixbuf.get_height()
        x_offset = (width - pix_width) / 2
        y_offset = (height - pix_height) / 2

        # Dibujar página
        Gdk.cairo_set_source_pixbuf(cr, self._page_pixbuf, x_offset, y_offset)
        cr.paint()

        # Dibujar rectángulo de firma
        if self._signature_position is not None:
            pos = self._signature_position

            # Escalar coordenadas de firma
            sig_x = x_offset + pos.x * self._scale
            sig_y = y_offset + pos.y * self._scale
            sig_w = pos.width * self._scale
            sig_h = pos.height * self._scale

            # Rectángulo con borde
            if pos.is_optimal:
                cr.set_source_rgba(0.2, 0.6, 0.2, 0.3)  # Verde
            else:
                cr.set_source_rgba(0.8, 0.6, 0.2, 0.3)  # Naranja
            cr.rectangle(sig_x, sig_y, sig_w, sig_h)
            cr.fill()

            # Borde
            if pos.is_optimal:
                cr.set_source_rgb(0.2, 0.6, 0.2)
            else:
                cr.set_source_rgb(0.8, 0.6, 0.2)
            cr.set_line_width(2)
            cr.rectangle(sig_x, sig_y, sig_w, sig_h)
            cr.stroke()

            # Texto "SIGNATURE"
            cr.set_source_rgb(0, 0, 0)
            cr.select_font_face("Sans")
            cr.set_font_size(10)
            cr.move_to(sig_x + 4, sig_y + sig_h / 2 + 4)
            cr.show_text("SIGNATURE")

    def clear(self) -> None:
        """Clears the preview."""
        self._pdf_path = None
        self._page_pixbuf = None
        self._signature_position = None
        self.position_label.set_label("")
        self.drawing_area.queue_draw()
