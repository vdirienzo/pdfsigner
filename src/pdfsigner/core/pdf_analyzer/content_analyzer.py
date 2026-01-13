"""
content_analyzer.py - Analizador de contenido de PDFs

Autor: Homero Thompson del Lago del Terror

Usa PyMuPDF para analizar el contenido de páginas PDF
y crear mapas de ocupación para posicionamiento de firma.
"""

from dataclasses import dataclass
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger


@dataclass
class BoundingBox:
    """Rectángulo delimitador."""

    x0: float
    y0: float
    x1: float
    y1: float

    @property
    def width(self) -> float:
        """Ancho del rectángulo."""
        return self.x1 - self.x0

    @property
    def height(self) -> float:
        """Alto del rectángulo."""
        return self.y1 - self.y0

    def intersects(self, other: "BoundingBox") -> bool:
        """Verifica si intersecta con otro rectángulo."""
        return not (
            self.x1 < other.x0 or self.x0 > other.x1 or self.y1 < other.y0 or self.y0 > other.y1
        )

    def to_tuple(self) -> tuple[float, float, float, float]:
        """Convierte a tupla (x0, y0, x1, y1)."""
        return (self.x0, self.y0, self.x1, self.y1)


@dataclass
class PageInfo:
    """Información de una página PDF."""

    page_number: int
    width: float
    height: float
    text_blocks: list[BoundingBox]
    image_blocks: list[BoundingBox]
    drawing_blocks: list[BoundingBox]

    @property
    def all_content_blocks(self) -> list[BoundingBox]:
        """Todos los bloques de contenido."""
        return self.text_blocks + self.image_blocks + self.drawing_blocks


class ContentAnalyzer:
    """
    Analizador de contenido de páginas PDF.

    Detecta áreas ocupadas por texto, imágenes y dibujos
    para encontrar espacio libre para la firma.
    """

    def __init__(self, pdf_path: Path | str):
        """
        Inicializa el analizador.

        Args:
            pdf_path: Ruta al archivo PDF
        """
        self.pdf_path = Path(pdf_path)
        self._doc: fitz.Document | None = None

    def open(self) -> None:
        """Abre el documento PDF."""
        self._doc = fitz.open(str(self.pdf_path))
        logger.debug(f"PDF abierto: {self.pdf_path.name} ({len(self._doc)} páginas)")

    def close(self) -> None:
        """Cierra el documento PDF."""
        if self._doc:
            self._doc.close()
            self._doc = None

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

    @property
    def page_count(self) -> int:
        """Número de páginas del PDF."""
        if self._doc is None:
            raise ValueError("Documento no abierto")
        return len(self._doc)

    def analyze_page(self, page_number: int) -> PageInfo:
        """
        Analiza el contenido de una página.

        Args:
            page_number: Número de página (0-indexed)

        Returns:
            Información de la página con áreas ocupadas
        """
        if self._doc is None:
            raise ValueError("Documento no abierto")

        page = self._doc[page_number]
        rect = page.rect

        # Extraer bloques de texto
        text_blocks = []
        text_dict = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
        for block in text_dict.get("blocks", []):
            if block.get("type") == 0:  # Texto
                bbox = BoundingBox(
                    x0=block["bbox"][0],
                    y0=block["bbox"][1],
                    x1=block["bbox"][2],
                    y1=block["bbox"][3],
                )
                text_blocks.append(bbox)

        # Extraer imágenes
        image_blocks = []
        for img in page.get_images():
            try:
                img_rect = page.get_image_bbox(img)
                if img_rect:
                    bbox = BoundingBox(
                        x0=img_rect.x0,
                        y0=img_rect.y0,
                        x1=img_rect.x1,
                        y1=img_rect.y1,
                    )
                    image_blocks.append(bbox)
            except Exception:
                continue

        # Extraer dibujos (paths)
        drawing_blocks = []
        for drawing in page.get_drawings():
            if drawing.get("rect"):
                r = drawing["rect"]
                bbox = BoundingBox(x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1)
                drawing_blocks.append(bbox)

        logger.debug(
            f"Página {page_number + 1}: "
            f"{len(text_blocks)} textos, "
            f"{len(image_blocks)} imágenes, "
            f"{len(drawing_blocks)} dibujos"
        )

        return PageInfo(
            page_number=page_number,
            width=rect.width,
            height=rect.height,
            text_blocks=text_blocks,
            image_blocks=image_blocks,
            drawing_blocks=drawing_blocks,
        )

    def is_area_free(self, page_number: int, bbox: BoundingBox, margin: float = 5.0) -> bool:
        """
        Verifica si un área está libre de contenido.

        Args:
            page_number: Número de página
            bbox: Rectángulo a verificar
            margin: Margen adicional alrededor del área

        Returns:
            True si el área está libre
        """
        page_info = self.analyze_page(page_number)

        # Expandir bbox con margen
        check_bbox = BoundingBox(
            x0=bbox.x0 - margin,
            y0=bbox.y0 - margin,
            x1=bbox.x1 + margin,
            y1=bbox.y1 + margin,
        )

        # Verificar intersección con cualquier contenido
        for content_bbox in page_info.all_content_blocks:
            if check_bbox.intersects(content_bbox):
                return False

        return True

    def get_page_margins(self, page_number: int) -> dict[str, float]:
        """
        Estima los márgenes de una página.

        Args:
            page_number: Número de página

        Returns:
            Dict con márgenes estimados (top, bottom, left, right)
        """
        page_info = self.analyze_page(page_number)

        if not page_info.all_content_blocks:
            # Sin contenido, usar márgenes por defecto (72 pts = 1 inch)
            return {"top": 72, "bottom": 72, "left": 72, "right": 72}

        # Encontrar extremos del contenido
        min_x = min(b.x0 for b in page_info.all_content_blocks)
        max_x = max(b.x1 for b in page_info.all_content_blocks)
        min_y = min(b.y0 for b in page_info.all_content_blocks)
        max_y = max(b.y1 for b in page_info.all_content_blocks)

        return {
            "top": min_y,
            "bottom": page_info.height - max_y,
            "left": min_x,
            "right": page_info.width - max_x,
        }
