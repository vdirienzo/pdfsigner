"""
position_finder.py - Buscador de posición óptima para firma

Autor: Homero Thompson del Lago del Terror

Implementa algoritmo de búsqueda de espacio libre en páginas PDF
para colocar la firma visible sin obstaculizar el contenido.
"""

from dataclasses import dataclass
from enum import Enum

from loguru import logger

from pdfsigner.core.pdf_analyzer.content_analyzer import (
    BoundingBox,
    ContentAnalyzer,
    PageInfo,
)


class PositionPreference(Enum):
    """Preferencia de posición para la firma."""

    BOTTOM_RIGHT = "bottom_right"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_CENTER = "bottom_center"
    TOP_RIGHT = "top_right"
    TOP_LEFT = "top_left"
    AUTO = "auto"  # Buscar mejor posición automáticamente


@dataclass
class SignaturePosition:
    """Posición calculada para la firma."""

    x: float
    y: float
    width: float
    height: float
    page_number: int
    is_optimal: bool  # True si encontró espacio libre, False si es fallback

    @property
    def bbox(self) -> BoundingBox:
        """Retorna como BoundingBox."""
        return BoundingBox(
            x0=self.x,
            y0=self.y,
            x1=self.x + self.width,
            y1=self.y + self.height,
        )


class PositionFinder:
    """
    Buscador de posición óptima para firma visible.

    Analiza el contenido de la página y encuentra el mejor lugar
    para colocar la firma sin obstaculizar texto o imágenes.
    """

    # Margen mínimo desde los bordes de la página (en puntos)
    PAGE_MARGIN = 36  # 0.5 inch

    # Margen entre la firma y el contenido existente
    CONTENT_MARGIN = 10

    # Tamaño del grid para búsqueda (celdas por dimensión)
    GRID_SIZE = 20

    def __init__(self, analyzer: ContentAnalyzer):
        """
        Inicializa el buscador.

        Args:
            analyzer: Analizador de contenido PDF
        """
        self.analyzer = analyzer

    def find_position(
        self,
        page_number: int,
        sig_width: float,
        sig_height: float,
        preference: PositionPreference = PositionPreference.AUTO,
    ) -> SignaturePosition:
        """
        Encuentra la mejor posición para la firma.

        Args:
            page_number: Número de página (0-indexed)
            sig_width: Ancho de la firma en puntos
            sig_height: Alto de la firma en puntos
            preference: Preferencia de posición

        Returns:
            Posición calculada para la firma
        """
        page_info = self.analyzer.analyze_page(page_number)

        # Si hay preferencia específica, intentar esa posición primero
        if preference != PositionPreference.AUTO:
            pos = self._get_preferred_position(page_info, sig_width, sig_height, preference)
            if self._is_position_valid(page_info, pos):
                logger.debug(f"Usando posición preferida: {preference.value}")
                return pos

        # Búsqueda automática de mejor posición
        best_pos = self._find_best_position(page_info, sig_width, sig_height)
        if best_pos:
            logger.debug(f"Posición óptima encontrada: ({best_pos.x:.1f}, {best_pos.y:.1f})")
            return best_pos

        # Fallback: esquina inferior derecha con posible superposición
        logger.warning("No se encontró espacio libre, usando posición por defecto")
        return self._get_fallback_position(page_info, sig_width, sig_height)

    def _get_preferred_position(
        self,
        page_info: PageInfo,
        sig_width: float,
        sig_height: float,
        preference: PositionPreference,
    ) -> SignaturePosition:
        """Calcula posición según preferencia."""
        w, h = page_info.width, page_info.height
        m = self.PAGE_MARGIN

        positions = {
            PositionPreference.BOTTOM_RIGHT: (w - m - sig_width, h - m - sig_height),
            PositionPreference.BOTTOM_LEFT: (m, h - m - sig_height),
            PositionPreference.BOTTOM_CENTER: ((w - sig_width) / 2, h - m - sig_height),
            PositionPreference.TOP_RIGHT: (w - m - sig_width, m),
            PositionPreference.TOP_LEFT: (m, m),
        }

        x, y = positions.get(preference, positions[PositionPreference.BOTTOM_RIGHT])

        return SignaturePosition(
            x=x,
            y=y,
            width=sig_width,
            height=sig_height,
            page_number=page_info.page_number,
            is_optimal=True,
        )

    def _is_position_valid(self, page_info: PageInfo, pos: SignaturePosition) -> bool:
        """Verifica si una posición no colisiona con contenido."""
        sig_bbox = BoundingBox(
            x0=pos.x - self.CONTENT_MARGIN,
            y0=pos.y - self.CONTENT_MARGIN,
            x1=pos.x + pos.width + self.CONTENT_MARGIN,
            y1=pos.y + pos.height + self.CONTENT_MARGIN,
        )

        for content_bbox in page_info.all_content_blocks:
            if sig_bbox.intersects(content_bbox):
                return False

        return True

    def _find_best_position(
        self, page_info: PageInfo, sig_width: float, sig_height: float
    ) -> SignaturePosition | None:
        """
        Busca la mejor posición usando búsqueda en grid.

        Prioriza posiciones en la parte inferior de la página.
        """
        w, h = page_info.width, page_info.height
        m = self.PAGE_MARGIN

        # Área utilizable
        usable_width = w - 2 * m - sig_width
        usable_height = h - 2 * m - sig_height

        if usable_width <= 0 or usable_height <= 0:
            return None

        # Crear grid de búsqueda
        cell_width = usable_width / self.GRID_SIZE
        cell_height = usable_height / self.GRID_SIZE

        # Buscar de abajo hacia arriba, de derecha a izquierda
        for row in range(self.GRID_SIZE - 1, -1, -1):
            for col in range(self.GRID_SIZE - 1, -1, -1):
                x = m + col * cell_width
                y = m + row * cell_height

                pos = SignaturePosition(
                    x=x,
                    y=y,
                    width=sig_width,
                    height=sig_height,
                    page_number=page_info.page_number,
                    is_optimal=True,
                )

                if self._is_position_valid(page_info, pos):
                    return pos

        return None

    def _get_fallback_position(
        self, page_info: PageInfo, sig_width: float, sig_height: float
    ) -> SignaturePosition:
        """Posición de fallback cuando no hay espacio libre."""
        return SignaturePosition(
            x=page_info.width - self.PAGE_MARGIN - sig_width,
            y=page_info.height - self.PAGE_MARGIN - sig_height,
            width=sig_width,
            height=sig_height,
            page_number=page_info.page_number,
            is_optimal=False,
        )

    def mm_to_points(self, mm: float) -> float:
        """Convierte milímetros a puntos PDF."""
        return mm * 72 / 25.4

    def get_signature_size_points(self, width_mm: float, height_mm: float) -> tuple[float, float]:
        """
        Convierte dimensiones de firma de mm a puntos.

        Args:
            width_mm: Ancho en milímetros
            height_mm: Alto en milímetros

        Returns:
            Tupla (ancho_pts, alto_pts)
        """
        return (self.mm_to_points(width_mm), self.mm_to_points(height_mm))
