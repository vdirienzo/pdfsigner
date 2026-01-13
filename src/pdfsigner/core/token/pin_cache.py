"""
pin_cache.py - Cache seguro de PIN en memoria

Autor: Homero Thompson del Lago del Terror

Implementa cache de PIN para firma en lote con:
- Almacenamiento solo en memoria (nunca en disco)
- Expiración automática por tiempo
- Limpieza segura de memoria
"""

import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class CachedPin:
    """PIN cacheado con metadata de expiración."""

    pin: str
    created_at: float
    expires_at: float


class PinCache:
    """
    Cache seguro de PIN en memoria.

    El PIN se almacena temporalmente para permitir firma en lote
    sin pedir el PIN múltiples veces.
    """

    def __init__(self, timeout_seconds: int = 300):
        """
        Inicializa el cache de PIN.

        Args:
            timeout_seconds: Tiempo de expiración en segundos (default: 5 min)
        """
        self._timeout = timeout_seconds
        self._cache: CachedPin | None = None
        self._lock = threading.Lock()

    def store(self, pin: str) -> None:
        """
        Almacena el PIN en cache.

        Args:
            pin: PIN a cachear
        """
        with self._lock:
            now = time.time()
            self._cache = CachedPin(
                pin=pin,
                created_at=now,
                expires_at=now + self._timeout,
            )

    def get(self) -> str | None:
        """
        Obtiene el PIN cacheado si no ha expirado.

        Returns:
            PIN si está válido, None si expiró o no existe
        """
        with self._lock:
            if self._cache is None:
                return None

            if time.time() > self._cache.expires_at:
                self._clear_unsafe()
                return None

            return self._cache.pin

    def clear(self) -> None:
        """Limpia el cache de forma segura."""
        with self._lock:
            self._clear_unsafe()

    def _clear_unsafe(self) -> None:
        """Limpia el cache (debe llamarse con lock adquirido)."""
        if self._cache is not None:
            # Sobrescribir el PIN en memoria antes de eliminar
            if self._cache.pin:
                # Generar datos aleatorios del mismo tamaño
                dummy = secrets.token_hex(len(self._cache.pin))
                # Sobrescribir (mejor esfuerzo en Python)
                self._cache.pin = dummy
            self._cache = None

    def is_valid(self) -> bool:
        """Verifica si hay un PIN válido en cache."""
        return self.get() is not None

    def extend(self, additional_seconds: int | None = None) -> bool:
        """
        Extiende la validez del PIN cacheado.

        Args:
            additional_seconds: Segundos a agregar (default: timeout original)

        Returns:
            True si se extendió, False si no había PIN válido
        """
        with self._lock:
            if self._cache is None or time.time() > self._cache.expires_at:
                return False

            extension = additional_seconds or self._timeout
            self._cache.expires_at = time.time() + extension
            return True

    @property
    def remaining_seconds(self) -> int:
        """Segundos restantes de validez del PIN."""
        with self._lock:
            if self._cache is None:
                return 0
            remaining = self._cache.expires_at - time.time()
            return max(0, int(remaining))


# Singleton global del cache
_pin_cache: PinCache | None = None


def get_pin_cache(timeout_seconds: int = 300) -> PinCache:
    """
    Obtiene la instancia global del cache de PIN.

    Args:
        timeout_seconds: Timeout inicial si se crea nueva instancia

    Returns:
        Instancia singleton de PinCache
    """
    global _pin_cache
    if _pin_cache is None:
        _pin_cache = PinCache(timeout_seconds)
    return _pin_cache


def clear_global_cache() -> None:
    """Limpia el cache global de PIN."""
    global _pin_cache
    if _pin_cache is not None:
        _pin_cache.clear()
