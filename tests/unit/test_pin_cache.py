"""
test_pin_cache.py - Tests para PinCache

Autor: Homero Thompson del Lago del Terror
"""

import time

from pdfsigner.core.token.pin_cache import PinCache, clear_global_cache, get_pin_cache


class TestPinCache:
    """Tests para la clase PinCache."""

    def test_store_and_get(self):
        """Test almacenar y recuperar PIN."""
        cache = PinCache(timeout_seconds=60)
        cache.store("1234")

        assert cache.get() == "1234"
        assert cache.is_valid()

    def test_expiration(self):
        """Test que el PIN expira después del timeout."""
        cache = PinCache(timeout_seconds=1)
        cache.store("1234")

        assert cache.get() == "1234"

        # Esperar a que expire
        time.sleep(1.5)

        assert cache.get() is None
        assert not cache.is_valid()

    def test_clear(self):
        """Test limpiar el cache."""
        cache = PinCache(timeout_seconds=60)
        cache.store("1234")

        assert cache.is_valid()

        cache.clear()

        assert not cache.is_valid()
        assert cache.get() is None

    def test_extend(self):
        """Test extender validez del PIN."""
        cache = PinCache(timeout_seconds=2)
        cache.store("1234")

        time.sleep(1)
        assert cache.extend(additional_seconds=5)

        # El PIN debería seguir válido después del timeout original
        time.sleep(1.5)
        assert cache.get() == "1234"

    def test_extend_expired_returns_false(self):
        """Test que extend retorna False si el PIN expiró."""
        cache = PinCache(timeout_seconds=1)
        cache.store("1234")

        time.sleep(1.5)

        assert not cache.extend()

    def test_remaining_seconds(self):
        """Test cálculo de segundos restantes."""
        cache = PinCache(timeout_seconds=10)
        cache.store("1234")

        remaining = cache.remaining_seconds
        assert 8 <= remaining <= 10

    def test_remaining_seconds_expired(self):
        """Test segundos restantes cuando está expirado."""
        cache = PinCache(timeout_seconds=1)
        cache.store("1234")

        time.sleep(1.5)

        assert cache.remaining_seconds == 0


class TestGlobalCache:
    """Tests para el cache global."""

    def test_get_pin_cache_singleton(self):
        """Test que get_pin_cache retorna singleton."""
        clear_global_cache()

        cache1 = get_pin_cache()
        cache2 = get_pin_cache()

        assert cache1 is cache2

    def test_clear_global_cache(self):
        """Test limpiar cache global."""
        cache = get_pin_cache()
        cache.store("1234")

        clear_global_cache()

        # El cache debería estar limpio pero la instancia es la misma
        # hasta que se solicite una nueva
        assert cache.get() is None
