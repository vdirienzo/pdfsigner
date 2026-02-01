"""
presets.py - Configuration presets for PDFSigner

Author: Homero Thompson del Lago del Terror

Provides pre-configured settings bundles for specific compliance scenarios.
Currently includes Argentina (Ley 25.506) preset optimized for legal validity.
"""

from dataclasses import dataclass
from typing import Any

from loguru import logger


@dataclass
class ConfigPreset:
    """
    Configuration preset with metadata and settings.

    Attributes:
        name: Preset identifier (e.g., "argentina")
        display_name: Human-readable name for UI
        description: Preset description explaining its purpose
        settings: Dictionary of setting_name -> value pairs
    """

    name: str
    display_name: str
    description: str
    settings: dict[str, Any]


# --- Preset Definitions ---

ARGENTINA_PRESET = ConfigPreset(
    name="argentina",
    display_name="Argentina (Ley 25.506)",
    description=(
        "Configuración optimizada para cumplimiento de Ley 25.506 (firma digital argentina). "
        "Habilita validación PAdES B-LT/LTA y modo FIPS para máxima compatibilidad legal."
    ),
    settings={
        # Argentina compliance
        "argentine_compliance_enabled": True,
        "argentine_strict_mode": False,  # Recommended: allow other valid certificates too
        # LTV (PAdES B-LT) - required for long-term validation
        "ltv_enabled": True,
        "ltv_fail_open": True,  # Don't block if LTV fails (signature still valid)
        "ltv_prefer_ocsp": True,
        # Archive timestamps (PAdES B-LTA) - recommended for legal documents
        "archive_ts_enabled": True,
        "archive_ts_auto": False,  # Manual control recommended
        # FIPS cryptography - aligns with Argentine standards
        "fips_mode_enabled": True,
        "fips_strict_mode": False,  # Warning mode (don't block operations)
        # Audit trail - important for legal evidence
        "audit_enabled": True,
        "audit_retention_days": 365,  # Keep 1 year of logs
    },
)

# Registry of all available presets
PRESETS: dict[str, ConfigPreset] = {
    "argentina": ARGENTINA_PRESET,
}


class PresetManager:
    """
    Manages configuration presets for PDFSigner.

    Allows applying predefined configuration bundles and retrieving preset metadata.
    """

    def __init__(self) -> None:
        """Initialize preset manager with available presets."""
        self._presets = PRESETS.copy()

    def list_presets(self) -> list[ConfigPreset]:
        """
        Get all available presets.

        Returns:
            List of ConfigPreset objects with metadata and settings
        """
        return list(self._presets.values())

    def get_preset(self, name: str) -> ConfigPreset | None:
        """
        Get specific preset by name.

        Args:
            name: Preset identifier (e.g., "argentina")

        Returns:
            ConfigPreset object or None if not found
        """
        return self._presets.get(name)

    def apply_preset(self, name: str, target_settings: Any) -> bool:
        """
        Apply preset to settings object.

        Args:
            name: Preset identifier (e.g., "argentina")
            target_settings: Settings object to modify (must have matching attributes)

        Returns:
            True if preset applied successfully, False if preset not found

        Example:
            >>> from pdfsigner.config.settings import get_settings
            >>> manager = PresetManager()
            >>> settings = get_settings()
            >>> manager.apply_preset("argentina", settings)
            True
        """
        preset = self.get_preset(name)
        if preset is None:
            logger.warning(f"Preset '{name}' not found")
            return False

        logger.info(f"Applying preset: {preset.display_name}")

        # Apply each setting from preset
        applied_count = 0
        for setting_name, value in preset.settings.items():
            if hasattr(target_settings, setting_name):
                setattr(target_settings, setting_name, value)
                applied_count += 1
                logger.debug(f"  {setting_name} = {value}")
            else:
                logger.warning(f"  Setting '{setting_name}' not found in target object")

        logger.info(f"Applied {applied_count}/{len(preset.settings)} settings from preset")
        return True

    def get_preset_diff(self, name: str, current_settings: Any) -> dict[str, tuple[Any, Any]]:
        """
        Get differences between preset and current settings.

        Args:
            name: Preset identifier
            current_settings: Settings object to compare against

        Returns:
            Dict mapping setting_name -> (current_value, preset_value)
            Empty dict if preset not found

        Example:
            >>> manager = PresetManager()
            >>> diff = manager.get_preset_diff("argentina", settings)
            >>> diff
            {'ltv_enabled': (False, True), 'fips_mode_enabled': (False, True)}
        """
        preset = self.get_preset(name)
        if preset is None:
            return {}

        diff: dict[str, tuple[Any, Any]] = {}

        for setting_name, preset_value in preset.settings.items():
            if hasattr(current_settings, setting_name):
                current_value = getattr(current_settings, setting_name)
                if current_value != preset_value:
                    diff[setting_name] = (current_value, preset_value)

        return diff


# Singleton instance
_preset_manager: PresetManager | None = None


def get_preset_manager() -> PresetManager:
    """
    Get singleton PresetManager instance.

    Returns:
        Shared PresetManager instance
    """
    global _preset_manager
    if _preset_manager is None:
        _preset_manager = PresetManager()
    return _preset_manager
