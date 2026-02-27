"""Test PAdESLevel enum consolidation (DRY).

Verifies that api.schemas.common.PAdESLevel and
core.validator.pdf_validator.PAdESLevel are the SAME object,
not duplicated enums.
"""

from pdfsigner.api.schemas.common import PAdESLevel as APIPAdESLevel
from pdfsigner.core.validator.pdf_validator import PAdESLevel as CorePAdESLevel


class TestPAdESLevelIdentity:
    """Verify PAdESLevel is a single source of truth."""

    def test_api_pades_level_is_core_pades_level(self):
        """API PAdESLevel must be the exact same class as core PAdESLevel."""
        assert APIPAdESLevel is CorePAdESLevel

    def test_api_schemas_package_reexports_core_pades_level(self):
        """api.schemas re-exports the same PAdESLevel from core."""
        from pdfsigner.api.schemas import PAdESLevel as SchemaPAdESLevel

        assert SchemaPAdESLevel is CorePAdESLevel

    def test_pades_level_has_unknown_member(self):
        """Core PAdESLevel includes UNKNOWN (superset of old API enum)."""
        assert hasattr(CorePAdESLevel, "UNKNOWN")
        assert CorePAdESLevel.UNKNOWN.value == "unknown"

    def test_pades_level_has_all_api_members(self):
        """Core PAdESLevel has all members that the old API enum had."""
        expected = {"B_B", "B_T", "B_LT", "B_LTA"}
        actual = {m.name for m in APIPAdESLevel}
        assert expected.issubset(actual)
