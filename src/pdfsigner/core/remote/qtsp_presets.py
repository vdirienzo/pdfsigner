"""
qtsp_presets.py - Pre-configured Qualified Trust Service Providers

Common QTSP configurations for remote signing via CSC API v2.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class QTSPPreset:
    """Pre-configured QTSP settings."""

    name: str
    country: str
    service_url: str
    authorize_url: str
    token_url: str
    client_id: str = ""  # Must be obtained from QTSP
    description: str = ""


# Known QTSPs with CSC API support
QTSP_PRESETS: dict[str, QTSPPreset] = {
    "swisscom": QTSPPreset(
        name="Swisscom Trust Services",
        country="CH",
        service_url="https://ais.swisscom.com/AIS-Server/rs/v1.0",
        authorize_url="https://ais.swisscom.com/oauth2/authorize",
        token_url="https://ais.swisscom.com/oauth2/token",
        description="Swisscom All-in Signing Service (Swiss QTSP)",
    ),
    "infocert": QTSPPreset(
        name="InfoCert",
        country="IT",
        service_url="https://signing.infocert.digital/csc/v2",
        authorize_url="https://signing.infocert.digital/oauth2/authorize",
        token_url="https://signing.infocert.digital/oauth2/token",
        description="InfoCert Remote Qualified Electronic Signature (Italian QTSP)",
    ),
    "a-trust": QTSPPreset(
        name="A-Trust",
        country="AT",
        service_url="https://esign.a-trust.at/csc/v2",
        authorize_url="https://esign.a-trust.at/oauth2/authorize",
        token_url="https://esign.a-trust.at/oauth2/token",
        description="A-Trust Qualified Signature Service (Austrian QTSP)",
    ),
    "custom": QTSPPreset(
        name="Custom QTSP",
        country="",
        service_url="",
        authorize_url="",
        token_url="",
        description="Custom QTSP configuration",
    ),
}


def get_preset(name: str) -> QTSPPreset | None:
    """Get a QTSP preset by name."""
    return QTSP_PRESETS.get(name.lower())


def list_presets() -> list[QTSPPreset]:
    """Get all available QTSP presets."""
    return [p for name, p in QTSP_PRESETS.items() if name != "custom"]
