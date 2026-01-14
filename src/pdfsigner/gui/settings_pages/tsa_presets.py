"""
tsa_presets.py - TSA URL presets

Author: Homero Thompson del Lago del Terror

Predefined TSA server URLs and utilities.
"""

# TSA preset URLs mapping
TSA_PRESETS = {
    0: "",  # Local time (no TSA)
    1: "https://freetsa.org/tsr",
    2: "http://timestamp.digicert.com",
    3: "http://timestamp.sectigo.com",
    4: "http://timestamp.globalsign.com/tsa/r6advanced1",
    5: "http://tsa.izenpe.com",
    6: "",  # Custom URL - keep current
}

# Preset names for display
TSA_PRESET_NAMES = [
    "Local time (no TSA)",
    "FreeTSA (freetsa.org)",
    "DigiCert",
    "Sectigo",
    "GlobalSign",
    "Izenpe (Basque Country)",
    "Custom URL",
]
