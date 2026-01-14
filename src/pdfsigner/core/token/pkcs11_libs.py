"""
pkcs11_libs.py - PKCS#11 library paths configuration

Author: Homero Thompson del Lago del Terror

Defines library paths for various PKCS#11 token vendors.
Paths are ordered by priority (first found is used).

Supported tokens:
- SafeNet/Thales eToken (5110, 5300, Luna HSM)
- YubiKey (PIV mode)
- Nitrokey Pro/HSM
- OpenSC (generic smart cards)
- Feitian ePass
- SoftHSM (testing)
- nCipher/Entrust HSM
- Generic NSS (fallback)
"""

# ==========================================================================
# SafeNet/Thales eToken (5110, 5300, Luna HSM)
# ==========================================================================
SAFENET_LIB_PATHS = [
    "/usr/lib/libeToken.so",
    "/usr/lib/x86_64-linux-gnu/libeToken.so",
    "/usr/lib64/libeToken.so",
    "/opt/safenet/lunaclient/lib/libCryptoki2_64.so",  # Luna HSM
    "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
]

# ==========================================================================
# YubiKey (PIV mode)
# ==========================================================================
YUBIKEY_LIB_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/lib/libykcs11.so",
    "/usr/lib64/libykcs11.so",
    "/usr/local/lib/libykcs11.so",
]

# ==========================================================================
# Nitrokey Pro/HSM
# ==========================================================================
NITROKEY_LIB_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libnethsm.so",
    "/usr/lib/libnethsm.so",
    "/usr/lib/x86_64-linux-gnu/libnitrokey.so",
    "/usr/lib/libnitrokey.so",
]

# ==========================================================================
# OpenSC (generic smart cards)
# ==========================================================================
OPENSC_LIB_PATHS = [
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
]

# ==========================================================================
# Feitian ePass
# ==========================================================================
FEITIAN_LIB_PATHS = [
    "/usr/lib/libcastle.so",
    "/usr/lib/x86_64-linux-gnu/libcastle.so",
    "/usr/lib/libftsafe-p11.so",
]

# ==========================================================================
# SoftHSM (software HSM for testing)
# ==========================================================================
SOFTHSM_LIB_PATHS = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
]

# ==========================================================================
# nCipher/Entrust HSM
# ==========================================================================
NCIPHER_LIB_PATHS = [
    "/opt/nfast/toolkits/pkcs11/libcknfast.so",
    "/usr/lib/libcknfast.so",
]

# ==========================================================================
# Generic NSS libraries (fallback)
# ==========================================================================
NSS_LIB_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libnssckbi.so",
    "/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
    "/usr/lib/libnssckbi.so",
    "/usr/lib/libsoftokn3.so",
    "/usr/lib64/libnssckbi.so",
    "/usr/lib64/libsoftokn3.so",
]

# ==========================================================================
# Search order for library discovery (priority order)
# ==========================================================================
PKCS11_LIB_GROUPS = [
    ("SafeNet/Thales", SAFENET_LIB_PATHS),
    ("YubiKey", YUBIKEY_LIB_PATHS),
    ("Nitrokey", NITROKEY_LIB_PATHS),
    ("OpenSC", OPENSC_LIB_PATHS),
    ("Feitian", FEITIAN_LIB_PATHS),
    ("SoftHSM", SOFTHSM_LIB_PATHS),
    ("nCipher", NCIPHER_LIB_PATHS),
    ("NSS", NSS_LIB_PATHS),
]
