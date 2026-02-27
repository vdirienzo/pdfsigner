"""
mock_nss.py - Mock NSS handler for dry-run mode

Author: Homero Thompson del Lago del Terror

Simulates token operations without real hardware.
"""

import time

from loguru import logger

from pdfsigner.core.mock.mock_certificate import MockCertificate, create_mock_certificate


class MockNSSHandler:
    """
    Mock NSS handler for dry-run mode.

    Simulates all token operations without real hardware.
    """

    def __init__(self):
        """Initializes the mock handler."""
        self._initialized = False
        self._authenticated = False
        self._connected = False
        logger.info("[DRY-RUN] MockNSSHandler created")

    def initialize(self) -> None:
        """Simulates NSS initialization."""
        logger.info("[DRY-RUN] Initializing NSS (simulated)...")
        time.sleep(0.2)  # Simulate latency
        self._initialized = True
        logger.info("[DRY-RUN] NSS initialized successfully")

    def get_available_tokens(self) -> list[str]:
        """Returns simulated tokens."""
        if not self._initialized:
            return []
        return ["SafeNet 5110 (SIMULATED)"]

    def connect_token(self) -> None:
        """Simulates token connection."""
        logger.info("[DRY-RUN] Connecting to simulated token...")
        time.sleep(0.3)
        self._connected = True
        logger.info("[DRY-RUN] Token connected")

    def authenticate(self, pin: str) -> None:
        """
        Simulates PIN authentication.

        Accepts any PIN with 4+ digits.
        """
        logger.info("[DRY-RUN] Authenticating with PIN...")
        time.sleep(0.5)  # Simulate verification

        if len(pin) < 4:
            raise ValueError("[DRY-RUN] PIN must be at least 4 digits")

        self._authenticated = True
        logger.info("[DRY-RUN] Authentication successful")

    def login(self, pin: str) -> None:
        """Alias for authenticate."""
        self.authenticate(pin)

    def is_authenticated(self) -> bool:
        """Checks if authenticated."""
        return self._authenticated

    def get_certificates(self) -> list[MockCertificate]:
        """Returns simulated certificates."""
        if not self._authenticated:
            return []

        return [
            create_mock_certificate("John Smith (TEST)"),
            create_mock_certificate("Jane Doe (TEST)"),
        ]

    def close(self) -> None:
        """Closes the simulated connection."""
        logger.info("[DRY-RUN] Closing token connection...")
        self._authenticated = False
        self._connected = False
        self._initialized = False
