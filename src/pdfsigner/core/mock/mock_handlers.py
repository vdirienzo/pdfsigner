"""
mock_handlers.py - Mock handlers for dry-run mode

Author: Homero Thompson del Lago del Terror

Simulates token and signing behavior without real hardware.
Useful for testing and demonstration.
"""

import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger


@dataclass
class MockCertificateInfo:
    """Simulated certificate information."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    pkcs11_id: bytes = b"MOCK_CERT_ID"


@dataclass
class MockCertificate:
    """Simulated certificate for dry-run."""

    info: MockCertificateInfo
    display_name: str
    days_until_expiry: int
    is_expiring_soon: bool = False


def create_mock_certificate(name: str = "Test User") -> MockCertificate:
    """
    Creates a mock certificate for testing.

    Args:
        name: Name of the certificate holder

    Returns:
        Simulated certificate
    """
    now = datetime.now()
    info = MockCertificateInfo(
        subject=f"CN={name}, O=Test Organization, C=AR",
        issuer="CN=Test CA, O=Certificate Authority, C=AR",
        serial_number="1234567890ABCDEF",
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=365),
    )

    return MockCertificate(
        info=info,
        display_name=name,
        days_until_expiry=365,
        is_expiring_soon=False,
    )


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
            create_mock_certificate("Juan Pérez (TEST)"),
            create_mock_certificate("María García (TEST)"),
        ]

    def close(self) -> None:
        """Closes the simulated connection."""
        logger.info("[DRY-RUN] Closing token connection...")
        self._authenticated = False
        self._connected = False
        self._initialized = False


@dataclass
class MockBatchProgress:
    """Simulated batch signing progress (compatible with BatchProgress)."""

    current: int
    total: int
    current_file: str
    status: str
    message: str = ""

    @property
    def completed(self) -> int:
        """Successfully completed files (for BatchProgress compatibility)."""
        return self.current if self.status == "success" else max(0, self.current - 1)

    @property
    def failed(self) -> int:
        """Failed files (for BatchProgress compatibility)."""
        return 0  # In dry-run there are no failures during progress


@dataclass
class MockBatchResult:
    """Simulated batch signing result."""

    successful: int
    failed: int
    all_successful: bool
    errors: dict[Path, str]

    def get_failed_files(self):
        """Returns failed files."""
        return list(self.errors.items())


class MockBatchManager:
    """
    Simulated batch signing manager.

    Simulates the signing process by copying files
    with _signed suffix without modifying content.
    """

    def __init__(self, nss_handler=None, lta_handler=None):
        """Initializes the mock manager."""
        self.nss_handler = nss_handler
        self.lta_handler = lta_handler
        logger.info("[DRY-RUN] MockBatchManager created")

    def sign_batch(
        self,
        files: list[Path] | None = None,
        pdf_files: list[Path] | None = None,
        pin: str | None = None,
        visible: bool = False,
        page: str | int = "last",
        appearance=None,
        cert_id: bytes | None = None,
        progress_callback=None,
    ) -> MockBatchResult:
        """
        Simulates batch file signing.

        Copies each PDF with _signed suffix simulating the process.

        Args:
            files: List of files (alias)
            pdf_files: List of files
            pin: PIN (ignored in mock)
            visible: Visible signature
            page: Page for visible signature
            appearance: Appearance configuration
            cert_id: Certificate ID
            progress_callback: Progress callback

        Returns:
            Simulated signing result
        """
        # Support both parameter names
        file_list = files or pdf_files or []

        if not file_list:
            return MockBatchResult(successful=0, failed=0, all_successful=True, errors={})

        total = len(file_list)
        successful = 0
        failed = 0
        errors = {}

        logger.info(f"[DRY-RUN] Simulating signing of {total} file(s)...")

        for i, pdf_path in enumerate(file_list):
            current_file = str(pdf_path)

            # Notify start
            if progress_callback:
                progress = MockBatchProgress(
                    current=i + 1,
                    total=total,
                    current_file=current_file,
                    status="processing",
                    message="Signing...",
                )
                progress_callback(progress)

            # Simulate signing time
            time.sleep(0.5)

            try:
                # Create "signed" file (copy with suffix)
                output_path = pdf_path.parent / f"{pdf_path.stem}_signed{pdf_path.suffix}"
                shutil.copy2(pdf_path, output_path)

                logger.info(f"[DRY-RUN] Signed: {pdf_path.name} → {output_path.name}")
                successful += 1

                # Notify success
                if progress_callback:
                    progress = MockBatchProgress(
                        current=i + 1,
                        total=total,
                        current_file=current_file,
                        status="success",
                        message="Signed (simulated)",
                    )
                    progress_callback(progress)

            except Exception as e:
                logger.error(f"[DRY-RUN] Error copying {pdf_path}: {e}")
                failed += 1
                errors[pdf_path] = str(e)

                if progress_callback:
                    progress = MockBatchProgress(
                        current=i + 1,
                        total=total,
                        current_file=current_file,
                        status="error",
                        message=str(e),
                    )
                    progress_callback(progress)

        logger.info(f"[DRY-RUN] Signing completed: {successful} success, {failed} failed")

        return MockBatchResult(
            successful=successful,
            failed=failed,
            all_successful=(failed == 0),
            errors=errors,
        )


def enable_dry_run_mode():
    """
    Enables dry-run mode globally.

    Modifies the setting so that components
    use mock implementations automatically.
    """
    import os

    # Settings is immutable, use environment variable
    os.environ["PDFSIGNER_DRY_RUN"] = "true"
    logger.warning("⚠️  DRY-RUN MODE ACTIVATED - No real signing")
