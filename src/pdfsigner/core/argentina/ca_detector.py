"""
ca_detector.py - Argentine CA Auto-Detection from PKCS#11 tokens

Author: Homero Thompson del Lago del Terror

Automatically detects if a certificate from a PKCS#11 token is issued by an
Argentine licensed certification authority (CA) under Ley 25.506.

Key features:
- Detect CA from certificates in PKCS#11 tokens
- Return detailed certifier information
- Support for multiple certificates per token
"""

import logging
from dataclasses import dataclass

from pdfsigner.core.argentina.ca_registry import (
    ArgentineCertifier,
    get_argentine_ca_registry,
)
from pdfsigner.core.token.nss_handler import CertificateInfo, NSSHandler
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    TokenAuthenticationError,
)

logger = logging.getLogger(__name__)


@dataclass
class CADetectionResult:
    """Result of Argentine CA detection from token certificate."""

    is_argentine_ca: bool
    certifier: ArgentineCertifier | None
    certificate: CertificateInfo | None
    error: str | None = None


class ArgentineCADetector:
    """Detects Argentine certification authorities from PKCS#11 tokens.

    Automatically identifies if certificates in a token are issued by
    licensed Argentine certifiers under Ley 25.506.
    """

    def __init__(self):
        """Initialize CA detector with registry."""
        self.registry = get_argentine_ca_registry()

    def detect_from_pkcs11(self, token_handler: NSSHandler) -> list[CADetectionResult]:
        """Detect Argentine CAs from all certificates in PKCS#11 token.

        Args:
            token_handler: Initialized and authenticated NSSHandler

        Returns:
            List of CADetectionResult for each certificate found

        Raises:
            TokenAuthenticationError: If token not authenticated
        """
        results: list[CADetectionResult] = []

        try:
            # List all certificates in token
            certificates = token_handler.list_certificates()

            if not certificates:
                logger.warning("No certificates found in token")
                return [
                    CADetectionResult(
                        is_argentine_ca=False,
                        certifier=None,
                        certificate=None,
                        error="No certificates found in token",
                    )
                ]

            # Check each certificate
            for cert_info in certificates:
                result = self._detect_from_certificate(cert_info)
                results.append(result)

        except TokenAuthenticationError as e:
            logger.error(f"Token authentication required: {e}")
            return [
                CADetectionResult(
                    is_argentine_ca=False,
                    certifier=None,
                    certificate=None,
                    error=f"Token authentication required: {str(e)}",
                )
            ]
        except CertificateNotFoundError as e:
            logger.error(f"Certificate not found: {e}")
            return [
                CADetectionResult(
                    is_argentine_ca=False,
                    certifier=None,
                    certificate=None,
                    error=f"Certificate not found: {str(e)}",
                )
            ]
        except Exception as e:
            logger.error(f"Error detecting Argentine CA: {e}")
            return [
                CADetectionResult(
                    is_argentine_ca=False,
                    certifier=None,
                    certificate=None,
                    error=f"Detection error: {str(e)}",
                )
            ]

        return results

    def _detect_from_certificate(self, cert_info: CertificateInfo) -> CADetectionResult:
        """Detect Argentine CA from certificate information.

        Args:
            cert_info: Certificate information from token

        Returns:
            CADetectionResult with detection status and certifier info
        """
        # Look up certifier by issuer DN
        certifier = self.registry.find_certifier_by_issuer(cert_info.issuer)

        if certifier:
            logger.info(f"Certificate '{cert_info.label}' issued by Argentine CA: {certifier.name}")
            return CADetectionResult(
                is_argentine_ca=True,
                certifier=certifier,
                certificate=cert_info,
                error=None,
            )
        else:
            logger.debug(f"Certificate '{cert_info.label}' not issued by recognized Argentine CA")
            return CADetectionResult(
                is_argentine_ca=False,
                certifier=None,
                certificate=cert_info,
                error=None,
            )

    def get_certifier_info(self, result: CADetectionResult) -> dict[str, str]:
        """Get detailed information about detected certifier.

        Args:
            result: CADetectionResult from detection

        Returns:
            Dictionary with certifier details (name, type, cost, website, etc.)
        """
        if not result.is_argentine_ca or result.certifier is None:
            return {
                "status": "not_argentine_ca",
                "message": "Certificate not issued by recognized Argentine CA",
            }

        certifier = result.certifier

        return {
            "status": "argentine_ca_detected",
            "name": certifier.name,
            "type": certifier.certifier_type.value,
            "cost": certifier.cost,
            "website": certifier.website,
            "modality": certifier.modality,
            "description": certifier.description,
            "license_status": certifier.status.value,
        }

    def detect_from_token_label(
        self, token_label: str | None = None, pin: str | None = None
    ) -> list[CADetectionResult]:
        """Convenience method to detect CA from token label.

        Initializes handler, connects to token, authenticates, and detects.

        Args:
            token_label: Token label (None = first available)
            pin: Token PIN (None = skip authentication, useful for dry-run)

        Returns:
            List of CADetectionResult

        Note:
            Does not raise exceptions - returns error in CADetectionResult instead
        """
        handler = NSSHandler()

        try:
            handler.initialize()
            handler.connect_token(token_label)

            if pin:
                handler.authenticate(pin)
            else:
                # For detection without authentication, we need an authenticated session
                logger.warning("PIN not provided - cannot list certificates without authentication")
                return [
                    CADetectionResult(
                        is_argentine_ca=False,
                        certifier=None,
                        certificate=None,
                        error="PIN required to list certificates",
                    )
                ]

            return self.detect_from_pkcs11(handler)

        except TokenAuthenticationError as e:
            logger.error(f"Authentication failed: {e}")
            return [
                CADetectionResult(
                    is_argentine_ca=False,
                    certifier=None,
                    certificate=None,
                    error=f"Authentication failed: {str(e)}",
                )
            ]
        except Exception as e:
            logger.error(f"Error detecting from token: {e}")
            return [
                CADetectionResult(
                    is_argentine_ca=False,
                    certifier=None,
                    certificate=None,
                    error=f"Error: {str(e)}",
                )
            ]
        finally:
            handler.close()


# --- Singleton access ---

_detector: ArgentineCADetector | None = None


def get_ca_detector() -> ArgentineCADetector:
    """Get or create the singleton Argentine CA detector instance.

    Returns:
        ArgentineCADetector singleton instance
    """
    global _detector
    if _detector is None:
        _detector = ArgentineCADetector()
    return _detector
