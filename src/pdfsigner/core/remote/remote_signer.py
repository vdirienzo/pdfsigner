"""
remote_signer.py - Bridge between CSC API v2 and pyHanko signing pipeline

Adapts the CSC API v2 client to work as a pyHanko Signer, enabling
remote qualified electronic signatures through QTSPs.

The signing pipeline remains the same:
  prep → fields → stamps → sign(REMOTE) → DSS(local) → archive_TS(local)

Only phase 4 (sign) changes: instead of PKCS#11 local signing,
the hash is sent to a remote QTSP via CSC API.
"""

import base64
import logging
from dataclasses import dataclass

from pdfsigner.core.remote.csc_client import CSCClient, CSCError

logger = logging.getLogger(__name__)


@dataclass
class RemoteSigningConfig:
    """Configuration for remote signing via CSC API."""

    service_url: str
    credential_id: str
    access_token: str
    sign_algo: str = "1.2.840.113549.1.1.11"  # sha256WithRSA default
    pin: str | None = None
    otp: str | None = None
    timeout: int = 30
    verify_ssl: bool = True


class RemoteSigningError(Exception):
    """Error during remote signing operation."""

    pass


def create_remote_signer(config: RemoteSigningConfig) -> "RemoteHashSigner":
    """Create a remote signer from configuration.

    Args:
        config: Remote signing configuration

    Returns:
        RemoteHashSigner ready for use in signing pipeline
    """
    client = CSCClient(
        service_url=config.service_url,
        timeout=config.timeout,
        verify_ssl=config.verify_ssl,
    )
    client.set_access_token(config.access_token)

    return RemoteHashSigner(
        client=client,
        credential_id=config.credential_id,
        sign_algo=config.sign_algo,
        pin=config.pin,
        otp=config.otp,
    )


class RemoteHashSigner:
    """Signs document hashes via CSC API v2.

    This is NOT a pyHanko Signer subclass (pyHanko's signer interface
    is tightly coupled to PKCS#11/local crypto). Instead, this provides
    a sign_hash() method that can be called after the PDF hash is computed.

    Usage in the signing pipeline:
    1. PDFSigner prepares the PDF and computes the hash (phases 1-3)
    2. RemoteHashSigner sends the hash to the QTSP and gets the signature
    3. PDFSigner embeds the signature and adds DSS/archive TS (phases 5-6)
    """

    def __init__(
        self,
        client: CSCClient,
        credential_id: str,
        sign_algo: str = "1.2.840.113549.1.1.11",
        pin: str | None = None,
        otp: str | None = None,
    ):
        self.client = client
        self.credential_id = credential_id
        self.sign_algo = sign_algo
        self.pin = pin
        self.otp = otp
        self._sad: str | None = None

    def get_certificate_chain(self) -> list[bytes]:
        """Retrieve signing certificate chain from QTSP.

        Returns:
            List of DER-encoded certificates (leaf first)
        """
        try:
            info = self.client.get_credential_info(self.credential_id)
            chain = []
            for b64_cert in info.certificates:
                chain.append(base64.b64decode(b64_cert))
            return chain
        except CSCError as e:
            raise RemoteSigningError(f"Failed to get certificates: {e}") from e

    def authorize(self, num_signatures: int = 1) -> str:
        """Authorize signing operation (may require PIN/OTP).

        Args:
            num_signatures: Number of signatures to authorize

        Returns:
            SAD (Signature Activation Data) token
        """
        try:
            result = self.client.authorize_credential(
                credential_id=self.credential_id,
                num_signatures=num_signatures,
                pin=self.pin,
                otp=self.otp,
            )
            self._sad = result.sad
            if not self._sad:
                raise RemoteSigningError("Authorization returned empty SAD")
            logger.info("Remote signing authorized (expires in %ds)", result.expires_in)
            return self._sad
        except CSCError as e:
            raise RemoteSigningError(f"Authorization failed: {e}") from e

    def sign_hash(self, hash_value: bytes) -> bytes:
        """Sign a document hash via QTSP.

        Args:
            hash_value: Raw hash bytes to sign

        Returns:
            Raw signature bytes

        Raises:
            RemoteSigningError: If signing fails
        """
        if not self._sad:
            self.authorize()

        try:
            b64_hash = base64.b64encode(hash_value).decode()
            result = self.client.sign_hash(
                credential_id=self.credential_id,
                sad=self._sad,
                hashes=[b64_hash],
                sign_algo=self.sign_algo,
            )

            if not result.signatures:
                raise RemoteSigningError("QTSP returned no signatures")

            return base64.b64decode(result.signatures[0])
        except CSCError as e:
            raise RemoteSigningError(f"Remote signing failed: {e}") from e

    def sign_batch(self, hash_values: list[bytes]) -> list[bytes]:
        """Sign multiple document hashes in one batch.

        Args:
            hash_values: List of raw hash bytes

        Returns:
            List of raw signature bytes (same order)
        """
        if not self._sad:
            self.authorize(num_signatures=len(hash_values))

        try:
            b64_hashes = [base64.b64encode(h).decode() for h in hash_values]
            signatures = self.client.sign_batch(
                credential_id=self.credential_id,
                sad=self._sad,
                hashes=b64_hashes,
                sign_algo=self.sign_algo,
            )
            return [base64.b64decode(s) for s in signatures]
        except CSCError as e:
            raise RemoteSigningError(f"Batch signing failed: {e}") from e
