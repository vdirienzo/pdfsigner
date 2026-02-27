"""
credential_manager.py - Remote signing credential management

Manages signing credentials from Qualified Trust Service Providers (QTSPs)
accessed via the CSC API v2 protocol.
"""

import base64
import logging
from dataclasses import dataclass, field

from pdfsigner.core.remote.csc_client import CSCClient, CSCCredentialInfo

logger = logging.getLogger(__name__)


@dataclass
class RemoteCredential:
    """A remote signing credential with parsed certificate info."""

    credential_id: str
    subject_dn: str
    issuer_dn: str
    key_algorithm: str
    key_size: int
    valid_from: str
    valid_to: str
    certificate_der: bytes | None = None
    certificate_chain_der: list[bytes] = field(default_factory=list)
    sign_algorithms: list[str] = field(default_factory=list)
    multisign: int = 1
    scal: str = "1"
    description: str = ""

    @property
    def display_name(self) -> str:
        """Human-readable name from subject DN."""
        # Extract CN from DN
        for part in self.subject_dn.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
        return self.subject_dn or self.credential_id


class RemoteCredentialManager:
    """Manages remote signing credentials from a QTSP.

    Provides methods to list, select, and cache credentials
    from a CSC API v2 compatible service.
    """

    def __init__(self, csc_client: CSCClient):
        self._client = csc_client
        self._credentials: dict[str, RemoteCredential] = {}

    def list_credentials(self) -> list[RemoteCredential]:
        """Fetch and return all available credentials.

        Returns:
            List of RemoteCredential objects
        """
        credential_ids = self._client.list_credentials()
        credentials: list[RemoteCredential] = []

        for cred_id in credential_ids:
            try:
                cred = self.get_credential(cred_id)
                credentials.append(cred)
            except Exception as e:
                logger.warning("Failed to get credential %s: %s", cred_id, e)

        return credentials

    def get_credential(self, credential_id: str) -> RemoteCredential:
        """Get detailed information about a specific credential.

        Args:
            credential_id: CSC credential ID

        Returns:
            RemoteCredential with parsed certificate information
        """
        # Check cache
        if credential_id in self._credentials:
            return self._credentials[credential_id]

        info = self._client.get_credential_info(credential_id)
        credential = self._parse_credential(info)
        self._credentials[credential_id] = credential
        return credential

    def _parse_credential(self, info: CSCCredentialInfo) -> RemoteCredential:
        """Parse CSC credential info into RemoteCredential.

        Args:
            info: Raw CSC credential info

        Returns:
            RemoteCredential with parsed data
        """
        cert_der = None
        chain_der: list[bytes] = []

        for b64_cert in info.certificates:
            try:
                cert_bytes = base64.b64decode(b64_cert)
                if cert_der is None:
                    cert_der = cert_bytes
                chain_der.append(cert_bytes)
            except Exception as e:
                logger.debug("Failed to decode certificate: %s", e)

        return RemoteCredential(
            credential_id=info.credential_id,
            subject_dn=info.subject_dn,
            issuer_dn=info.issuer_dn,
            key_algorithm=info.key_algo,
            key_size=info.key_len,
            valid_from=info.valid_from,
            valid_to=info.valid_to,
            certificate_der=cert_der,
            certificate_chain_der=chain_der,
            sign_algorithms=info.sign_algos,
            multisign=info.multisign,
            scal=info.scal,
            description=info.description,
        )

    def clear_cache(self) -> None:
        """Clear cached credential information."""
        self._credentials.clear()
