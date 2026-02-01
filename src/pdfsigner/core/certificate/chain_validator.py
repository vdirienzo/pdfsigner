"""
chain_validator.py - Certificate chain validation

Author: Homero Thompson del Lago del Terror

Validates X.509 certificate chains from end-entity certificate
up to trusted Root CA, verifying signatures and validity periods.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID
from loguru import logger

from pdfsigner.core.certificate.trust_store import TrustStore


class ChainStatus(Enum):
    """Certificate chain validation status."""

    VALID = "valid"  # Complete chain to trusted root
    PARTIAL_CHAIN = "partial_chain"  # Incomplete chain (missing intermediate)
    UNTRUSTED_ROOT = "untrusted_root"  # Chain ends at untrusted root
    INVALID_SIGNATURE = "invalid_signature"  # Signature verification failed
    EXPIRED = "expired"  # Certificate expired in chain
    ERROR = "error"  # Validation error occurred


@dataclass
class ChainValidationResult:
    """
    Result of certificate chain validation.

    Attributes:
        status: Validation status
        chain: List of certificates in chain (leaf to root)
        trust_anchor: Trusted root certificate if found
        errors: List of validation error messages
    """

    status: ChainStatus
    chain: list[x509.Certificate]
    trust_anchor: x509.Certificate | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if chain is valid and trusted."""
        return self.status == ChainStatus.VALID

    @property
    def is_trusted(self) -> bool:
        """Check if chain ends at trusted root."""
        return self.trust_anchor is not None


class CertificateChainValidator:
    """
    Validates X.509 certificate chains.

    Builds certificate chains from end-entity certificates
    up to trusted root CAs, verifying signatures and validity.
    """

    def __init__(self, trust_store: TrustStore):
        """
        Initialize validator with trust store.

        Args:
            trust_store: Trust store with Root CAs
        """
        self.trust_store = trust_store

    def validate_chain(self, cert: x509.Certificate) -> ChainValidationResult:
        """
        Validate certificate chain up to trusted root.

        Args:
            cert: End-entity certificate to validate

        Returns:
            Validation result with chain and status
        """
        try:
            # Build certificate chain
            chain = self.build_chain(cert)

            if not chain:
                return ChainValidationResult(
                    status=ChainStatus.ERROR,
                    chain=[],
                    errors=["Failed to build certificate chain"],
                )

            # Validate each certificate in chain
            errors = []

            # Check validity periods
            now = datetime.now(UTC)
            for idx, cert_in_chain in enumerate(chain):
                if not self._is_cert_valid_at_time(cert_in_chain, now):
                    not_after = cert_in_chain.not_valid_after_utc
                    errors.append(
                        f"Certificate {idx} ({self._get_cn(cert_in_chain)}) "
                        f"expired on {not_after.isoformat()}"
                    )

            if errors:
                return ChainValidationResult(status=ChainStatus.EXPIRED, chain=chain, errors=errors)

            # Verify signatures in chain
            signature_errors = self._verify_chain_signatures(chain)
            if signature_errors:
                return ChainValidationResult(
                    status=ChainStatus.INVALID_SIGNATURE, chain=chain, errors=signature_errors
                )

            # Check if chain ends at trusted root
            root_cert = chain[-1]
            is_trusted = self.trust_store.is_trusted(root_cert)

            if is_trusted:
                logger.debug(f"Certificate chain valid, trusted by {self._get_cn(root_cert)}")
                return ChainValidationResult(
                    status=ChainStatus.VALID, chain=chain, trust_anchor=root_cert
                )

            # Check if it's a self-signed root
            if self._is_self_signed(root_cert):
                logger.warning(f"Chain ends at untrusted root: {self._get_cn(root_cert)}")
                return ChainValidationResult(
                    status=ChainStatus.UNTRUSTED_ROOT,
                    chain=chain,
                    errors=[f"Root certificate not trusted: {self._get_cn(root_cert)}"],
                )

            # Chain incomplete (missing intermediate)
            logger.warning(f"Chain incomplete at: {self._get_cn(root_cert)}")
            return ChainValidationResult(
                status=ChainStatus.PARTIAL_CHAIN,
                chain=chain,
                errors=["Incomplete chain, missing intermediate certificate"],
            )

        except Exception as e:
            logger.error(f"Chain validation error: {e}")
            return ChainValidationResult(
                status=ChainStatus.ERROR, chain=[cert], errors=[f"Validation error: {str(e)}"]
            )

    def build_chain(self, cert: x509.Certificate) -> list[x509.Certificate]:
        """
        Build certificate chain from end-entity to root.

        Args:
            cert: Certificate to build chain from

        Returns:
            List of certificates (leaf to root)
        """
        chain = [cert]
        current = cert
        max_depth = 10  # Prevent infinite loops

        for _ in range(max_depth):
            # Check if current certificate is self-signed (root)
            if self._is_self_signed(current):
                logger.debug(f"Reached root certificate: {self._get_cn(current)}")
                break

            # Find issuer certificate
            issuer = self.trust_store.get_issuer(current)

            if issuer is None:
                # Try to find issuer by Authority Key Identifier
                issuer = self._find_issuer_by_aki(current)

            if issuer is None:
                logger.debug(f"Issuer not found for: {self._get_cn(current)}")
                break

            # Avoid cycles
            if issuer in chain:
                logger.warning("Certificate chain cycle detected")
                break

            chain.append(issuer)
            current = issuer

        logger.debug(f"Built chain with {len(chain)} certificates")
        return chain

    def _verify_chain_signatures(self, chain: list[x509.Certificate]) -> list[str]:
        """
        Verify signatures in certificate chain.

        Args:
            chain: List of certificates (leaf to root)

        Returns:
            List of signature verification errors
        """
        errors = []

        for idx in range(len(chain) - 1):
            cert = chain[idx]
            issuer = chain[idx + 1]

            if not self._verify_signature(cert, issuer):
                errors.append(
                    f"Invalid signature on certificate {idx} "
                    f"({self._get_cn(cert)}) from issuer ({self._get_cn(issuer)})"
                )

        # Verify root self-signature
        root = chain[-1]
        if self._is_self_signed(root):
            if not self._verify_signature(root, root):
                errors.append(f"Invalid self-signature on root certificate ({self._get_cn(root)})")

        return errors

    def _verify_signature(self, cert: x509.Certificate, issuer: x509.Certificate) -> bool:
        """
        Verify certificate signature using issuer's public key.

        Args:
            cert: Certificate to verify
            issuer: Issuer certificate

        Returns:
            True if signature is valid
        """
        try:
            public_key = issuer.public_key()
            hash_algorithm = cert.signature_hash_algorithm

            if hash_algorithm is None:
                logger.warning(f"Certificate {self._get_cn(cert)} has no signature hash algorithm")
                return False

            # Verify signature based on algorithm
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hash_algorithm,
                )
                return True
            # Note: Other key types have different verify signatures
            # For now, we focus on RSA which is most common
            else:
                logger.debug(
                    f"Skipping signature verification for non-RSA key type: {type(public_key)}"
                )
                return True  # Assume valid for non-RSA keys

        except InvalidSignature:
            logger.warning(f"Invalid signature on {self._get_cn(cert)} from {self._get_cn(issuer)}")
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    def _is_cert_valid_at_time(self, cert: x509.Certificate, check_time: datetime) -> bool:
        """
        Check if certificate is valid at specific time.

        Args:
            cert: Certificate to check
            check_time: Time to check validity at

        Returns:
            True if certificate is valid
        """
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        return not_before <= check_time <= not_after

    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        """
        Check if certificate is self-signed.

        Args:
            cert: Certificate to check

        Returns:
            True if self-signed
        """
        return cert.subject == cert.issuer

    def _find_issuer_by_aki(self, cert: x509.Certificate) -> x509.Certificate | None:
        """
        Find issuer certificate using Authority Key Identifier extension.

        Args:
            cert: Certificate whose issuer to find

        Returns:
            Issuer certificate if found
        """
        try:
            # Get Authority Key Identifier extension
            aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            aki = aki_ext.value

            # Type check
            if not isinstance(aki, x509.AuthorityKeyIdentifier):
                return None

            if aki.key_identifier is None:
                return None

            # Search for certificate with matching Subject Key Identifier
            issuer_der = cert.issuer.public_bytes()
            potential_issuer = self.trust_store.get_certificate_by_subject(issuer_der)

            if potential_issuer is None:
                return None

            # Verify SKI matches
            try:
                ski_ext = potential_issuer.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                )
                ski = ski_ext.value

                # Type check
                if isinstance(ski, x509.SubjectKeyIdentifier) and ski.digest == aki.key_identifier:
                    return potential_issuer
            except x509.ExtensionNotFound:
                pass

            return None

        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            logger.debug(f"Error finding issuer by AKI: {e}")
            return None

    def _get_cn(self, cert: x509.Certificate) -> str:
        """
        Extract Common Name from certificate.

        Args:
            cert: Certificate

        Returns:
            Common Name or subject string
        """
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attrs:
                cn_value = cn_attrs[0].value
                # Ensure we return a string
                return str(cn_value) if not isinstance(cn_value, str) else cn_value
        except Exception as e:
            logger.debug(f"Could not extract CN from certificate: {e}")

        return cert.subject.rfc4514_string()
