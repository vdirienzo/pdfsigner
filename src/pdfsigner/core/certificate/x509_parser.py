"""
x509_parser.py - X.509 certificate parser

Author: Homero Thompson del Lago del Terror

Parses X.509 certificates and extracts detailed information
including extensions, key usage, policies, and more.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class X509Details:
    """
    Detailed information extracted from an X.509 certificate.

    Contains all relevant fields including subject, issuer, validity,
    extensions, key information, and thumbprints.
    """

    # Subject and Issuer
    subject_dn: dict[str, str]
    issuer_dn: dict[str, str]

    # Serial Number
    serial_number: str  # Hexadecimal
    serial_number_decimal: str

    # Validity Period
    not_before: datetime
    not_after: datetime

    # Key Usage
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)

    # Subject Alternative Names
    subject_alt_names: list[str] = field(default_factory=list)

    # CRL and OCSP
    crl_distribution_points: list[str] = field(default_factory=list)
    ocsp_responders: list[str] = field(default_factory=list)

    # Certificate Policies
    certificate_policies: list[dict[str, str]] = field(default_factory=list)

    # Thumbprints (Fingerprints)
    thumbprint_sha256: str = ""
    thumbprint_sha1: str = ""

    # Public Key Information
    public_key_algorithm: str = ""
    public_key_size: int = 0
    signature_algorithm: str = ""

    # All Extensions (for advanced view)
    all_extensions: list[dict[str, str]] = field(default_factory=list)


class X509Parser:
    """
    X.509 certificate parser.

    Parses DER-encoded certificates and extracts all relevant
    information into a structured format.
    """

    @staticmethod
    def parse(cert_bytes: bytes) -> X509Details:
        """
        Parse a DER-encoded certificate.

        Args:
            cert_bytes: Certificate in DER format

        Returns:
            X509Details with all parsed information

        Raises:
            ValueError: If certificate cannot be parsed
        """
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse certificate: {e}") from e

        return X509Parser._extract_details(cert, cert_bytes)

    @staticmethod
    def _extract_details(cert: x509.Certificate, cert_bytes: bytes) -> X509Details:
        """Extract all details from a certificate object."""
        return X509Details(
            subject_dn=X509Parser._extract_dn(cert.subject),
            issuer_dn=X509Parser._extract_dn(cert.issuer),
            serial_number=format(cert.serial_number, "x").upper(),
            serial_number_decimal=str(cert.serial_number),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            key_usage=X509Parser._extract_key_usage(cert),
            extended_key_usage=X509Parser._extract_extended_key_usage(cert),
            subject_alt_names=X509Parser._extract_subject_alt_names(cert),
            crl_distribution_points=X509Parser._extract_crl_distribution_points(cert),
            ocsp_responders=X509Parser._extract_ocsp_responders(cert),
            certificate_policies=X509Parser._extract_certificate_policies(cert),
            thumbprint_sha256=X509Parser._compute_thumbprint(cert_bytes, hashes.SHA256()),
            thumbprint_sha1=X509Parser._compute_thumbprint(cert_bytes, hashes.SHA1()),
            public_key_algorithm=X509Parser._extract_public_key_algorithm(cert),
            public_key_size=X509Parser._extract_public_key_size(cert),
            signature_algorithm=X509Parser._extract_signature_algorithm(cert),
            all_extensions=X509Parser._extract_all_extensions(cert),
        )

    @staticmethod
    def _extract_dn(name: x509.Name) -> dict[str, str]:
        """Extract Distinguished Name as a dictionary."""
        dn: dict[str, str] = {}

        # Common name attributes mapping
        oid_names = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
            NameOID.EMAIL_ADDRESS: "E",
            NameOID.SERIAL_NUMBER: "SERIALNUMBER",
        }

        for attr in name:
            oid = attr.oid
            value = attr.value

            if oid in oid_names:
                key = oid_names[oid]
            else:
                key = oid.dotted_string

            # Handle multiple values with same OID
            if key in dn:
                dn[key] = f"{dn[key]}, {value}"
            else:
                dn[key] = value

        return dn

    @staticmethod
    def _extract_key_usage(cert: x509.Certificate) -> list[str]:
        """Extract key usage extension."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
            usage = ext.value
            usages = []

            if usage.digital_signature:
                usages.append("Digital Signature")
            if usage.content_commitment:
                usages.append("Non-Repudiation")
            if usage.key_encipherment:
                usages.append("Key Encipherment")
            if usage.data_encipherment:
                usages.append("Data Encipherment")
            if usage.key_agreement:
                usages.append("Key Agreement")
                # encipher_only and decipher_only are only valid when key_agreement is True
                try:
                    if usage.encipher_only:
                        usages.append("Encipher Only")
                except ValueError:
                    pass
                try:
                    if usage.decipher_only:
                        usages.append("Decipher Only")
                except ValueError:
                    pass
            if usage.key_cert_sign:
                usages.append("Certificate Sign")
            if usage.crl_sign:
                usages.append("CRL Sign")

            return usages
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_extended_key_usage(cert: x509.Certificate) -> list[str]:
        """Extract extended key usage extension."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            usages = []

            eku_names = {
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH: "TLS Web Server Authentication",
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH: "TLS Web Client Authentication",
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION: "Email Protection",
                x509.oid.ExtendedKeyUsageOID.TIME_STAMPING: "Time Stamping",
                x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP Signing",
            }

            for oid in ext.value:
                if oid in eku_names:
                    usages.append(eku_names[oid])
                else:
                    usages.append(oid.dotted_string)

            return usages
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_subject_alt_names(cert: x509.Certificate) -> list[str]:
        """Extract Subject Alternative Names."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = []

            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    names.append(f"DNS: {name.value}")
                elif isinstance(name, x509.RFC822Name):
                    names.append(f"Email: {name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    names.append(f"URI: {name.value}")
                elif isinstance(name, x509.IPAddress):
                    names.append(f"IP: {name.value}")
                else:
                    names.append(str(name))

            return names
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_crl_distribution_points(cert: x509.Certificate) -> list[str]:
        """Extract CRL Distribution Points."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            urls = []

            for dp in ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            urls.append(name.value)

            return urls
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_ocsp_responders(cert: x509.Certificate) -> list[str]:
        """Extract OCSP responder URLs from Authority Information Access."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            urls = []

            for desc in ext.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        urls.append(desc.access_location.value)

            return urls
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_certificate_policies(cert: x509.Certificate) -> list[dict[str, str]]:
        """Extract Certificate Policies."""
        try:
            ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
            policies = []

            for policy in ext.value:
                policy_dict = {
                    "oid": policy.policy_identifier.dotted_string,
                }

                if policy.policy_qualifiers:
                    qualifiers = []
                    for qualifier in policy.policy_qualifiers:
                        if isinstance(qualifier, str):
                            qualifiers.append(qualifier)
                        elif hasattr(qualifier, "notice_reference") or hasattr(
                            qualifier, "explicit_text"
                        ):
                            if hasattr(qualifier, "explicit_text") and qualifier.explicit_text:
                                qualifiers.append(qualifier.explicit_text)
                    if qualifiers:
                        policy_dict["qualifiers"] = ", ".join(qualifiers)

                policies.append(policy_dict)

            return policies
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _compute_thumbprint(cert_bytes: bytes, algorithm) -> str:
        """Compute certificate thumbprint (fingerprint)."""
        digest = hashlib.new(algorithm.name)
        digest.update(cert_bytes)
        return digest.hexdigest().upper()

    @staticmethod
    def _extract_public_key_algorithm(cert: x509.Certificate) -> str:
        """Extract public key algorithm name."""
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            return f"ECC ({curve_name})"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        else:
            return type(public_key).__name__

    @staticmethod
    def _extract_public_key_size(cert: x509.Certificate) -> int:
        """Extract public key size in bits."""
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.curve.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            return public_key.key_size
        else:
            return 0

    @staticmethod
    def _extract_signature_algorithm(cert: x509.Certificate) -> str:
        """Extract signature algorithm name."""
        sig_alg = cert.signature_algorithm_oid

        # Common signature algorithm OIDs
        sig_names = {
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256: "SHA256withRSA",
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384: "SHA384withRSA",
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512: "SHA512withRSA",
            x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1: "SHA1withRSA",
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA256: "SHA256withECDSA",
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA384: "SHA384withECDSA",
            x509.oid.SignatureAlgorithmOID.ECDSA_WITH_SHA512: "SHA512withECDSA",
            x509.oid.SignatureAlgorithmOID.DSA_WITH_SHA256: "SHA256withDSA",
        }

        return sig_names.get(sig_alg, sig_alg.dotted_string)

    @staticmethod
    def _extract_all_extensions(cert: x509.Certificate) -> list[dict[str, str]]:
        """Extract all extensions with OID and critical flag."""
        extensions = []

        # Extension name mapping
        ext_names = {
            ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject Key Identifier",
            ExtensionOID.KEY_USAGE: "Key Usage",
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject Alternative Name",
            ExtensionOID.BASIC_CONSTRAINTS: "Basic Constraints",
            ExtensionOID.EXTENDED_KEY_USAGE: "Extended Key Usage",
            ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL Distribution Points",
            ExtensionOID.CERTIFICATE_POLICIES: "Certificate Policies",
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority Key Identifier",
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority Information Access",
        }

        for ext in cert.extensions:
            ext_dict = {
                "oid": ext.oid.dotted_string,
                "name": ext_names.get(ext.oid, ext.oid.dotted_string),
                "critical": "Yes" if ext.critical else "No",
            }

            # Try to get a human-readable value
            try:
                value_str = str(ext.value)
                # Truncate very long values
                if len(value_str) > 200:
                    value_str = value_str[:200] + "..."
                ext_dict["value"] = value_str
            except Exception:
                ext_dict["value"] = "[Binary data]"

            extensions.append(ext_dict)

        return extensions
