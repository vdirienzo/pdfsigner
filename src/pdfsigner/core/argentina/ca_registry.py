"""
ca_registry.py - Argentine Certification Authorities Registry (Ley 25.506)

Author: Homero Thompson del Lago del Terror

Manages the registry of licensed Argentine Certification Authorities (CAs)
as mandated by Argentine Law 25.506 (Digital Signature Law).

Official regulatory body: ONTI (Oficina Nacional de Tecnologías de Información)
Reference: https://www.argentina.gob.ar/jefatura/innovacion-publica/administrativa/ley-de-firma-digital

Key features:
- Registry of governmental and private licensed certifiers
- Query CAs by issuer DN, type, or cost
- Compliance checking for certificate validation
- Support for SafeNet eToken and other PKCS#11 tokens
"""

from dataclasses import dataclass
from enum import Enum

from loguru import logger


class CertifierType(str, Enum):
    """Type of Argentine Certification Authority."""

    GOVERNMENTAL = "governmental"
    PRIVATE = "private"


class CertifierStatus(str, Enum):
    """Status of Argentine Certification Authority license."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


@dataclass
class ArgentineCertifier:
    """Argentine Certification Authority information."""

    name: str
    certifier_type: CertifierType
    status: CertifierStatus
    issuer_dns: list[str]  # Distinguished Names used by this certifier
    website: str
    cost: str  # "Gratis" or "USD X-Y/año"
    modality: str  # "Token", "Software", "FDR", "Token/Software"
    description: str


# Registry of licensed Argentine Certification Authorities
ARGENTINE_CERTIFIERS = [
    # Governmental certifiers (free)
    ArgentineCertifier(
        name="AFIP",
        certifier_type=CertifierType.GOVERNMENTAL,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC AFIP",
            "CN=Autoridad Certificante AFIP",
            "CN=AFIP Autoridad Certificante",
            "O=AFIP",
            "OU=AFIP",
        ],
        website="https://www.afip.gob.ar/cl_fiscal/",
        cost="Gratis",
        modality="Token/Software",
        description="Administración Federal de Ingresos Públicos - For taxpayers with CUIT",
    ),
    ArgentineCertifier(
        name="RENAPER",
        certifier_type=CertifierType.GOVERNMENTAL,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC RENAPER",
            "CN=Autoridad Certificante RENAPER",
            "O=RENAPER",
            "OU=RENAPER",
        ],
        website="https://www.argentina.gob.ar/interior/renaper",
        cost="Gratis",
        modality="Token",
        description="Registro Nacional de las Personas - For Argentine citizens with DNI",
    ),
    ArgentineCertifier(
        name="FDR",
        certifier_type=CertifierType.GOVERNMENTAL,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC FDR",
            "CN=Firma Digital Remota",
            "CN=Autoridad Certificante FDR",
            "O=Innovación Pública",
            "O=Secretaría de Innovación Pública",
        ],
        website="https://fdr.gob.ar/",
        cost="Gratis",
        modality="FDR",
        description="Firma Digital Remota - Remote digital signature with HSM (Innovación Pública)",
    ),
    ArgentineCertifier(
        name="IOSFA",
        certifier_type=CertifierType.GOVERNMENTAL,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC IOSFA",
            "CN=Autoridad Certificante IOSFA",
            "O=IOSFA",
            "OU=IOSFA",
        ],
        website="https://www.iosfa.gob.ar/",
        cost="Gratis",
        modality="Token",
        description="Instituto de Obra Social de las Fuerzas Armadas",
    ),
    # Private certifiers (paid)
    ArgentineCertifier(
        name="Andreani",
        certifier_type=CertifierType.PRIVATE,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC Andreani",
            "CN=Autoridad Certificante Andreani",
            "CN=Andreani Certificadora",
            "O=Andreani",
        ],
        website="https://www.andreani.com/institucional/certificacion-digital/",
        cost="USD 80-200/año",
        modality="Token",
        description="Andreani Certified Digital Signatures - SafeNet eToken compatible",
    ),
    ArgentineCertifier(
        name="E-CERT NIC Argentina",
        certifier_type=CertifierType.PRIVATE,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC E-CERT",
            "CN=E-CERT NIC Argentina",
            "CN=Autoridad Certificante E-CERT",
            "O=E-CERT",
            "O=NIC Argentina",
        ],
        website="https://www.e-cert.com.ar/",
        cost="USD 100-300/año",
        modality="Token/Software",
        description="E-CERT by NIC Argentina - Multiple certification levels",
    ),
    ArgentineCertifier(
        name="Certant",
        certifier_type=CertifierType.PRIVATE,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC Certant",
            "CN=Autoridad Certificante Certant",
            "O=Certant",
        ],
        website="https://www.certant.com/",
        cost="USD 120-250/año",
        modality="Token",
        description="Certant Digital Certificates - PKCS#11 tokens",
    ),
    ArgentineCertifier(
        name="Colegio de Escribanos CABA",
        certifier_type=CertifierType.PRIVATE,
        status=CertifierStatus.ACTIVE,
        issuer_dns=[
            "CN=AC Colegio de Escribanos",
            "CN=Colegio de Escribanos de la Ciudad de Buenos Aires",
            "O=Colegio de Escribanos",
        ],
        website="https://www.colegio-escribanos.org.ar/",
        cost="USD 150/año",
        modality="Token",
        description="College of Notaries of Buenos Aires - For registered notaries",
    ),
]


class ArgentineCARegistry:
    """Registry of licensed Argentine Certification Authorities.

    Provides lookup and validation services for CAs licensed under
    Argentine Law 25.506 (Digital Signature Law).
    """

    def __init__(self):
        """Initialize the Argentine CA registry."""
        self._certifiers: dict[str, ArgentineCertifier] = {}
        self._issuer_to_certifier: dict[str, ArgentineCertifier] = {}
        self._load_certifiers()

    def _load_certifiers(self) -> None:
        """Load all registered certification authorities into registry."""
        for certifier in ARGENTINE_CERTIFIERS:
            # Index by name
            self._certifiers[certifier.name] = certifier

            # Index by each issuer DN
            for issuer_dn in certifier.issuer_dns:
                normalized_dn = self._normalize_dn(issuer_dn)
                self._issuer_to_certifier[normalized_dn] = certifier

        logger.info("Loaded %d Argentine certifiers", len(self._certifiers))

    def _normalize_dn(self, dn: str) -> str:
        """Normalize Distinguished Name for consistent matching.

        Args:
            dn: Distinguished Name to normalize

        Returns:
            Normalized DN (lowercase, trimmed)
        """
        return dn.lower().strip()

    def find_certifier_by_issuer(self, issuer_dn: str) -> ArgentineCertifier | None:
        """Find certifier by certificate issuer Distinguished Name.

        Performs exact match and fuzzy matching on issuer DN components.

        Args:
            issuer_dn: Certificate issuer DN (e.g., "CN=AC AFIP, O=AFIP")

        Returns:
            ArgentineCertifier if found, None otherwise
        """
        normalized_dn = self._normalize_dn(issuer_dn)

        # Try exact match first
        if normalized_dn in self._issuer_to_certifier:
            return self._issuer_to_certifier[normalized_dn]

        # Try fuzzy matching on DN components
        for registered_dn, certifier in self._issuer_to_certifier.items():
            if self._dn_matches(normalized_dn, registered_dn):
                return certifier

        return None

    def _dn_matches(self, cert_dn: str, registered_dn: str) -> bool:
        """Check if certificate DN matches registered DN using fuzzy logic.

        Args:
            cert_dn: Certificate DN (normalized)
            registered_dn: Registered DN pattern (normalized)

        Returns:
            True if DNs match
        """
        # Check if registered DN is contained in certificate DN
        if registered_dn in cert_dn:
            return True

        # Extract components (CN, O, OU)
        cert_parts = [part.strip() for part in cert_dn.split(",")]
        registered_parts = [part.strip() for part in registered_dn.split(",")]

        # Check if any registered part matches any certificate part
        for reg_part in registered_parts:
            for cert_part in cert_parts:
                if reg_part in cert_part or cert_part in reg_part:
                    return True

        return False

    def is_licensed_certifier(self, issuer_dn: str) -> bool:
        """Check if issuer is a licensed Argentine certification authority.

        Args:
            issuer_dn: Certificate issuer DN

        Returns:
            True if issuer is licensed and active
        """
        certifier = self.find_certifier_by_issuer(issuer_dn)
        if certifier is None:
            return False

        return certifier.status == CertifierStatus.ACTIVE

    def get_all_certifiers(self) -> list[ArgentineCertifier]:
        """Get all registered certification authorities.

        Returns:
            List of all ArgentineCertifier entries
        """
        return list(self._certifiers.values())

    def get_governmental_certifiers(self) -> list[ArgentineCertifier]:
        """Get only free governmental certification authorities.

        Returns:
            List of governmental (free) certifiers
        """
        return [
            cert
            for cert in self._certifiers.values()
            if cert.certifier_type == CertifierType.GOVERNMENTAL
        ]

    def get_private_certifiers(self) -> list[ArgentineCertifier]:
        """Get only private (paid) certification authorities.

        Returns:
            List of private (paid) certifiers
        """
        return [
            cert
            for cert in self._certifiers.values()
            if cert.certifier_type == CertifierType.PRIVATE
        ]

    def get_certifier_by_name(self, name: str) -> ArgentineCertifier | None:
        """Get certifier by exact name match.

        Args:
            name: Certifier name (e.g., "AFIP", "Andreani")

        Returns:
            ArgentineCertifier if found, None otherwise
        """
        return self._certifiers.get(name)


# --- Singleton access ---

_registry: ArgentineCARegistry | None = None


def get_argentine_ca_registry() -> ArgentineCARegistry:
    """Get or create the singleton Argentine CA registry instance.

    Returns:
        ArgentineCARegistry singleton instance
    """
    global _registry
    if _registry is None:
        _registry = ArgentineCARegistry()
    return _registry
