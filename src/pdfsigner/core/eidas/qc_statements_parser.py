"""
qc_statements_parser.py - ASN.1 parsing of QcStatements from X.509 certificates

Implements real ASN.1 parsing per ETSI EN 319 412-5 V2.5.1 using asn1crypto.
Parses the QcStatements extension (OID 1.3.6.1.5.5.7.1.3) and extracts all
defined QcStatement types.

QcStatements OIDs:
- 0.4.0.1862.1.1: QcCompliance - Certificate is Qualified
- 0.4.0.1862.1.2: QcLimitValue - Transaction limit
- 0.4.0.1862.1.3: QcRetentionPeriod - Retention period in years
- 0.4.0.1862.1.4: QcSSCD - Qualified Signature Creation Device
- 0.4.0.1862.1.5: QcPDS - PKI Disclosure Statements
- 0.4.0.1862.1.6: QcType - Certificate type (esign, eseal, web)
- 0.4.0.1862.1.7: QcCClegislation - Country codes under EU legislation
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from asn1crypto import core as asn1_core
from asn1crypto import x509 as asn1_x509

logger = logging.getLogger(__name__)

# --- OID constants ---

QC_STATEMENTS_EXT_OID = "1.3.6.1.5.5.7.1.3"

QC_OID_COMPLIANCE = "0.4.0.1862.1.1"
QC_OID_LIMIT_VALUE = "0.4.0.1862.1.2"
QC_OID_RETENTION = "0.4.0.1862.1.3"
QC_OID_SSCD = "0.4.0.1862.1.4"
QC_OID_PDS = "0.4.0.1862.1.5"
QC_OID_TYPE = "0.4.0.1862.1.6"
QC_OID_LEGISLATION = "0.4.0.1862.1.7"

QC_TYPE_ESIGN = "0.4.0.1862.1.6.1"
QC_TYPE_ESEAL = "0.4.0.1862.1.6.2"
QC_TYPE_WEB = "0.4.0.1862.1.6.3"

QC_TYPE_MAP: dict[str, str] = {
    QC_TYPE_ESIGN: "esign",
    QC_TYPE_ESEAL: "eseal",
    QC_TYPE_WEB: "web",
}

QC_OID_NAMES: dict[str, str] = {
    QC_OID_COMPLIANCE: "QcCompliance",
    QC_OID_LIMIT_VALUE: "QcLimitValue",
    QC_OID_RETENTION: "QcRetentionPeriod",
    QC_OID_SSCD: "QcSSCD",
    QC_OID_PDS: "QcPDS",
    QC_OID_TYPE: "QcType",
    QC_OID_LEGISLATION: "QcCClegislation",
}


# --- ASN.1 structure definitions per ETSI EN 319 412-5 ---


class QcLimitValue(asn1_core.Sequence):
    """QcLimitValue ::= SEQUENCE { currency, amount, exponent }"""

    _fields = [
        (
            "currency",
            asn1_core.Choice,
            {
                "options": {
                    "alphabetic": asn1_core.PrintableString,
                    "numeric": asn1_core.Integer,
                }
            },
        ),
        ("amount", asn1_core.Integer),
        ("exponent", asn1_core.Integer),
    ]


class QcPDSLocation(asn1_core.Sequence):
    """QcPDSLocation ::= SEQUENCE { url IA5String, language PrintableString }"""

    _fields = [
        ("url", asn1_core.IA5String),
        ("language", asn1_core.PrintableString),
    ]


class QcPDSLocations(asn1_core.SequenceOf):
    """QcPDS ::= SEQUENCE OF QcPDSLocation"""

    _child_spec = QcPDSLocation


class QcTypeOids(asn1_core.SequenceOf):
    """QcType ::= SEQUENCE OF OBJECT IDENTIFIER"""

    _child_spec = asn1_core.ObjectIdentifier


class QcCClegislation(asn1_core.SequenceOf):
    """QcCClegislation ::= SEQUENCE OF PrintableString (SIZE(2))"""

    _child_spec = asn1_core.PrintableString


class QcStatement(asn1_core.Sequence):
    """QcStatement ::= SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }"""

    _fields = [
        ("statement_id", asn1_core.ObjectIdentifier),
        ("statement_info", asn1_core.Any, {"optional": True}),
    ]


class QcStatements(asn1_core.SequenceOf):
    """QcStatements ::= SEQUENCE OF QcStatement"""

    _child_spec = QcStatement


# --- Result dataclass ---


@dataclass
class QcStatementsResult:
    """Parsed QcStatements from a certificate.

    Attributes:
        has_qc_statements: True if the QcStatements extension was found
        is_qualified: True if QcCompliance (0.4.0.1862.1.1) is present
        has_qscd: True if QcSSCD (0.4.0.1862.1.4) is present
        qc_type: Primary certificate type ("esign", "eseal", "web") or None
        qc_types: All certificate types if multiple are present
        retention_period: Retention period in years, or None
        legislation_countries: Country codes from QcCClegislation
        pds_urls: PKI Disclosure Statement URLs with language
        limit_value: Transaction limit (currency, amount, exponent) or None
        raw_statements: All parsed statements keyed by OID name
    """

    has_qc_statements: bool = False
    is_qualified: bool = False
    has_qscd: bool = False
    qc_type: str | None = None
    qc_types: list[str] = field(default_factory=list)
    retention_period: int | None = None
    legislation_countries: list[str] = field(default_factory=list)
    pds_urls: list[dict[str, str]] = field(default_factory=list)
    limit_value: dict[str, Any] | None = None
    raw_statements: dict[str, Any] = field(default_factory=dict)


# --- Parsing functions ---


def _parse_qc_type(info_bytes: bytes) -> list[str]:
    """Parse QcType statementInfo into list of type names."""
    types: list[str] = []
    try:
        qc_type_seq = QcTypeOids.load(info_bytes)
        for oid_value in qc_type_seq:
            oid_str = oid_value.dotted
            type_name = QC_TYPE_MAP.get(oid_str)
            if type_name:
                types.append(type_name)
            else:
                logger.debug("Unknown QcType OID: %s", oid_str)
                types.append(f"unknown({oid_str})")
    except Exception as e:
        logger.debug("Failed to parse QcType: %s", e)
    return types


def _parse_qc_limit_value(info_bytes: bytes) -> dict[str, Any] | None:
    """Parse QcLimitValue statementInfo."""
    try:
        limit = QcLimitValue.load(info_bytes)
        currency_choice = limit["currency"]
        currency = currency_choice.chosen.native
        return {
            "currency": str(currency),
            "amount": int(limit["amount"].native),
            "exponent": int(limit["exponent"].native),
        }
    except Exception as e:
        logger.debug("Failed to parse QcLimitValue: %s", e)
        return None


def _parse_qc_retention(info_bytes: bytes) -> int | None:
    """Parse QcRetentionPeriod statementInfo (INTEGER)."""
    try:
        value = asn1_core.Integer.load(info_bytes)
        return int(value.native)
    except Exception as e:
        logger.debug("Failed to parse QcRetentionPeriod: %s", e)
        return None


def _parse_qc_pds(info_bytes: bytes) -> list[dict[str, str]]:
    """Parse QcPDS statementInfo into list of {url, language} dicts."""
    results: list[dict[str, str]] = []
    try:
        pds_seq = QcPDSLocations.load(info_bytes)
        for location in pds_seq:
            results.append(
                {
                    "url": str(location["url"].native),
                    "language": str(location["language"].native),
                }
            )
    except Exception as e:
        logger.debug("Failed to parse QcPDS: %s", e)
    return results


def _parse_qc_legislation(info_bytes: bytes) -> list[str]:
    """Parse QcCClegislation statementInfo into list of country codes."""
    countries: list[str] = []
    try:
        leg_seq = QcCClegislation.load(info_bytes)
        for country in leg_seq:
            countries.append(str(country.native))
    except Exception as e:
        logger.debug("Failed to parse QcCClegislation: %s", e)
    return countries


def parse_qc_statements(certificate_bytes: bytes) -> QcStatementsResult:
    """Parse QcStatements extension from a DER-encoded X.509 certificate.

    Extracts the QcStatements extension (OID 1.3.6.1.5.5.7.1.3) and parses
    all QcStatement types per ETSI EN 319 412-5 V2.5.1.

    Args:
        certificate_bytes: DER-encoded X.509 certificate bytes

    Returns:
        QcStatementsResult with all parsed QcStatement fields.
        If the extension is not found or parsing fails, returns a result
        with has_qc_statements=False.
    """
    result = QcStatementsResult()

    try:
        cert = asn1_x509.Certificate.load(certificate_bytes)
    except Exception as e:
        logger.warning("Failed to load certificate: %s", e)
        return result

    # Find QcStatements extension
    tbs = cert["tbs_certificate"]
    extensions = tbs["extensions"]
    if extensions is None:
        logger.debug("Certificate has no extensions")
        return result

    qc_ext_value: bytes | None = None
    for ext in extensions:
        if ext["extn_id"].dotted == QC_STATEMENTS_EXT_OID:
            qc_ext_value = bytes(ext["extn_value"].native)
            break

    if qc_ext_value is None:
        logger.debug("QcStatements extension not found in certificate")
        return result

    # Parse the extension value as QcStatements
    try:
        qc_statements = QcStatements.load(qc_ext_value)
    except Exception as e:
        logger.warning("Failed to parse QcStatements ASN.1: %s", e)
        return result

    result.has_qc_statements = True

    for stmt in qc_statements:
        oid_str = stmt["statement_id"].dotted
        oid_name = QC_OID_NAMES.get(oid_str, oid_str)
        info = stmt["statement_info"]
        # info.contents is b'' for Void (absent optional), non-empty when present
        info_bytes = info.dump() if info.contents else None

        if oid_str == QC_OID_COMPLIANCE:
            result.is_qualified = True
            result.raw_statements[oid_name] = True

        elif oid_str == QC_OID_SSCD:
            result.has_qscd = True
            result.raw_statements[oid_name] = True

        elif oid_str == QC_OID_TYPE and info_bytes:
            types = _parse_qc_type(info_bytes)
            result.qc_types = types
            result.qc_type = types[0] if types else None
            result.raw_statements[oid_name] = types

        elif oid_str == QC_OID_RETENTION and info_bytes:
            result.retention_period = _parse_qc_retention(info_bytes)
            result.raw_statements[oid_name] = result.retention_period

        elif oid_str == QC_OID_LEGISLATION and info_bytes:
            result.legislation_countries = _parse_qc_legislation(info_bytes)
            result.raw_statements[oid_name] = result.legislation_countries

        elif oid_str == QC_OID_PDS and info_bytes:
            result.pds_urls = _parse_qc_pds(info_bytes)
            result.raw_statements[oid_name] = result.pds_urls

        elif oid_str == QC_OID_LIMIT_VALUE and info_bytes:
            result.limit_value = _parse_qc_limit_value(info_bytes)
            result.raw_statements[oid_name] = result.limit_value

        else:
            # Unknown or presence-only statement
            result.raw_statements[oid_name] = True
            logger.debug("Unhandled QcStatement OID: %s", oid_str)

    logger.debug(
        "Parsed QcStatements: qualified=%s, qscd=%s, type=%s, countries=%s",
        result.is_qualified,
        result.has_qscd,
        result.qc_type,
        result.legislation_countries,
    )
    return result
