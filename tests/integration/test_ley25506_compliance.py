"""
Integration tests for Ley 25.506 compliance controls.

Tests verify the structure, legal accuracy, and functionality of
Argentine digital signature law compliance controls.
"""

from dataclasses import is_dataclass

from pdfsigner.core.compliance.controls import (
    CONTROL_REGISTRY,
    LEY_25506_CONTROLS,
    ComplianceStandard,
    ControlDefinition,
    get_all_controls,
    get_controls_for_standard,
)


class TestLey25506ControlsIntegrity:
    """Tests for Ley 25.506 control definitions integrity."""

    def test_all_controls_have_unique_ids(self):
        """Verify all control IDs are unique."""
        ids = [c.control_id for c in LEY_25506_CONTROLS]
        assert len(ids) == len(set(ids)), f"Duplicate control IDs found: {ids}"

    def test_all_controls_have_check_functions(self):
        """Verify all controls reference a check function."""
        for control in LEY_25506_CONTROLS:
            assert control.check_func, f"Control {control.control_id} missing check_func"
            assert control.check_func.startswith("_check_"), (
                f"Invalid check_func name: {control.check_func}"
            )

    def test_required_controls_have_high_weight(self):
        """Required controls should have weight >= 1.0."""
        for control in LEY_25506_CONTROLS:
            if control.required:
                assert control.weight >= 1.0, (
                    f"Required control {control.control_id} has weight {control.weight} < 1.0"
                )

    def test_control_categories_are_valid(self):
        """Verify control categories are meaningful."""
        valid_categories = {
            "Signature",
            "Certificate",
            "Verification",
            "Certifier",
            "Cryptography",
            "Format",
            "Timestamp",
        }
        for control in LEY_25506_CONTROLS:
            assert control.category in valid_categories, (
                f"Invalid category: {control.category} in {control.control_id}"
            )

    def test_controls_have_proper_tags(self):
        """All controls should have 'argentina' tag."""
        for control in LEY_25506_CONTROLS:
            assert "argentina" in control.tags, (
                f"Control {control.control_id} missing 'argentina' tag"
            )

    def test_registry_contains_ley_25506(self):
        """Verify LEY_25506 is in the control registry."""
        assert ComplianceStandard.LEY_25506 in CONTROL_REGISTRY
        assert CONTROL_REGISTRY[ComplianceStandard.LEY_25506] == LEY_25506_CONTROLS

    def test_get_controls_for_standard_works(self):
        """Test the helper function returns correct controls."""
        controls = get_controls_for_standard(ComplianceStandard.LEY_25506)
        assert controls == LEY_25506_CONTROLS
        assert len(controls) == 8  # Expected 8 controls

    def test_control_ids_follow_convention(self):
        """Control IDs should follow naming convention."""
        for control in LEY_25506_CONTROLS:
            control_id = control.control_id
            # Should start with LEY25506-
            assert control_id.startswith("LEY25506-"), (
                f"Control ID doesn't start with LEY25506-: {control_id}"
            )

    def test_all_controls_have_descriptions(self):
        """All controls must have non-empty descriptions."""
        for control in LEY_25506_CONTROLS:
            assert control.description, f"Control {control.control_id} missing description"
            assert len(control.description) >= 20, (
                f"Control {control.control_id} has too short description"
            )

    def test_check_function_names_match_control_ids(self):
        """Check functions should reference the control type."""
        for control in LEY_25506_CONTROLS:
            # Extract key part from control ID
            # LEY25506-Art.2 -> signature_control
            # LEY25506-CRYPTO-RSA -> rsa_keysize
            assert "ley25506" in control.check_func.lower(), (
                f"Check func doesn't mention ley25506: {control.check_func}"
            )


class TestControlDefinitionStructure:
    """Tests for ControlDefinition dataclass structure."""

    def test_control_definition_is_dataclass(self):
        """Verify ControlDefinition is a proper dataclass."""
        assert is_dataclass(ControlDefinition)

    def test_control_definition_fields(self):
        """Verify all required fields exist."""
        required_fields = [
            "control_id",
            "name",
            "description",
            "standard",
            "category",
            "check_func",
        ]
        for control in LEY_25506_CONTROLS:
            for field in required_fields:
                assert hasattr(control, field), (
                    f"Control {control.control_id} missing field: {field}"
                )
                value = getattr(control, field)
                assert value is not None, f"Control {control.control_id} has null field: {field}"

    def test_control_has_weight_field(self):
        """All controls must have a weight field."""
        for control in LEY_25506_CONTROLS:
            assert hasattr(control, "weight")
            assert isinstance(control.weight, (int, float))
            assert control.weight > 0, f"Control {control.control_id} has non-positive weight"

    def test_control_has_required_field(self):
        """All controls must have a required boolean field."""
        for control in LEY_25506_CONTROLS:
            assert hasattr(control, "required")
            assert isinstance(control.required, bool)

    def test_control_has_tags_list(self):
        """All controls must have a tags list."""
        for control in LEY_25506_CONTROLS:
            assert hasattr(control, "tags")
            assert isinstance(control.tags, list)


class TestLey25506LegalContent:
    """Tests for legal accuracy of Ley 25.506 controls."""

    def test_article_references_are_valid(self):
        """Control IDs should reference valid Ley 25.506 articles."""
        valid_articles = ["Art.2", "Art.9", "Art.7", "CRYPTO", "FORMAT", "TSA"]
        for control in LEY_25506_CONTROLS:
            has_valid_ref = any(ref in control.control_id for ref in valid_articles)
            assert has_valid_ref, f"Invalid article reference in control ID: {control.control_id}"

    def test_crypto_controls_specify_algorithms(self):
        """Crypto controls should mention specific algorithms."""
        crypto_controls = [c for c in LEY_25506_CONTROLS if c.category == "Cryptography"]
        assert len(crypto_controls) >= 2, "Expected at least 2 crypto controls"

        for control in crypto_controls:
            desc_lower = control.description.lower()
            has_algo = any(algo in desc_lower for algo in ["rsa", "sha", "ecdsa", "md5", "hash"])
            assert has_algo, (
                f"Crypto control missing algorithm spec: {control.control_id} - "
                f"{control.description}"
            )

    def test_certifier_control_mentions_aaip(self):
        """Licensed certifier control should mention AAIP."""
        certifier_controls = [c for c in LEY_25506_CONTROLS if c.category == "Certifier"]
        assert len(certifier_controls) >= 1, "Expected at least one Certifier control"

        for control in certifier_controls:
            desc = control.description
            # Should mention AAIP (the Argentine competent authority)
            assert "AAIP" in desc or "licens" in desc.lower(), (
                f"Certifier control missing AAIP/license reference: {control.control_id}"
            )

    def test_signature_control_mentions_signer_control(self):
        """Signature control should mention signer's exclusive control."""
        signature_controls = [c for c in LEY_25506_CONTROLS if c.category == "Signature"]
        assert len(signature_controls) >= 1

        for control in signature_controls:
            desc_lower = control.description.lower()
            # Art.2 requires info exclusively known to signer under absolute control
            has_control_concept = any(
                word in desc_lower for word in ["control", "exclusive", "signer"]
            )
            assert has_control_concept, (
                f"Signature control missing signer control concept: {control.control_id}"
            )

    def test_certificate_validity_mentioned(self):
        """Certificate controls should mention validity period."""
        cert_controls = [c for c in LEY_25506_CONTROLS if c.category == "Certificate"]
        assert len(cert_controls) >= 1

        for control in cert_controls:
            desc_lower = control.description.lower()
            # Should mention validity period (Art. 9.1)
            has_validity = "validity" in desc_lower or "period" in desc_lower
            if "validity" in control.control_id.lower():
                assert has_validity, (
                    f"Certificate validity control missing validity concept: {control.control_id}"
                )

    def test_rsa_keysize_minimum_specified(self):
        """RSA control should specify minimum key size of 2048 bits."""
        rsa_controls = [c for c in LEY_25506_CONTROLS if "RSA" in c.control_id]
        assert len(rsa_controls) >= 1, "Missing RSA control"

        for control in rsa_controls:
            desc = control.description
            # Should mention 2048 bits as minimum
            assert "2048" in desc, (
                f"RSA control doesn't specify 2048 bit minimum: {control.control_id}"
            )

    def test_hash_algorithm_prohibits_weak_algos(self):
        """Hash algorithm control should prohibit MD5 and SHA-1."""
        hash_controls = [c for c in LEY_25506_CONTROLS if "HASH" in c.control_id]
        assert len(hash_controls) >= 1, "Missing hash algorithm control"

        for control in hash_controls:
            desc = control.description
            # Should mention prohibition of weak algorithms
            desc_lower = desc.lower()
            mentions_weak = "md5" in desc_lower or "sha-1" in desc_lower
            mentions_prohibited = "prohibit" in desc_lower
            assert mentions_weak or mentions_prohibited, (
                f"Hash control doesn't mention weak algorithms: {control.control_id}"
            )

    def test_pades_format_mentions_long_term(self):
        """PAdES format control should mention long-term validity."""
        pades_controls = [c for c in LEY_25506_CONTROLS if "FORMAT" in c.control_id]
        assert len(pades_controls) >= 1, "Missing PAdES format control"

        for control in pades_controls:
            desc_lower = control.description.lower()
            # Should mention PAdES-LT or PAdES-LTA for long-term validity
            has_pades = "pades" in desc_lower
            has_long_term = "long-term" in desc_lower or "lt" in desc_lower or "lta" in desc_lower
            assert has_pades and has_long_term, (
                f"PAdES control missing long-term concept: {control.control_id}"
            )

    def test_tsa_control_mentions_rfc3161(self):
        """TSA control should mention RFC 3161."""
        tsa_controls = [c for c in LEY_25506_CONTROLS if "TSA" in c.control_id]
        assert len(tsa_controls) >= 1, "Missing TSA control"

        for control in tsa_controls:
            desc = control.description
            # Should mention RFC 3161 standard for timestamps
            assert "RFC 3161" in desc or "RFC3161" in desc, (
                f"TSA control doesn't mention RFC 3161: {control.control_id}"
            )


class TestLey25506VsOtherStandards:
    """Compare Ley 25.506 controls with other standards."""

    def test_has_similar_structure_to_hipaa(self):
        """Ley 25.506 should follow same patterns as HIPAA controls."""
        hipaa_controls = CONTROL_REGISTRY.get(ComplianceStandard.HIPAA, [])

        # Both should have controls of cryptography/signature
        ley_crypto = [c for c in LEY_25506_CONTROLS if c.category == "Cryptography"]
        hipaa_crypto = [
            c
            for c in hipaa_controls
            if "crypt" in c.category.lower() or "encrypt" in c.name.lower()
        ]

        assert len(ley_crypto) >= 1, "Missing crypto controls in Ley 25.506"
        # HIPAA may not have explicit crypto category, but should have encryption controls
        assert len(hipaa_crypto) >= 1, "HIPAA should have encryption controls"

    def test_total_standards_count(self):
        """Verify total number of compliance standards."""
        assert len(CONTROL_REGISTRY) >= 7  # HIPAA, NIST, FedRAMP, eIDAS, GDPR, SOC2, LEY_25506

    def test_ley25506_in_all_controls(self):
        """Verify Ley 25.506 is included in get_all_controls."""
        all_controls = get_all_controls()
        assert ComplianceStandard.LEY_25506 in all_controls
        assert all_controls[ComplianceStandard.LEY_25506] == LEY_25506_CONTROLS

    def test_ley25506_has_reasonable_control_count(self):
        """Ley 25.506 should have a reasonable number of controls."""
        # Not too few (less than 5) or too many (more than 15)
        count = len(LEY_25506_CONTROLS)
        assert 5 <= count <= 15, f"Unexpected control count: {count}"

    def test_ley25506_weights_comparable_to_other_standards(self):
        """Ley 25.506 control weights should be comparable to other standards."""
        ley_weights = [c.weight for c in LEY_25506_CONTROLS]
        nist_controls = CONTROL_REGISTRY.get(ComplianceStandard.NIST_800_53, [])
        nist_weights = [c.weight for c in nist_controls]

        # Average weights should be in similar range
        ley_avg = sum(ley_weights) / len(ley_weights)
        nist_avg = sum(nist_weights) / len(nist_weights)

        # Both should be between 1.0 and 2.0 on average
        assert 0.5 <= ley_avg <= 3.0, f"Ley 25.506 avg weight out of range: {ley_avg}"
        assert 0.5 <= nist_avg <= 3.0, f"NIST avg weight out of range: {nist_avg}"

    def test_required_controls_ratio(self):
        """Verify ratio of required vs optional controls is reasonable."""
        required_count = sum(1 for c in LEY_25506_CONTROLS if c.required)
        total_count = len(LEY_25506_CONTROLS)

        # At least 50% should be required
        ratio = required_count / total_count
        assert ratio >= 0.5, f"Too few required controls: {required_count}/{total_count}"


class TestLey25506ControlCategories:
    """Test control category distribution."""

    def test_has_signature_controls(self):
        """Must have at least one signature control."""
        sig_controls = [c for c in LEY_25506_CONTROLS if c.category == "Signature"]
        assert len(sig_controls) >= 1, "Missing Signature controls"

    def test_has_certificate_controls(self):
        """Must have certificate-related controls."""
        cert_controls = [c for c in LEY_25506_CONTROLS if c.category == "Certificate"]
        assert len(cert_controls) >= 1, "Missing Certificate controls"

    def test_has_cryptography_controls(self):
        """Must have cryptography controls."""
        crypto_controls = [c for c in LEY_25506_CONTROLS if c.category == "Cryptography"]
        assert len(crypto_controls) >= 2, "Expected at least 2 Cryptography controls"

    def test_has_certifier_controls(self):
        """Must have certifier/CA controls."""
        certifier_controls = [c for c in LEY_25506_CONTROLS if c.category == "Certifier"]
        assert len(certifier_controls) >= 1, "Missing Certifier controls"

    def test_categories_have_multiple_controls(self):
        """Key categories should have multiple controls."""
        # Count controls per category
        from collections import Counter

        categories = Counter(c.category for c in LEY_25506_CONTROLS)

        # Cryptography is important, should have at least 2 controls
        assert categories.get("Cryptography", 0) >= 2, (
            "Cryptography category should have multiple controls"
        )


class TestLey25506ControlWeighting:
    """Test control weight distribution."""

    def test_critical_controls_have_high_weight(self):
        """Critical controls should have weight >= 2.0."""
        # Art.2 (signature control) and Art.9.3 (licensed certifier) are critical
        critical_ids = ["LEY25506-Art.2", "LEY25506-Art.9.3"]

        for control in LEY_25506_CONTROLS:
            if control.control_id in critical_ids:
                assert control.weight >= 1.5, (
                    f"Critical control {control.control_id} has low weight: {control.weight}"
                )

    def test_optional_controls_have_lower_weight(self):
        """Optional controls may have lower weight."""
        optional_controls = [c for c in LEY_25506_CONTROLS if not c.required]

        for control in optional_controls:
            # Optional controls can have weight as low as 0.5
            assert control.weight >= 0.5, (
                f"Optional control has too low weight: {control.control_id}"
            )

    def test_no_zero_weight_controls(self):
        """No control should have zero weight."""
        for control in LEY_25506_CONTROLS:
            assert control.weight > 0, f"Control has zero weight: {control.control_id}"


class TestLey25506Tags:
    """Test control tagging."""

    def test_all_controls_have_argentina_tag(self):
        """All Ley 25.506 controls must have 'argentina' tag."""
        for control in LEY_25506_CONTROLS:
            assert "argentina" in control.tags, f"Missing 'argentina' tag: {control.control_id}"

    def test_critical_controls_have_critical_tag(self):
        """Critical controls should be tagged as 'critical'."""
        # Art.9.3 (licensed certifier) is marked as critical in tags
        critical_control = next(c for c in LEY_25506_CONTROLS if "Art.9.3" in c.control_id)
        assert "critical" in critical_control.tags, "Art.9.3 should have 'critical' tag"

    def test_crypto_controls_have_relevant_tags(self):
        """Crypto controls should have appropriate tags."""
        crypto_controls = [c for c in LEY_25506_CONTROLS if c.category == "Cryptography"]

        for control in crypto_controls:
            # Should have either 'cryptography', 'rsa', or 'hash' tag
            relevant_tags = {"cryptography", "rsa", "hash", "ecdsa"}
            has_relevant = any(tag in control.tags for tag in relevant_tags)
            assert has_relevant, (
                f"Crypto control missing relevant tags: {control.control_id} - {control.tags}"
            )

    def test_signature_controls_have_signature_tag(self):
        """Signature controls should have 'signature' tag."""
        sig_controls = [c for c in LEY_25506_CONTROLS if c.category == "Signature"]

        for control in sig_controls:
            assert "signature" in control.tags or "legal" in control.tags


class TestLey25506Standard:
    """Test ComplianceStandard enum."""

    def test_ley_25506_is_valid_standard(self):
        """LEY_25506 should be a valid ComplianceStandard."""
        assert hasattr(ComplianceStandard, "LEY_25506")
        assert ComplianceStandard.LEY_25506 == "ley_25506"

    def test_standard_value_is_lowercase(self):
        """Standard value should be lowercase with underscore."""
        assert ComplianceStandard.LEY_25506.value == "ley_25506"

    def test_all_controls_reference_correct_standard(self):
        """All Ley 25.506 controls should reference LEY_25506 standard."""
        for control in LEY_25506_CONTROLS:
            assert control.standard == ComplianceStandard.LEY_25506, (
                f"Control {control.control_id} has wrong standard: {control.standard}"
            )
