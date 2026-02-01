"""Tests for encryption policy engine."""

from datetime import datetime
from unittest.mock import MagicMock, patch

from pdfsigner.core.policies import (
    EncryptionPolicy,
    PolicyAction,
    PolicyEngine,
    PolicyResult,
    PolicyTrigger,
    get_policy_engine,
)


class TestPolicyTrigger:
    """Tests for PolicyTrigger enum."""

    def test_always_value(self):
        """Test ALWAYS trigger has correct value."""
        assert PolicyTrigger.ALWAYS.value == "always"

    def test_phi_detected_value(self):
        """Test PHI_DETECTED trigger has correct value."""
        assert PolicyTrigger.PHI_DETECTED.value == "phi_detected"

    def test_department_value(self):
        """Test DEPARTMENT trigger has correct value."""
        assert PolicyTrigger.DEPARTMENT.value == "department"

    def test_manual_value(self):
        """Test MANUAL trigger has correct value."""
        assert PolicyTrigger.MANUAL.value == "manual"


class TestPolicyAction:
    """Tests for PolicyAction enum."""

    def test_encrypt_value(self):
        """Test ENCRYPT action has correct value."""
        assert PolicyAction.ENCRYPT.value == "encrypt"

    def test_warn_value(self):
        """Test WARN action has correct value."""
        assert PolicyAction.WARN.value == "warn"

    def test_block_value(self):
        """Test BLOCK action has correct value."""
        assert PolicyAction.BLOCK.value == "block"


class TestEncryptionPolicy:
    """Tests for EncryptionPolicy dataclass."""

    def test_default_policy_creation(self):
        """Test creating policy with defaults."""
        policy = EncryptionPolicy()
        assert policy.id != ""  # Should have UUID
        assert policy.trigger == PolicyTrigger.MANUAL
        assert policy.action == PolicyAction.WARN
        assert policy.enabled is True
        assert policy.priority == 0

    def test_custom_policy_creation(self):
        """Test creating policy with custom values."""
        policy = EncryptionPolicy(
            name="Test Policy",
            description="Test description",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.ENCRYPT,
            priority=100,
        )
        assert policy.name == "Test Policy"
        assert policy.trigger == PolicyTrigger.ALWAYS
        assert policy.action == PolicyAction.ENCRYPT
        assert policy.priority == 100

    def test_phi_policy_with_types(self):
        """Test PHI policy with specific types."""
        policy = EncryptionPolicy(
            trigger=PolicyTrigger.PHI_DETECTED,
            phi_types=["ssn", "mrn"],
            min_confidence="high",
        )
        assert policy.phi_types == ["ssn", "mrn"]
        assert policy.min_confidence == "high"

    def test_department_policy_with_list(self):
        """Test department policy with department list."""
        policy = EncryptionPolicy(
            trigger=PolicyTrigger.DEPARTMENT,
            departments=["medical_records", "radiology"],
        )
        assert "medical_records" in policy.departments
        assert "radiology" in policy.departments

    def test_to_dict_serialization(self):
        """Test policy serialization to dict."""
        policy = EncryptionPolicy(
            name="Test",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.ENCRYPT,
            priority=50,
        )
        data = policy.to_dict()

        assert data["name"] == "Test"
        assert data["trigger"] == "always"
        assert data["action"] == "encrypt"
        assert data["priority"] == 50
        assert "id" in data
        assert "created_at" in data

    def test_from_dict_deserialization(self):
        """Test policy deserialization from dict."""
        data = {
            "id": "test-id",
            "name": "Test Policy",
            "description": "Test",
            "trigger": "phi_detected",
            "action": "encrypt",
            "departments": [],
            "phi_types": ["ssn"],
            "min_confidence": "medium",
            "encryption_method": "aes256",
            "enabled": True,
            "priority": 100,
            "created_at": datetime.now().isoformat(),
        }
        policy = EncryptionPolicy.from_dict(data)

        assert policy.id == "test-id"
        assert policy.name == "Test Policy"
        assert policy.trigger == PolicyTrigger.PHI_DETECTED
        assert policy.action == PolicyAction.ENCRYPT
        assert policy.phi_types == ["ssn"]

    def test_round_trip_serialization(self):
        """Test policy can be serialized and deserialized."""
        original = EncryptionPolicy(
            name="Round Trip",
            trigger=PolicyTrigger.DEPARTMENT,
            departments=["lab"],
            priority=75,
        )
        data = original.to_dict()
        restored = EncryptionPolicy.from_dict(data)

        assert restored.name == original.name
        assert restored.trigger == original.trigger
        assert restored.departments == original.departments
        assert restored.priority == original.priority


class TestPolicyResult:
    """Tests for PolicyResult dataclass."""

    def test_triggered_result(self):
        """Test creating triggered result."""
        policy = EncryptionPolicy(name="Test")
        result = PolicyResult(
            triggered=True,
            policy=policy,
            action=PolicyAction.ENCRYPT,
            reason="Test reason",
        )

        assert result.triggered is True
        assert result.policy == policy
        assert result.action == PolicyAction.ENCRYPT
        assert result.reason == "Test reason"

    def test_non_triggered_result(self):
        """Test creating non-triggered result."""
        result = PolicyResult(
            triggered=False,
            policy=None,
            action=PolicyAction.WARN,
            reason="No match",
        )

        assert result.triggered is False
        assert result.policy is None

    def test_result_to_dict(self):
        """Test result serialization."""
        policy = EncryptionPolicy(name="Test")
        result = PolicyResult(
            triggered=True,
            policy=policy,
            action=PolicyAction.ENCRYPT,
            reason="Test",
        )
        data = result.to_dict()

        assert data["triggered"] is True
        assert data["action"] == "encrypt"
        assert data["reason"] == "Test"
        assert data["policy"] is not None


class TestPolicyEngine:
    """Tests for PolicyEngine class."""

    def test_engine_initialization_with_defaults(self):
        """Test engine initializes with default policies."""
        engine = PolicyEngine()
        policies = engine.get_policies()

        assert len(policies) > 0
        # Should have HIPAA PHI Protection and Medical Records policies
        policy_names = [p.name for p in policies]
        assert "HIPAA PHI Protection" in policy_names
        assert "Medical Records Department" in policy_names

    def test_engine_initialization_with_custom_policies(self):
        """Test engine initializes with custom policies."""
        custom_policies = [
            EncryptionPolicy(name="Custom 1", priority=10),
            EncryptionPolicy(name="Custom 2", priority=20),
        ]
        engine = PolicyEngine(policies=custom_policies)
        policies = engine.get_policies()

        assert len(policies) == 2
        assert policies[0].name == "Custom 2"  # Higher priority first
        assert policies[1].name == "Custom 1"

    def test_policy_always_triggers(self, tmp_path):
        """Test ALWAYS trigger always matches."""
        policy = EncryptionPolicy(
            name="Always Encrypt",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.ENCRYPT,
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            result = engine.evaluate(pdf_path)

        assert result.triggered is True
        assert result.policy.name == "Always Encrypt"
        assert result.action == PolicyAction.ENCRYPT

    def test_policy_healthcare_mode_disabled_skips_evaluation(self, tmp_path):
        """Test policies are skipped when healthcare mode is disabled."""
        policy = EncryptionPolicy(
            name="Test",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.ENCRYPT,
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = False
            result = engine.evaluate(pdf_path)

        assert result.triggered is False
        assert "Healthcare mode disabled" in result.reason

    def test_policy_department_triggers_for_matching_dept(self, tmp_path):
        """Test DEPARTMENT trigger matches when department is in list."""
        policy = EncryptionPolicy(
            name="Medical Dept",
            trigger=PolicyTrigger.DEPARTMENT,
            action=PolicyAction.ENCRYPT,
            departments=["medical_records", "radiology"],
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            result = engine.evaluate(pdf_path, user_department="medical_records")

        assert result.triggered is True
        assert result.action == PolicyAction.ENCRYPT
        assert "medical_records" in result.reason

    def test_policy_department_ignores_other_dept(self, tmp_path):
        """Test DEPARTMENT trigger does not match other departments."""
        policy = EncryptionPolicy(
            name="Medical Dept",
            trigger=PolicyTrigger.DEPARTMENT,
            departments=["medical_records"],
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            result = engine.evaluate(pdf_path, user_department="accounting")

        assert result.triggered is False

    def test_policy_department_requires_user_department(self, tmp_path):
        """Test DEPARTMENT trigger requires user_department parameter."""
        policy = EncryptionPolicy(
            name="Medical Dept",
            trigger=PolicyTrigger.DEPARTMENT,
            departments=["medical_records"],
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            result = engine.evaluate(pdf_path, user_department=None)

        assert result.triggered is False

    def test_policy_phi_detected_triggers_on_ssn(self, tmp_path):
        """Test PHI_DETECTED trigger matches when SSN is found."""
        # Mock PHI scanner result
        mock_result = MagicMock()
        mock_result.has_phi = True
        mock_result.total_findings = 1
        mock_result.overall_confidence = MagicMock()
        mock_result.overall_confidence.value = "high"
        mock_result.by_type = {"ssn": []}

        # Mock Confidence enum with proper index support
        mock_low = MagicMock()
        mock_medium = MagicMock()
        mock_high = MagicMock()
        type(mock_low).__index__ = lambda self: 0
        type(mock_medium).__index__ = lambda self: 1
        type(mock_high).__index__ = lambda self: 2

        mock_result.overall_confidence = mock_high

        mock_scanner = MagicMock()
        mock_scanner.scan_pdf.return_value = mock_result

        # Create mock Confidence class
        def mock_confidence_class(value):
            if value == "low":
                return mock_low
            elif value == "medium":
                return mock_medium
            elif value == "high":
                return mock_high
            raise ValueError(f"Invalid confidence: {value}")

        policy = EncryptionPolicy(
            name="PHI Protection",
            trigger=PolicyTrigger.PHI_DETECTED,
            action=PolicyAction.ENCRYPT,
            min_confidence="medium",
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        # Mock the PHI module imports
        mock_phi_module = MagicMock()
        mock_phi_module.get_phi_scanner.return_value = mock_scanner
        mock_phi_module.Confidence = mock_confidence_class
        mock_phi_module.Confidence.LOW = mock_low
        mock_phi_module.Confidence.MEDIUM = mock_medium
        mock_phi_module.Confidence.HIGH = mock_high

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            with patch.dict("sys.modules", {"pdfsigner.core.phi": mock_phi_module}):
                result = engine.evaluate(pdf_path)

        assert result.triggered is True
        assert result.action == PolicyAction.ENCRYPT
        assert result.phi_scan_result is not None

    def test_policy_phi_detected_respects_confidence(self, tmp_path):
        """Test PHI_DETECTED trigger respects minimum confidence level."""
        # Mock PHI scanner result with low confidence
        mock_result = MagicMock()
        mock_result.has_phi = True

        # Create mock Confidence enum values with proper indexing
        mock_low = MagicMock()
        mock_medium = MagicMock()
        mock_high = MagicMock()
        type(mock_low).__index__ = lambda self: 0
        type(mock_medium).__index__ = lambda self: 1
        type(mock_high).__index__ = lambda self: 2

        # Set overall confidence to LOW (doesn't meet HIGH threshold)
        mock_result.overall_confidence = mock_low
        mock_result.by_type = {"ssn": []}

        mock_scanner = MagicMock()
        mock_scanner.scan_pdf.return_value = mock_result

        # Create mock Confidence class
        def mock_confidence_class(value):
            if value == "low":
                return mock_low
            elif value == "medium":
                return mock_medium
            elif value == "high":
                return mock_high
            raise ValueError(f"Invalid confidence: {value}")

        policy = EncryptionPolicy(
            name="PHI Protection",
            trigger=PolicyTrigger.PHI_DETECTED,
            min_confidence="high",  # Require HIGH confidence
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        # Mock the PHI module imports
        mock_phi_module = MagicMock()
        mock_phi_module.get_phi_scanner.return_value = mock_scanner
        mock_phi_module.Confidence = mock_confidence_class
        mock_phi_module.Confidence.LOW = mock_low
        mock_phi_module.Confidence.MEDIUM = mock_medium
        mock_phi_module.Confidence.HIGH = mock_high

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            with patch.dict("sys.modules", {"pdfsigner.core.phi": mock_phi_module}):
                result = engine.evaluate(pdf_path)

        # Should not trigger because confidence is too low (LOW < HIGH)
        assert result.triggered is False

    def test_policy_phi_scanner_not_available_skips_check(self, tmp_path):
        """Test PHI_DETECTED trigger is skipped when scanner unavailable."""
        policy = EncryptionPolicy(
            name="PHI Protection",
            trigger=PolicyTrigger.PHI_DETECTED,
            action=PolicyAction.ENCRYPT,
        )
        engine = PolicyEngine(policies=[policy])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        # Mock ImportError when trying to import PHI scanner
        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            # PHI scanner import will naturally fail if module doesn't exist
            result = engine.evaluate(pdf_path)

        # Should not trigger because PHI scanner is not available
        assert result.triggered is False

    def test_policy_priority_ordering(self, tmp_path):
        """Test policies are evaluated in priority order."""
        low_priority = EncryptionPolicy(
            name="Low Priority",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.WARN,
            priority=10,
        )
        high_priority = EncryptionPolicy(
            name="High Priority",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.ENCRYPT,
            priority=100,
        )

        # Add in reverse order to test sorting
        engine = PolicyEngine(policies=[low_priority, high_priority])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            result = engine.evaluate(pdf_path)

        # Should trigger high priority policy first
        assert result.triggered is True
        assert result.policy.name == "High Priority"
        assert result.action == PolicyAction.ENCRYPT

    def test_policy_disabled_not_evaluated(self, tmp_path):
        """Test disabled policies are skipped."""
        disabled = EncryptionPolicy(
            name="Disabled",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.ENCRYPT,
            enabled=False,
            priority=100,
        )
        enabled = EncryptionPolicy(
            name="Enabled",
            trigger=PolicyTrigger.ALWAYS,
            action=PolicyAction.WARN,
            enabled=True,
            priority=50,
        )

        engine = PolicyEngine(policies=[disabled, enabled])

        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_text("dummy")

        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            mock_settings.return_value.healthcare_mode = True
            result = engine.evaluate(pdf_path)

        # Should skip disabled and trigger enabled
        assert result.triggered is True
        assert result.policy.name == "Enabled"

    def test_add_policy(self):
        """Test adding policy to engine."""
        engine = PolicyEngine(policies=[])
        assert len(engine.get_policies()) == 0

        policy = EncryptionPolicy(name="New Policy", priority=50)
        engine.add_policy(policy)

        assert len(engine.get_policies()) == 1
        assert engine.get_policies()[0].name == "New Policy"

    def test_add_policy_maintains_priority_order(self):
        """Test adding policies maintains priority order."""
        engine = PolicyEngine(policies=[])

        low = EncryptionPolicy(name="Low", priority=10)
        high = EncryptionPolicy(name="High", priority=100)
        medium = EncryptionPolicy(name="Medium", priority=50)

        engine.add_policy(low)
        engine.add_policy(high)
        engine.add_policy(medium)

        policies = engine.get_policies()
        assert policies[0].name == "High"
        assert policies[1].name == "Medium"
        assert policies[2].name == "Low"

    def test_remove_policy_success(self):
        """Test removing existing policy."""
        policy = EncryptionPolicy(id="test-id", name="Test")
        engine = PolicyEngine(policies=[policy])

        removed = engine.remove_policy("test-id")

        assert removed is True
        assert len(engine.get_policies()) == 0

    def test_remove_policy_not_found(self):
        """Test removing non-existent policy."""
        policy = EncryptionPolicy(id="existing", name="Test")
        engine = PolicyEngine(policies=[policy])

        removed = engine.remove_policy("non-existent")

        assert removed is False
        assert len(engine.get_policies()) == 1

    def test_get_policies_returns_copy(self):
        """Test get_policies returns a copy of the list."""
        policy = EncryptionPolicy(name="Test")
        engine = PolicyEngine(policies=[policy])

        policies1 = engine.get_policies()
        policies2 = engine.get_policies()

        # Should be different list instances
        assert policies1 is not policies2
        # But contain same policy
        assert policies1[0] == policies2[0]


class TestPolicyEngineSingleton:
    """Tests for get_policy_engine singleton function."""

    def test_get_policy_engine_returns_instance(self):
        """Test get_policy_engine returns PolicyEngine."""
        engine = get_policy_engine()
        assert isinstance(engine, PolicyEngine)

    def test_get_policy_engine_returns_same_instance(self):
        """Test get_policy_engine returns singleton."""
        engine1 = get_policy_engine()
        engine2 = get_policy_engine()
        assert engine1 is engine2

    def test_singleton_has_default_policies(self):
        """Test singleton is initialized with default policies."""
        engine = get_policy_engine()
        policies = engine.get_policies()
        assert len(policies) > 0
