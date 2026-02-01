"""
Tests for retention management module.

Tests RetentionPolicy, RetentionResult, and RetentionManager for HIPAA compliance.
"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from pdfsigner.core.retention import (
    RetentionAction,
    RetentionManager,
    RetentionPolicy,
    RetentionResult,
    RetentionTarget,
    get_retention_manager,
)


class TestRetentionTarget:
    """Tests for RetentionTarget enum."""

    def test_retention_target_values(self):
        """Test RetentionTarget enum has expected values."""
        assert RetentionTarget.AUDIT_LOGS == "audit_logs"
        assert RetentionTarget.TEMP_FILES == "temp_files"
        assert RetentionTarget.SESSION_DATA == "session_data"
        assert RetentionTarget.REPORTS == "reports"

    def test_retention_target_is_string(self):
        """Test RetentionTarget values are strings."""
        assert isinstance(RetentionTarget.AUDIT_LOGS.value, str)
        assert isinstance(RetentionTarget.TEMP_FILES.value, str)


class TestRetentionAction:
    """Tests for RetentionAction enum."""

    def test_retention_action_values(self):
        """Test RetentionAction enum has expected values."""
        assert RetentionAction.DELETE == "delete"
        assert RetentionAction.ARCHIVE == "archive"
        assert RetentionAction.ANONYMIZE == "anonymize"

    def test_retention_action_is_string(self):
        """Test RetentionAction values are strings."""
        assert isinstance(RetentionAction.DELETE.value, str)
        assert isinstance(RetentionAction.ARCHIVE.value, str)


class TestRetentionPolicy:
    """Tests for RetentionPolicy dataclass."""

    def test_retention_policy_creation(self):
        """Test creating a retention policy with default values."""
        policy = RetentionPolicy(
            name="Test Policy",
            description="Test description",
            target=RetentionTarget.TEMP_FILES,
            retention_days=30,
            action=RetentionAction.DELETE,
        )
        assert policy.name == "Test Policy"
        assert policy.description == "Test description"
        assert policy.target == RetentionTarget.TEMP_FILES
        assert policy.retention_days == 30
        assert policy.action == RetentionAction.DELETE
        assert policy.enabled is True
        assert policy.hipaa_reference == ""
        assert isinstance(policy.id, str)
        assert isinstance(policy.created_at, datetime)

    def test_retention_policy_with_hipaa_reference(self):
        """Test creating policy with HIPAA reference."""
        policy = RetentionPolicy(
            name="HIPAA Policy",
            target=RetentionTarget.AUDIT_LOGS,
            retention_days=2190,
            action=RetentionAction.ARCHIVE,
            hipaa_reference="§164.530(j)",
        )
        assert policy.hipaa_reference == "§164.530(j)"
        assert policy.retention_days == 2190

    def test_retention_policy_serialization(self):
        """Test policy serialization to dict."""
        policy = RetentionPolicy(
            name="Test Policy",
            target=RetentionTarget.REPORTS,
            retention_days=90,
            action=RetentionAction.ARCHIVE,
        )
        data = policy.to_dict()

        assert data["name"] == "Test Policy"
        assert data["target"] == "reports"
        assert data["retention_days"] == 90
        assert data["action"] == "archive"
        assert "id" in data
        assert "created_at" in data

    def test_retention_policy_deserialization(self):
        """Test policy deserialization from dict."""
        now = datetime.now()
        data = {
            "id": "test-id-123",
            "name": "Test Policy",
            "description": "Test description",
            "target": "audit_logs",
            "retention_days": 2190,
            "action": "archive",
            "enabled": True,
            "hipaa_reference": "§164.530(j)",
            "created_at": now.isoformat(),
        }
        policy = RetentionPolicy.from_dict(data)

        assert policy.id == "test-id-123"
        assert policy.name == "Test Policy"
        assert policy.target == RetentionTarget.AUDIT_LOGS
        assert policy.retention_days == 2190
        assert policy.action == RetentionAction.ARCHIVE
        assert policy.hipaa_reference == "§164.530(j)"


class TestRetentionResult:
    """Tests for RetentionResult dataclass."""

    def test_retention_result_creation(self):
        """Test creating a retention result."""
        started = datetime.now()
        completed = started + timedelta(seconds=5)

        result = RetentionResult(
            policy_id="policy-123",
            policy_name="Test Policy",
            target=RetentionTarget.TEMP_FILES,
            action=RetentionAction.DELETE,
            items_processed=100,
            items_deleted=95,
            items_archived=0,
            items_failed=5,
            started_at=started,
            completed_at=completed,
            errors=["Error 1", "Error 2"],
        )

        assert result.policy_id == "policy-123"
        assert result.policy_name == "Test Policy"
        assert result.items_processed == 100
        assert result.items_deleted == 95
        assert result.items_failed == 5
        assert len(result.errors) == 2
        assert result.duration_seconds == pytest.approx(5.0, abs=0.1)

    def test_retention_result_duration_calculation(self):
        """Test duration calculation."""
        started = datetime.now()
        completed = started + timedelta(seconds=10.5)

        result = RetentionResult(
            policy_id="policy-123",
            policy_name="Test",
            target=RetentionTarget.REPORTS,
            action=RetentionAction.DELETE,
            items_processed=0,
            items_deleted=0,
            items_archived=0,
            items_failed=0,
            started_at=started,
            completed_at=completed,
        )

        assert result.duration_seconds == pytest.approx(10.5, abs=0.1)

    def test_retention_result_serialization(self):
        """Test result serialization to dict."""
        started = datetime.now()
        completed = started + timedelta(seconds=5)

        result = RetentionResult(
            policy_id="policy-123",
            policy_name="Test Policy",
            target=RetentionTarget.TEMP_FILES,
            action=RetentionAction.DELETE,
            items_processed=100,
            items_deleted=95,
            items_archived=0,
            items_failed=5,
            started_at=started,
            completed_at=completed,
            errors=["Error 1"],
        )

        data = result.to_dict()

        assert data["policy_id"] == "policy-123"
        assert data["policy_name"] == "Test Policy"
        assert data["target"] == "temp_files"
        assert data["action"] == "delete"
        assert data["items_processed"] == 100
        assert data["items_deleted"] == 95
        assert data["items_failed"] == 5
        assert "duration_seconds" in data


class TestRetentionManager:
    """Tests for RetentionManager class."""

    @pytest.fixture
    def temp_db(self, tmp_path: Path) -> Path:
        """Create temporary database path."""
        return tmp_path / "test_retention.db"

    @pytest.fixture
    def manager(self, temp_db: Path) -> RetentionManager:
        """Create RetentionManager with temp database."""
        return RetentionManager(db_path=temp_db)

    def test_manager_initialization(self, manager: RetentionManager):
        """Test RetentionManager initializes correctly."""
        assert manager is not None
        assert manager.db_path.exists()

    def test_manager_creates_default_policies(self, manager: RetentionManager):
        """Test manager creates default HIPAA policies."""
        policies = manager.list_policies()
        assert len(policies) >= 4  # At least 4 default policies

        # Check for HIPAA audit log policy
        audit_policies = [p for p in policies if p.target == RetentionTarget.AUDIT_LOGS]
        assert len(audit_policies) >= 1
        assert any(p.retention_days == 2190 for p in audit_policies)  # 6 years

    def test_add_policy(self, manager: RetentionManager):
        """Test adding a new retention policy."""
        policy = RetentionPolicy(
            name="Custom Policy",
            description="Custom retention policy",
            target=RetentionTarget.REPORTS,
            retention_days=60,
            action=RetentionAction.DELETE,
        )

        created = manager.add_policy(policy)
        assert created.id == policy.id
        assert created.name == "Custom Policy"

        # Verify it was saved
        retrieved = manager.get_policy(created.id)
        assert retrieved is not None
        assert retrieved.name == "Custom Policy"

    def test_get_policy(self, manager: RetentionManager):
        """Test retrieving a policy by ID."""
        policies = manager.list_policies()
        assert len(policies) > 0

        first_policy = policies[0]
        retrieved = manager.get_policy(first_policy.id)

        assert retrieved is not None
        assert retrieved.id == first_policy.id
        assert retrieved.name == first_policy.name

    def test_get_nonexistent_policy(self, manager: RetentionManager):
        """Test getting a policy that doesn't exist returns None."""
        result = manager.get_policy("nonexistent-id")
        assert result is None

    def test_list_policies(self, manager: RetentionManager):
        """Test listing all retention policies."""
        policies = manager.list_policies()
        assert len(policies) >= 4  # Default policies

        # Verify all are RetentionPolicy instances
        for policy in policies:
            assert isinstance(policy, RetentionPolicy)

    def test_list_policies_enabled_only(self, manager: RetentionManager):
        """Test listing only enabled policies."""
        # Create a disabled policy
        policy = RetentionPolicy(
            name="Disabled Policy",
            target=RetentionTarget.REPORTS,
            retention_days=30,
            action=RetentionAction.DELETE,
            enabled=False,
        )
        manager.add_policy(policy)

        all_policies = manager.list_policies(enabled_only=False)
        enabled_policies = manager.list_policies(enabled_only=True)

        assert len(all_policies) > len(enabled_policies)

    def test_update_policy(self, manager: RetentionManager):
        """Test updating an existing policy."""
        # Create a policy
        policy = RetentionPolicy(
            name="Original Name",
            target=RetentionTarget.REPORTS,
            retention_days=30,
            action=RetentionAction.DELETE,
        )
        created = manager.add_policy(policy)

        # Update it
        created.name = "Updated Name"
        created.retention_days = 60
        updated = manager.update_policy(created)

        assert updated.name == "Updated Name"
        assert updated.retention_days == 60

        # Verify changes were saved
        retrieved = manager.get_policy(created.id)
        assert retrieved is not None
        assert retrieved.name == "Updated Name"
        assert retrieved.retention_days == 60

    def test_delete_policy(self, manager: RetentionManager):
        """Test deleting a non-HIPAA policy."""
        # Create a policy without HIPAA reference
        policy = RetentionPolicy(
            name="Deletable Policy",
            target=RetentionTarget.REPORTS,
            retention_days=30,
            action=RetentionAction.DELETE,
        )
        created = manager.add_policy(policy)

        # Delete it
        success = manager.delete_policy(created.id)
        assert success is True

        # Verify it was deleted
        retrieved = manager.get_policy(created.id)
        assert retrieved is None

    def test_cannot_delete_hipaa_policy(self, manager: RetentionManager):
        """Test cannot delete HIPAA-required policy."""
        # Find a HIPAA policy
        policies = manager.list_policies()
        hipaa_policy = next((p for p in policies if p.hipaa_reference), None)
        assert hipaa_policy is not None

        # Try to delete it
        success = manager.delete_policy(hipaa_policy.id)
        assert success is False

        # Verify it still exists
        retrieved = manager.get_policy(hipaa_policy.id)
        assert retrieved is not None

    def test_execute_temp_file_cleanup(self, manager: RetentionManager):
        """Test executing temp file cleanup policy."""
        # Find temp file policy
        policies = manager.list_policies()
        temp_policy = next((p for p in policies if p.target == RetentionTarget.TEMP_FILES), None)
        assert temp_policy is not None

        # Run cleanup (may not actually clean anything in test)
        results = manager.run_cleanup(policy_id=temp_policy.id)

        assert len(results) == 1
        result = results[0]
        assert result.policy_id == temp_policy.id
        assert result.policy_name == temp_policy.name
        assert result.target == RetentionTarget.TEMP_FILES
        assert result.items_processed >= 0

    def test_record_history(self, manager: RetentionManager):
        """Test recording cleanup history."""
        # Run cleanup to generate history
        policies = manager.list_policies(enabled_only=True)
        assert len(policies) > 0

        results = manager.run_cleanup(policy_id=policies[0].id)
        assert len(results) > 0

        # Check history was recorded
        history = manager.get_history(limit=10)
        assert len(history) > 0

        record = history[0]
        assert "policy_id" in record
        assert "items_processed" in record
        assert "started_at" in record
        assert "completed_at" in record

    def test_get_history_filtered_by_policy(self, manager: RetentionManager):
        """Test getting history filtered by policy ID."""
        policies = manager.list_policies(enabled_only=True)
        assert len(policies) > 0

        # Run cleanup for first policy
        policy_id = policies[0].id
        manager.run_cleanup(policy_id=policy_id)

        # Get history for that policy
        history = manager.get_history(policy_id=policy_id, limit=10)
        assert len(history) > 0

        # All records should be for the same policy
        for record in history:
            assert record["policy_id"] == policy_id


class TestRetentionManagerSingleton:
    """Tests for singleton pattern."""

    def test_get_retention_manager_returns_instance(self):
        """Test get_retention_manager returns a RetentionManager."""
        manager = get_retention_manager()
        assert isinstance(manager, RetentionManager)

    def test_get_retention_manager_returns_same_instance(self):
        """Test singleton returns same instance."""
        # Reset singleton for test
        import pdfsigner.core.retention.retention_manager as rm

        rm._retention_manager = None

        manager1 = get_retention_manager()
        manager2 = get_retention_manager()
        assert manager1 is manager2

    def test_hipaa_audit_retention_constant(self):
        """Test HIPAA audit retention constant is 6 years."""
        assert RetentionManager.HIPAA_AUDIT_RETENTION_DAYS == 2190  # 6 years * 365 days
