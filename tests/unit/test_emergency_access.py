"""
Tests for emergency access module.

Tests EmergencyAccessRequest, Repository, and BreakGlassService
for HIPAA compliance (§164.312(a)(2)(ii)).
"""

import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.emergency import (
    BreakGlassService,
    EmergencyAccessRepository,
    EmergencyAccessRequest,
    EmergencyAccessStatus,
    get_break_glass_service,
)


class TestEmergencyAccessStatus:
    """Tests for EmergencyAccessStatus enum."""

    def test_all_statuses_defined(self):
        """Test all required statuses are defined."""
        expected = {"pending", "approved", "denied", "expired", "revoked"}
        actual = {s.value for s in EmergencyAccessStatus}
        assert expected == actual

    def test_status_values(self):
        """Test status enum values."""
        assert EmergencyAccessStatus.PENDING.value == "pending"
        assert EmergencyAccessStatus.APPROVED.value == "approved"
        assert EmergencyAccessStatus.DENIED.value == "denied"
        assert EmergencyAccessStatus.EXPIRED.value == "expired"
        assert EmergencyAccessStatus.REVOKED.value == "revoked"


class TestEmergencyAccessRequest:
    """Tests for EmergencyAccessRequest dataclass."""

    def test_request_creation(self):
        """Test creating a request with required fields."""
        request = EmergencyAccessRequest(
            id=str(uuid.uuid4()),
            requester_id="user_123",
            reason="Patient emergency",
            status=EmergencyAccessStatus.PENDING,
            requested_at=datetime.now(),
        )
        assert request.requester_id == "user_123"
        assert request.reason == "Patient emergency"
        assert request.status == EmergencyAccessStatus.PENDING
        assert request.approved_by is None
        assert request.documents_accessed == []

    def test_request_is_active_when_approved_and_not_expired(self):
        """Test is_active returns True for valid approved request."""
        request = EmergencyAccessRequest(
            id=str(uuid.uuid4()),
            requester_id="user_123",
            reason="Emergency",
            status=EmergencyAccessStatus.APPROVED,
            requested_at=datetime.now(),
            approved_by="admin_456",
            approved_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=4),
        )
        assert request.is_active is True

    def test_request_is_not_active_when_pending(self):
        """Test is_active returns False for pending request."""
        request = EmergencyAccessRequest(
            id=str(uuid.uuid4()),
            requester_id="user_123",
            reason="Emergency",
            status=EmergencyAccessStatus.PENDING,
            requested_at=datetime.now(),
        )
        assert request.is_active is False

    def test_request_is_not_active_when_expired(self):
        """Test is_active returns False for expired request."""
        request = EmergencyAccessRequest(
            id=str(uuid.uuid4()),
            requester_id="user_123",
            reason="Emergency",
            status=EmergencyAccessStatus.APPROVED,
            requested_at=datetime.now() - timedelta(hours=5),
            approved_at=datetime.now() - timedelta(hours=5),
            expires_at=datetime.now() - timedelta(hours=1),
        )
        assert request.is_active is False

    def test_request_to_dict(self):
        """Test request serialization."""
        request_id = str(uuid.uuid4())
        request = EmergencyAccessRequest(
            id=request_id,
            requester_id="user_123",
            reason="Test reason",
            status=EmergencyAccessStatus.PENDING,
            requested_at=datetime.now(),
            documents_accessed=["/path/to/doc.pdf"],
        )
        data = request.to_dict()
        assert data["id"] == request_id
        assert data["requester_id"] == "user_123"
        assert data["reason"] == "Test reason"
        assert data["status"] == "pending"
        assert "/path/to/doc.pdf" in data["documents_accessed"]

    def test_request_from_dict(self):
        """Test request deserialization."""
        now = datetime.now()
        data = {
            "id": "test-id",
            "requester_id": "user_789",
            "reason": "Critical access needed",
            "status": "approved",
            "requested_at": now.isoformat(),
            "approved_by": "admin_001",
            "approved_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=4)).isoformat(),
            "documents_accessed": ["/doc1.pdf", "/doc2.pdf"],
        }
        request = EmergencyAccessRequest.from_dict(data)
        assert request.id == "test-id"
        assert request.requester_id == "user_789"
        assert request.status == EmergencyAccessStatus.APPROVED
        assert len(request.documents_accessed) == 2


class TestEmergencyAccessRepository:
    """Tests for EmergencyAccessRepository."""

    @pytest.fixture
    def temp_db(self, tmp_path: Path) -> Path:
        """Create temporary database path."""
        return tmp_path / "test_emergency.db"

    @pytest.fixture
    def repo(self, temp_db: Path) -> EmergencyAccessRepository:
        """Create repository with temp database."""
        return EmergencyAccessRepository(db_path=temp_db)

    def test_initialization(self, repo: EmergencyAccessRepository):
        """Test repository initializes correctly."""
        assert repo is not None
        assert repo.db_path.exists()

    def test_create_request(self, repo: EmergencyAccessRepository):
        """Test creating an emergency access request."""
        request = repo.create_request(
            requester_id="user_123",
            reason="Patient in critical condition",
        )
        assert request is not None
        assert request.requester_id == "user_123"
        assert request.status == EmergencyAccessStatus.PENDING

    def test_get_request(self, repo: EmergencyAccessRepository):
        """Test retrieving a request by ID."""
        created = repo.create_request("user_123", "Emergency")
        retrieved = repo.get_request(created.id)
        assert retrieved is not None
        assert retrieved.id == created.id

    def test_get_nonexistent_request(self, repo: EmergencyAccessRepository):
        """Test getting nonexistent request returns None."""
        result = repo.get_request("nonexistent-id")
        assert result is None

    def test_get_pending_requests(self, repo: EmergencyAccessRepository):
        """Test getting all pending requests."""
        repo.create_request("user_1", "Emergency 1")
        repo.create_request("user_2", "Emergency 2")

        pending = repo.get_pending_requests()
        assert len(pending) == 2
        for req in pending:
            assert req.status == EmergencyAccessStatus.PENDING

    def test_get_user_requests(self, repo: EmergencyAccessRepository):
        """Test getting requests for specific user."""
        repo.create_request("user_123", "Emergency 1")
        repo.create_request("user_123", "Emergency 2")
        repo.create_request("user_456", "Other emergency")

        user_requests = repo.get_user_requests("user_123")
        assert len(user_requests) == 2

    def test_update_request(self, repo: EmergencyAccessRepository):
        """Test updating a request."""
        request = repo.create_request("user_123", "Emergency")
        request.status = EmergencyAccessStatus.APPROVED
        request.approved_by = "admin_789"
        request.approved_at = datetime.now()
        request.expires_at = datetime.now() + timedelta(hours=4)

        repo.update_request(request)

        updated = repo.get_request(request.id)
        assert updated is not None
        assert updated.status == EmergencyAccessStatus.APPROVED
        assert updated.approved_by == "admin_789"


class TestBreakGlassService:
    """Tests for BreakGlassService."""

    @pytest.fixture
    def temp_db(self, tmp_path: Path) -> Path:
        """Create temporary database path."""
        return tmp_path / "test_breakglass.db"

    @pytest.fixture
    def service(self, temp_db: Path) -> BreakGlassService:
        """Create service with temp database."""
        repo = EmergencyAccessRepository(db_path=temp_db)
        return BreakGlassService(repository=repo)

    def test_request_emergency_access(self, service: BreakGlassService):
        """Test requesting emergency access."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access(
                requester_id="user_123",
                reason="Critical patient situation",
            )
            assert request is not None
            assert request.status == EmergencyAccessStatus.PENDING

    def test_request_emergency_access_auto_approve(self, temp_db: Path):
        """Test auto-approval when require_approval is False."""
        repo = EmergencyAccessRepository(db_path=temp_db)
        service = BreakGlassService(repository=repo)
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=False,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access(
                requester_id="user_123",
                reason="Urgent access needed",
            )
            assert request.status == EmergencyAccessStatus.APPROVED

    def test_approve_request(self, service: BreakGlassService):
        """Test approving an emergency access request."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access("user_123", "Emergency")
            approved = service.approve_request(request.id, admin_id="admin_456")

            assert approved.status == EmergencyAccessStatus.APPROVED
            assert approved.approved_by == "admin_456"
            assert approved.expires_at is not None

    def test_deny_request(self, service: BreakGlassService):
        """Test denying an emergency access request."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access("user_123", "Emergency")
            denied = service.deny_request(request.id, admin_id="admin_456")

            assert denied.status == EmergencyAccessStatus.DENIED

    def test_revoke_access(self, service: BreakGlassService):
        """Test revoking approved access."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access("user_123", "Emergency")
            approved = service.approve_request(request.id, "admin_456")
            revoked = service.revoke_access(approved.id, admin_id="admin_789")

            assert revoked.status == EmergencyAccessStatus.REVOKED
            assert revoked.revoked_by == "admin_789"

    def test_check_emergency_access_true(self, service: BreakGlassService):
        """Test check returns True for user with active access."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access("user_123", "Emergency")
            service.approve_request(request.id, "admin_456")

            has_access = service.check_emergency_access("user_123")
            assert has_access is True

    def test_check_emergency_access_false(self, service: BreakGlassService):
        """Test check returns False for user without access."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        has_access = service.check_emergency_access("user_without_access")
        assert has_access is False

    def test_check_emergency_access_healthcare_disabled(self, service: BreakGlassService):
        """Test check returns False when healthcare_mode is disabled."""
        service.settings = MagicMock(healthcare_mode=False)
        has_access = service.check_emergency_access("any_user")
        assert has_access is False

    def test_log_document_access(self, service: BreakGlassService):
        """Test logging document access."""
        service.settings = MagicMock(
            healthcare_mode=True,
            healthcare_emergency_duration_hours=4,
            healthcare_emergency_require_approval=True,
        )
        with patch.object(service, "audit_logger"):
            request = service.request_emergency_access("user_123", "Emergency")
            approved = service.approve_request(request.id, "admin_456")

            service.log_document_access(approved.id, "/path/to/patient_record.pdf")

            # Retrieve and check
            updated = service.repository.get_request(approved.id)
            assert "/path/to/patient_record.pdf" in updated.documents_accessed


class TestBreakGlassServiceSingleton:
    """Tests for singleton pattern."""

    def test_get_break_glass_service_returns_instance(self):
        """Test get_break_glass_service returns a BreakGlassService."""
        service = get_break_glass_service()
        assert isinstance(service, BreakGlassService)

    def test_get_break_glass_service_returns_same_instance(self):
        """Test singleton returns same instance."""
        import pdfsigner.core.emergency.break_glass as bg

        bg._break_glass_service = None

        service1 = get_break_glass_service()
        service2 = get_break_glass_service()
        assert service1 is service2
