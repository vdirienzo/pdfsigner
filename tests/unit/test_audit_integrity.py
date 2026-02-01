"""Tests for audit integrity protection."""

import json

import pytest

from pdfsigner.core.audit import (
    AuditEvent,
    AuditEventType,
    AuditIntegrityManager,
    get_audit_integrity_manager,
    verify_audit_integrity,
)


class TestAuditIntegrityManager:
    """Tests for AuditIntegrityManager class."""

    @pytest.fixture
    def manager(self):
        """Create fresh integrity manager with known secret."""
        return AuditIntegrityManager(secret_key=b"test_secret_key_32bytes_long!!")

    @pytest.fixture
    def sample_event(self):
        """Create sample audit event."""
        return AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            user_id="user123",
            session_id="session456",
            document_path="/path/to/doc.pdf",
        )

    def test_sign_event_adds_hash(self, manager, sample_event):
        """Test signing adds record hash."""
        signed = manager.sign_event(sample_event)

        assert signed.record_hash is not None
        assert len(signed.record_hash) == 64  # SHA-256 hex

    def test_sign_event_adds_hmac(self, manager, sample_event):
        """Test signing adds HMAC signature."""
        signed = manager.sign_event(sample_event)

        assert signed.hmac_signature is not None
        assert len(signed.hmac_signature) == 64  # HMAC-SHA256 hex

    def test_sign_event_chains_hashes(self, manager, sample_event):
        """Test events are chained via previous_hash."""
        event1 = AuditEvent(event_type=AuditEventType.SESSION_START)
        event2 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)

        signed1 = manager.sign_event(event1)
        signed2 = manager.sign_event(event2)

        assert signed1.previous_hash is None  # First event
        assert signed2.previous_hash == signed1.record_hash  # Chained

    def test_verify_event_valid(self, manager, sample_event):
        """Test verification passes for valid event."""
        signed = manager.sign_event(sample_event)

        is_valid, reason = manager.verify_event(signed)

        assert is_valid is True
        assert reason == "Valid"

    def test_verify_event_detects_tampered_content(self, manager, sample_event):
        """Test verification fails if content modified."""
        signed = manager.sign_event(sample_event)

        # Tamper with content
        signed.document_path = "/tampered/path.pdf"

        is_valid, reason = manager.verify_event(signed)

        assert is_valid is False
        assert "hash mismatch" in reason.lower()

    def test_verify_event_detects_tampered_hash(self, manager, sample_event):
        """Test verification fails if hash modified."""
        signed = manager.sign_event(sample_event)

        # Tamper with hash
        signed.record_hash = "a" * 64

        is_valid, reason = manager.verify_event(signed)

        assert is_valid is False

    def test_verify_chain_valid(self, manager):
        """Test chain verification passes for valid chain."""
        events = []
        for i in range(5):
            event = AuditEvent(
                event_type=AuditEventType.SIGN_SUCCESS,
                user_id=f"user{i}",
            )
            signed = manager.sign_event(event)
            events.append(signed)

        is_valid, issues = manager.verify_chain(events)

        assert is_valid is True
        assert len(issues) == 0

    def test_verify_chain_detects_broken_link(self, manager):
        """Test chain verification detects broken chain."""
        event1 = manager.sign_event(AuditEvent(event_type=AuditEventType.SESSION_START))
        event2 = manager.sign_event(AuditEvent(event_type=AuditEventType.SIGN_SUCCESS))

        # Break the chain
        event2.previous_hash = "broken_hash"

        is_valid, issues = manager.verify_chain([event1, event2])

        assert is_valid is False
        assert any("chain" in str(issue).lower() for issue in issues)

    def test_verify_event_missing_hash_fails(self, manager, sample_event):
        """Test verification fails without hash."""
        is_valid, reason = manager.verify_event(sample_event)

        assert is_valid is False
        assert "missing" in reason.lower()


class TestVerifyAuditFile:
    """Tests for file verification."""

    @pytest.fixture
    def manager(self):
        """Create integrity manager."""
        return AuditIntegrityManager(secret_key=b"test_secret_key_32bytes_long!!")

    def test_verify_valid_file(self, manager, tmp_path):
        """Test verification of valid audit file."""
        audit_file = tmp_path / "audit_test.jsonl"

        # Create valid audit file
        events = []
        for i in range(3):
            event = AuditEvent(
                event_type=AuditEventType.SIGN_SUCCESS,
                user_id=f"user{i}",
            )
            signed = manager.sign_event(event)
            events.append(signed)

        with open(audit_file, "w") as f:
            for event in events:
                f.write(json.dumps(event.to_dict()) + "\n")

        # Verify
        is_valid, report = manager.verify_audit_file(audit_file)

        assert is_valid is True
        assert report["total_records"] == 3
        assert report["chain_intact"] is True

    def test_verify_nonexistent_file(self, manager, tmp_path):
        """Test verification of missing file."""
        is_valid, report = manager.verify_audit_file(tmp_path / "missing.jsonl")

        assert is_valid is False
        assert any("not found" in str(i).lower() for i in report["issues"])

    def test_verify_file_with_corrupted_line(self, manager, tmp_path):
        """Test verification handles corrupted JSON lines."""
        audit_file = tmp_path / "audit_corrupt.jsonl"

        event = manager.sign_event(AuditEvent(event_type=AuditEventType.SIGN_SUCCESS))

        with open(audit_file, "w") as f:
            f.write(json.dumps(event.to_dict()) + "\n")
            f.write("not valid json\n")
            f.write(json.dumps(event.to_dict()) + "\n")

        is_valid, report = manager.verify_audit_file(audit_file)

        # Should report the corrupted line
        assert any("parse" in str(i).lower() for i in report["issues"])


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_get_audit_integrity_manager_singleton(self):
        """Test singleton returns same instance."""
        manager1 = get_audit_integrity_manager()
        manager2 = get_audit_integrity_manager()

        assert manager1 is manager2

    def test_verify_audit_integrity_function(self, tmp_path):
        """Test convenience function works."""
        audit_file = tmp_path / "audit.jsonl"
        audit_file.write_text("")

        is_valid, report = verify_audit_integrity(audit_file)

        assert isinstance(is_valid, bool)
        assert isinstance(report, dict)
        assert "total_records" in report
