"""Tests for SOC 2 evidence collector."""

from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.compliance.evidence_collector import EvidenceCollector, get_evidence_collector
from pdfsigner.core.compliance.evidence_types import (
    Evidence,
    EvidenceCategory,
    EvidenceCollection,
    EvidenceType,
)
from pdfsigner.core.compliance.soc2_report import ControlStatus, generate_report
from pdfsigner.core.users.user_model import User, UserRole, UserStatus


class TestEvidenceTypes:
    """Tests for evidence type definitions."""

    def test_evidence_category_enum_values(self):
        """Test evidence category enum has expected values."""
        assert EvidenceCategory.CC1_CONTROL_ENVIRONMENT.value == "cc1"
        assert EvidenceCategory.CC6_LOGICAL_ACCESS.value == "cc6"
        assert EvidenceCategory.CC7_SYSTEM_OPERATIONS.value == "cc7"

    def test_evidence_type_enum_values(self):
        """Test evidence type enum has expected values."""
        assert EvidenceType.ACCESS_LOG.value == "access_log"
        assert EvidenceType.AUDIT_LOG.value == "audit_log"
        assert EvidenceType.CONFIG_SNAPSHOT.value == "config_snapshot"

    def test_evidence_creation(self):
        """Test creating evidence object."""
        now = datetime.now()
        evidence = Evidence(
            id="test-123",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.ACCESS_LOG,
            title="Test Evidence",
            description="Test description",
            collected_at=now,
            period_start=now - timedelta(days=30),
            period_end=now,
            data={"key": "value"},
        )

        assert evidence.id == "test-123"
        assert evidence.category == EvidenceCategory.CC6_LOGICAL_ACCESS
        assert evidence.evidence_type == EvidenceType.ACCESS_LOG
        assert evidence.title == "Test Evidence"
        assert evidence.data["key"] == "value"

    def test_evidence_serialization(self):
        """Test evidence to_dict and from_dict."""
        now = datetime.now()
        evidence = Evidence(
            id="test-123",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.ACCESS_LOG,
            title="Test Evidence",
            description="Test description",
            collected_at=now,
            period_start=now - timedelta(days=30),
            period_end=now,
            data={"key": "value"},
            checksum="abc123",
        )

        # Serialize
        data = evidence.to_dict()
        assert data["id"] == "test-123"
        assert data["category"] == "cc6"
        assert data["evidence_type"] == "access_log"
        assert data["checksum"] == "abc123"

        # Deserialize
        restored = Evidence.from_dict(data)
        assert restored.id == evidence.id
        assert restored.category == evidence.category
        assert restored.evidence_type == evidence.evidence_type


class TestEvidenceCollection:
    """Tests for evidence collection."""

    def test_evidence_collection_creation(self):
        """Test creating evidence collection."""
        now = datetime.now()
        collection = EvidenceCollection(
            period_start=now - timedelta(days=30),
            period_end=now,
            collected_at=now,
        )

        assert collection.evidence_items == []
        assert collection.summary == {}

    def test_add_evidence_to_collection(self):
        """Test adding evidence to collection."""
        now = datetime.now()
        collection = EvidenceCollection(
            period_start=now - timedelta(days=30),
            period_end=now,
            collected_at=now,
        )

        evidence = Evidence(
            id="test-123",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.ACCESS_LOG,
            title="Test",
            description="Test",
            collected_at=now,
            period_start=now - timedelta(days=30),
            period_end=now,
            data={},
        )

        collection.add_evidence(evidence)
        assert len(collection.evidence_items) == 1
        assert collection.evidence_items[0].id == "test-123"

    def test_get_evidence_by_category(self):
        """Test filtering evidence by category."""
        now = datetime.now()
        collection = EvidenceCollection(
            period_start=now - timedelta(days=30),
            period_end=now,
            collected_at=now,
        )

        # Add evidence from different categories
        for i, category in enumerate(
            [
                EvidenceCategory.CC6_LOGICAL_ACCESS,
                EvidenceCategory.CC7_SYSTEM_OPERATIONS,
                EvidenceCategory.CC6_LOGICAL_ACCESS,
            ]
        ):
            evidence = Evidence(
                id=f"test-{i}",
                category=category,
                evidence_type=EvidenceType.ACCESS_LOG,
                title=f"Test {i}",
                description="Test",
                collected_at=now,
                period_start=now - timedelta(days=30),
                period_end=now,
                data={},
            )
            collection.add_evidence(evidence)

        # Filter
        cc6_evidence = collection.get_by_category(EvidenceCategory.CC6_LOGICAL_ACCESS)
        assert len(cc6_evidence) == 2


class TestEvidenceCollector:
    """Tests for evidence collector."""

    @pytest.fixture
    def mock_audit_logger(self):
        """Mock audit logger."""
        logger = Mock()
        logger.get_events.return_value = []
        logger.get_events_filtered.return_value = []
        logger.retention_days = 90
        return logger

    @pytest.fixture
    def mock_user_repository(self):
        """Mock user repository."""
        repo = Mock()
        repo.list_users.return_value = []
        return repo

    @pytest.fixture
    def mock_settings(self):
        """Mock settings."""
        settings = Mock()
        settings.encryption_enabled = True
        settings.encryption_strength = "aes256"
        settings.fips_mode_enabled = False
        settings.tls_enabled = False
        settings.tls_min_version = "TLSv1.2"
        settings.healthcare_mode = False
        settings.healthcare_session_timeout_minutes = 15
        settings.healthcare_max_sessions = 3
        settings.encryption_hipaa_mode = False
        settings.sign_events = False
        settings.mfa_enabled = False
        return settings

    @pytest.fixture
    def collector(self, mock_audit_logger, mock_user_repository, mock_settings):
        """Create evidence collector with mocks."""
        return EvidenceCollector(
            audit_logger=mock_audit_logger,
            user_repository=mock_user_repository,
            settings=mock_settings,
        )

    def test_collect_access_logs_empty(self, collector):
        """Test collecting access logs when no events exist."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        evidence = collector.collect_access_logs(start, end)

        assert evidence.category == EvidenceCategory.CC6_LOGICAL_ACCESS
        assert evidence.evidence_type == EvidenceType.ACCESS_LOG
        assert evidence.period_start == start
        assert evidence.period_end == end
        assert evidence.data["summary"]["total_events"] == 0

    def test_collect_access_logs_with_events(self, collector, mock_audit_logger):
        """Test collecting access logs with events."""
        # Create mock events
        now = datetime.now()
        events = [
            AuditEvent(
                event_type=AuditEventType.SIGN_SUCCESS,
                status="SUCCESS",
                user_id="user1",
                timestamp=now - timedelta(days=i),
            )
            for i in range(5)
        ]
        mock_audit_logger.get_events.return_value = events

        start = now - timedelta(days=30)
        end = now

        evidence = collector.collect_access_logs(start, end)

        assert evidence.data["summary"]["total_events"] == 5
        assert evidence.data["summary"]["unique_users"] == 1
        assert evidence.data["summary"]["success_count"] == 5

    def test_collect_audit_logs(self, collector, mock_audit_logger):
        """Test collecting audit logs."""
        now = datetime.now()
        events = [
            AuditEvent(
                event_type=AuditEventType.SIGN_SUCCESS,
                status="SUCCESS",
                phi_accessed=True,
                timestamp=now - timedelta(days=i),
            )
            for i in range(10)
        ]
        mock_audit_logger.get_events.return_value = events

        start = now - timedelta(days=30)
        end = now

        evidence = collector.collect_audit_logs(start, end)

        assert evidence.category == EvidenceCategory.CC7_SYSTEM_OPERATIONS
        assert evidence.evidence_type == EvidenceType.AUDIT_LOG
        assert evidence.data["analysis"]["total_events"] == 10
        assert evidence.data["analysis"]["phi_access_events"] == 10

    def test_collect_config_snapshot(self, collector, mock_settings):
        """Test collecting configuration snapshot."""
        evidence = collector.collect_config_snapshot()

        assert evidence.category == EvidenceCategory.CC5_CONTROL_ACTIVITIES
        assert evidence.evidence_type == EvidenceType.CONFIG_SNAPSHOT
        assert "security" in evidence.data
        assert "access_control" in evidence.data
        assert evidence.data["security"]["encryption_enabled"] is True
        assert evidence.checksum is not None

    def test_collect_user_access_review_empty(self, collector):
        """Test collecting user access review with no users."""
        evidence = collector.collect_user_access_review()

        assert evidence.category == EvidenceCategory.CC6_LOGICAL_ACCESS
        assert evidence.evidence_type == EvidenceType.USER_ACCESS_REVIEW
        assert evidence.data["summary"]["total_users"] == 0

    def test_collect_user_access_review_with_users(self, collector, mock_user_repository):
        """Test collecting user access review with users."""
        # Create mock users
        now = datetime.now()
        users = [
            User(
                id=f"user-{i}",
                username=f"user{i}",
                role=UserRole.SIGNER,
                status=UserStatus.ACTIVE,
                created_at=now - timedelta(days=365),
                updated_at=now,
                last_login_at=now - timedelta(days=i),
            )
            for i in range(3)
        ]
        mock_user_repository.list_users.return_value = users

        evidence = collector.collect_user_access_review()

        assert evidence.data["summary"]["total_users"] == 3
        assert evidence.data["summary"]["active_users"] == 3
        assert len(evidence.data["users"]) == 3

    def test_collect_incident_logs(self, collector, mock_audit_logger):
        """Test collecting incident logs."""
        now = datetime.now()
        events = [
            AuditEvent(
                event_type=AuditEventType.SIGN_FAILURE,
                status="FAILURE",
                error_message="Test error",
                phi_accessed=True,
                timestamp=now - timedelta(hours=i),
            )
            for i in range(3)
        ]
        mock_audit_logger.get_events_filtered.return_value = events

        start = now - timedelta(days=7)
        end = now

        evidence = collector.collect_incident_logs(start, end)

        assert evidence.category == EvidenceCategory.CC9_RISK_MITIGATION
        assert evidence.evidence_type == EvidenceType.INCIDENT_LOG
        assert evidence.data["summary"]["total_incidents"] == 3
        assert evidence.data["summary"]["high_severity"] == 3  # PHI accessed

    def test_generate_quarterly_access_review(self, collector):
        """Test generating quarterly access review."""
        evidence = collector.generate_quarterly_access_review(quarter=1, year=2026)

        assert evidence.category == EvidenceCategory.CC6_LOGICAL_ACCESS
        assert evidence.evidence_type == EvidenceType.USER_ACCESS_REVIEW
        assert "Q1 2026" in evidence.title
        assert evidence.data["quarter"] == 1
        assert evidence.data["year"] == 2026

    def test_collect_all_evidence(self, collector):
        """Test collecting all evidence types."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        collection = collector.collect_all_evidence(start, end)

        assert len(collection.evidence_items) == 5  # 5 evidence types
        assert collection.summary["total_evidence"] == 5
        assert "by_category" in collection.summary
        assert "by_type" in collection.summary

    def test_get_evidence_collector_singleton(self):
        """Test evidence collector singleton."""
        collector1 = get_evidence_collector()
        collector2 = get_evidence_collector()

        assert collector1 is collector2


class TestSOC2Report:
    """Tests for SOC 2 report generation."""

    def test_generate_report_with_empty_evidence(self):
        """Test generating report with no evidence."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        report = generate_report([], start, end)

        assert report.period_start == start
        assert report.period_end == end
        assert len(report.controls) > 0  # Default controls defined
        assert report.summary["total_controls"] > 0

    def test_generate_report_with_evidence(self):
        """Test generating report with evidence."""
        now = datetime.now()
        start = now - timedelta(days=30)
        end = now

        # Create evidence
        evidence = [
            Evidence(
                id="test-1",
                category=EvidenceCategory.CC6_LOGICAL_ACCESS,
                evidence_type=EvidenceType.ACCESS_LOG,
                title="Access Logs",
                description="Test access logs",
                collected_at=now,
                period_start=start,
                period_end=end,
                data={},
            ),
            Evidence(
                id="test-2",
                category=EvidenceCategory.CC7_SYSTEM_OPERATIONS,
                evidence_type=EvidenceType.AUDIT_LOG,
                title="Audit Logs",
                description="Test audit logs",
                collected_at=now,
                period_start=start,
                period_end=end,
                data={},
            ),
        ]

        report = generate_report(evidence, start, end)

        assert len(report.evidence) == 2
        assert report.summary["total_evidence"] == 2

    def test_control_status_mapping(self):
        """Test control status values."""
        assert ControlStatus.IMPLEMENTED.value == "implemented"
        assert ControlStatus.PARTIAL.value == "partial"
        assert ControlStatus.NOT_IMPLEMENTED.value == "not_implemented"

    def test_get_control_status(self):
        """Test getting control status."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        report = generate_report([], start, end)

        # CC6.1 should be implemented
        status = report.get_control_status("CC6.1")
        assert status == ControlStatus.IMPLEMENTED

        # Non-existent control
        status = report.get_control_status("CC99.99")
        assert status == ControlStatus.NOT_IMPLEMENTED

    def test_report_summary_calculation(self):
        """Test report summary statistics."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        report = generate_report([], start, end)

        assert "total_controls" in report.summary
        assert "implemented" in report.summary
        assert "partial" in report.summary
        assert "coverage_percentage" in report.summary
        assert report.summary["coverage_percentage"] > 0

    def test_report_export_to_markdown(self):
        """Test exporting report to Markdown."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        report = generate_report([], start, end)
        markdown = report.export_to_markdown()

        assert "# SOC 2 Type II Compliance Report" in markdown
        assert "## Executive Summary" in markdown
        assert "## Controls Assessment" in markdown
        assert "CC6.1" in markdown

    def test_report_to_dict(self):
        """Test converting report to dictionary."""
        start = datetime.now() - timedelta(days=30)
        end = datetime.now()

        report = generate_report([], start, end)
        data = report.to_dict()

        assert "period_start" in data
        assert "period_end" in data
        assert "controls" in data
        assert "summary" in data
        assert isinstance(data["controls"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
