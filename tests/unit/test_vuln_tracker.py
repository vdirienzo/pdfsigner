"""
test_vuln_tracker.py - Tests for vulnerability tracker

Tests vulnerability tracking, deduplication, and workflow for NIST RA-5 compliance.
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from pdfsigner.core.security import (
    Vulnerability,
    VulnRepository,
    VulnSeverity,
    VulnSource,
    VulnStatus,
    VulnTracker,
)


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def repository(temp_db):
    """Create repository with temporary database."""
    return VulnRepository(db_path=temp_db)


@pytest.fixture
def tracker(repository):
    """Create tracker with test repository."""
    return VulnTracker(repository=repository)


@pytest.fixture
def sample_vulnerability():
    """Create sample vulnerability for testing."""
    return Vulnerability(
        title="SQL Injection in user query",
        description="User input is directly concatenated into SQL query",
        severity=VulnSeverity.HIGH,
        source=VulnSource.SEMGREP,
        file_path="src/api/routes.py",
        line_number=142,
        cwe_id="CWE-89",
    )


class TestVulnRepository:
    """Test VulnRepository CRUD operations."""

    def test_save_and_get_vulnerability(self, repository, sample_vulnerability):
        """Test saving and retrieving vulnerability."""
        saved = repository.save_vulnerability(sample_vulnerability)
        retrieved = repository.get_vulnerability(saved.id)

        assert retrieved is not None
        assert retrieved.id == saved.id
        assert retrieved.title == sample_vulnerability.title
        assert retrieved.severity == VulnSeverity.HIGH
        assert retrieved.status == VulnStatus.OPEN

    def test_get_nonexistent_vulnerability_returns_none(self, repository):
        """Test get_vulnerability returns None for nonexistent ID."""
        result = repository.get_vulnerability("nonexistent-id")
        assert result is None

    def test_list_vulnerabilities_empty(self, repository):
        """Test listing vulnerabilities when database is empty."""
        vulns = repository.list_vulnerabilities()
        assert len(vulns) == 0

    def test_list_vulnerabilities_with_filters(self, repository, sample_vulnerability):
        """Test listing vulnerabilities with filters."""
        # Add multiple vulnerabilities
        vuln1 = sample_vulnerability
        vuln2 = Vulnerability(
            title="XSS vulnerability",
            description="Reflected XSS",
            severity=VulnSeverity.MEDIUM,
            source=VulnSource.SEMGREP,
        )
        vuln3 = Vulnerability(
            title="Outdated dependency",
            description="Old package version",
            severity=VulnSeverity.LOW,
            source=VulnSource.PIP_AUDIT,
            status=VulnStatus.RESOLVED,
        )

        repository.save_vulnerability(vuln1)
        repository.save_vulnerability(vuln2)
        repository.save_vulnerability(vuln3)

        # Filter by severity
        high_vulns = repository.list_vulnerabilities(severity=VulnSeverity.HIGH)
        assert len(high_vulns) == 1
        assert high_vulns[0].title == "SQL Injection in user query"

        # Filter by status
        open_vulns = repository.list_vulnerabilities(status=VulnStatus.OPEN)
        assert len(open_vulns) == 2

        # Filter by source
        semgrep_vulns = repository.list_vulnerabilities(source=VulnSource.SEMGREP)
        assert len(semgrep_vulns) == 2

    def test_update_status(self, repository, sample_vulnerability):
        """Test updating vulnerability status."""
        saved = repository.save_vulnerability(sample_vulnerability)

        # Update status
        success = repository.update_status(saved.id, VulnStatus.RESOLVED)
        assert success is True

        # Verify update
        updated = repository.get_vulnerability(saved.id)
        assert updated.status == VulnStatus.RESOLVED
        assert updated.resolved_at is not None

    def test_get_statistics(self, repository):
        """Test getting vulnerability statistics."""
        # Add vulnerabilities
        repository.save_vulnerability(
            Vulnerability(
                title="Vuln 1",
                description="Test",
                severity=VulnSeverity.CRITICAL,
                source=VulnSource.SEMGREP,
            )
        )
        repository.save_vulnerability(
            Vulnerability(
                title="Vuln 2",
                description="Test",
                severity=VulnSeverity.HIGH,
                source=VulnSource.SEMGREP,
                status=VulnStatus.IN_PROGRESS,
            )
        )
        repository.save_vulnerability(
            Vulnerability(
                title="Vuln 3",
                description="Test",
                severity=VulnSeverity.MEDIUM,
                source=VulnSource.PIP_AUDIT,
                status=VulnStatus.RESOLVED,
            )
        )

        stats = repository.get_statistics()

        assert stats["total"] == 3
        assert stats["open"] == 2  # OPEN + IN_PROGRESS
        assert stats["high_critical_open"] == 2
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1
        assert stats["by_status"]["open"] == 1
        assert stats["by_status"]["in_progress"] == 1
        assert stats["by_status"]["resolved"] == 1

    def test_delete_vulnerability(self, repository, sample_vulnerability):
        """Test deleting vulnerability."""
        saved = repository.save_vulnerability(sample_vulnerability)

        # Delete
        success = repository.delete_vulnerability(saved.id)
        assert success is True

        # Verify deletion
        deleted = repository.get_vulnerability(saved.id)
        assert deleted is None


class TestVulnTracker:
    """Test VulnTracker workflow operations."""

    def test_add_new_vulnerability(self, tracker, sample_vulnerability):
        """Test adding new vulnerability."""
        added = tracker.add_vulnerability(sample_vulnerability)

        assert added.id is not None
        assert added.status == VulnStatus.OPEN
        assert "first_seen" in added.metadata

    def test_add_duplicate_vulnerability_updates_existing(self, tracker, sample_vulnerability):
        """Test adding duplicate vulnerability updates existing instead of creating new."""
        # Add first time
        first = tracker.add_vulnerability(sample_vulnerability)
        first_id = first.id

        # Add again (duplicate)
        second = tracker.add_vulnerability(sample_vulnerability)

        # Should return same ID
        assert second.id == first_id
        assert "last_seen" in second.metadata

    def test_add_duplicate_with_higher_severity_updates(self, tracker, sample_vulnerability):
        """Test duplicate with higher severity updates existing."""
        # Add with HIGH severity
        first = tracker.add_vulnerability(sample_vulnerability)
        assert first.severity == VulnSeverity.HIGH

        # Create new vulnerability with same details but CRITICAL severity
        duplicate_vuln = Vulnerability(
            title=sample_vulnerability.title,
            description=sample_vulnerability.description,
            severity=VulnSeverity.CRITICAL,
            source=sample_vulnerability.source,
            file_path=sample_vulnerability.file_path,
            line_number=sample_vulnerability.line_number,
            cwe_id=sample_vulnerability.cwe_id,
        )

        second = tracker.add_vulnerability(duplicate_vuln)

        # Should update to CRITICAL
        assert second.id == first.id
        assert second.severity == VulnSeverity.CRITICAL

    def test_add_reopens_resolved_vulnerability(self, tracker, sample_vulnerability):
        """Test adding vulnerability reopens if previously resolved."""
        # Add and resolve
        vuln = tracker.add_vulnerability(sample_vulnerability)
        tracker.update_status(vuln.id, VulnStatus.RESOLVED)

        # Add again (rediscovered)
        reopened = tracker.add_vulnerability(sample_vulnerability)

        # Should reopen
        assert reopened.id == vuln.id
        assert reopened.status == VulnStatus.OPEN
        assert reopened.resolved_at is None

    def test_update_status_with_notes(self, tracker, sample_vulnerability):
        """Test updating status with notes."""
        vuln = tracker.add_vulnerability(sample_vulnerability)

        # Update status
        success = tracker.update_status(
            vuln.id,
            VulnStatus.IN_PROGRESS,
            notes="Working on fix",
            assignee="john.doe",
        )

        assert success is True

        # Verify update
        updated = tracker.repository.get_vulnerability(vuln.id)
        assert updated.status == VulnStatus.IN_PROGRESS
        assert updated.assignee == "john.doe"
        assert "status_history" in updated.metadata
        assert len(updated.metadata["status_history"]) == 1
        assert updated.metadata["status_history"][0]["notes"] == "Working on fix"

    def test_update_nonexistent_vulnerability_returns_false(self, tracker):
        """Test updating nonexistent vulnerability returns False."""
        success = tracker.update_status("nonexistent-id", VulnStatus.RESOLVED)
        assert success is False

    def test_assign_vulnerability(self, tracker, sample_vulnerability):
        """Test assigning vulnerability to user."""
        vuln = tracker.add_vulnerability(sample_vulnerability)

        # Assign
        success = tracker.assign_vulnerability(vuln.id, "jane.doe")
        assert success is True

        # Verify assignment
        assigned = tracker.repository.get_vulnerability(vuln.id)
        assert assigned.assignee == "jane.doe"
        assert "assigned_at" in assigned.metadata

    def test_get_overdue_vulnerabilities(self, tracker):
        """Test getting overdue vulnerabilities."""
        # Add old vulnerability (40 days ago)
        old_vuln = Vulnerability(
            title="Old vulnerability",
            description="Test",
            severity=VulnSeverity.HIGH,
            source=VulnSource.SEMGREP,
        )
        old_vuln.discovered_at = datetime.utcnow() - timedelta(days=40)
        tracker.repository.save_vulnerability(old_vuln)

        # Add recent vulnerability (10 days ago)
        recent_vuln = Vulnerability(
            title="Recent vulnerability",
            description="Test",
            severity=VulnSeverity.MEDIUM,
            source=VulnSource.SEMGREP,
        )
        recent_vuln.discovered_at = datetime.utcnow() - timedelta(days=10)
        tracker.repository.save_vulnerability(recent_vuln)

        # Get overdue (30+ days)
        overdue = tracker.get_overdue_vulnerabilities(sla_days=30)

        assert len(overdue) == 1
        assert overdue[0].title == "Old vulnerability"

    def test_import_scan_results(self, tracker):
        """Test importing scan results with deduplication."""
        # First scan
        scan1 = [
            Vulnerability(
                title="Vuln A",
                description="Test",
                severity=VulnSeverity.HIGH,
                source=VulnSource.SEMGREP,
            ),
            Vulnerability(
                title="Vuln B",
                description="Test",
                severity=VulnSeverity.MEDIUM,
                source=VulnSource.SEMGREP,
            ),
        ]

        stats1 = tracker.import_scan_results(scan1)
        assert stats1["new"] == 2
        assert stats1["updated"] == 0

        # Second scan (Vuln A still exists, Vuln B resolved, Vuln C is new)
        scan2 = [
            Vulnerability(
                title="Vuln A",
                description="Test",
                severity=VulnSeverity.CRITICAL,  # Severity increased
                source=VulnSource.SEMGREP,
            ),
            Vulnerability(
                title="Vuln C",
                description="Test",
                severity=VulnSeverity.LOW,
                source=VulnSource.SEMGREP,
            ),
        ]

        stats2 = tracker.import_scan_results(scan2)
        assert stats2["new"] == 1  # Vuln C
        assert stats2["updated"] == 1  # Vuln A (severity changed)

    def test_import_scan_results_marks_missing_as_resolved(self, tracker):
        """Test import marks missing vulnerabilities as resolved."""
        # First scan
        scan1 = [
            Vulnerability(
                title="Vuln A",
                description="Test",
                severity=VulnSeverity.HIGH,
                source=VulnSource.SEMGREP,
            ),
            Vulnerability(
                title="Vuln B",
                description="Test",
                severity=VulnSeverity.MEDIUM,
                source=VulnSource.SEMGREP,
            ),
        ]

        tracker.import_scan_results(scan1)

        # Second scan (only Vuln A)
        scan2 = [
            Vulnerability(
                title="Vuln A",
                description="Test",
                severity=VulnSeverity.HIGH,
                source=VulnSource.SEMGREP,
            ),
        ]

        stats = tracker.import_scan_results(scan2, mark_missing_as_resolved=True)
        assert stats["resolved"] == 1  # Vuln B marked as resolved

        # Verify Vuln B is resolved
        all_vulns = tracker.repository.list_vulnerabilities(limit=100)
        vuln_b = next(v for v in all_vulns if v.title == "Vuln B")
        assert vuln_b.status == VulnStatus.RESOLVED


class TestVulnerabilityMethods:
    """Test Vulnerability model methods."""

    def test_is_open(self):
        """Test is_open method."""
        vuln = Vulnerability(
            title="Test",
            description="Test",
            severity=VulnSeverity.HIGH,
            source=VulnSource.SEMGREP,
        )

        assert vuln.is_open() is True

        vuln.status = VulnStatus.IN_PROGRESS
        assert vuln.is_open() is True

        vuln.status = VulnStatus.RESOLVED
        assert vuln.is_open() is False

    def test_is_high_severity(self):
        """Test is_high_severity method."""
        vuln = Vulnerability(
            title="Test",
            description="Test",
            severity=VulnSeverity.HIGH,
            source=VulnSource.SEMGREP,
        )

        assert vuln.is_high_severity() is True

        vuln.severity = VulnSeverity.CRITICAL
        assert vuln.is_high_severity() is True

        vuln.severity = VulnSeverity.MEDIUM
        assert vuln.is_high_severity() is False

    def test_days_open(self):
        """Test days_open calculation."""
        vuln = Vulnerability(
            title="Test",
            description="Test",
            severity=VulnSeverity.HIGH,
            source=VulnSource.SEMGREP,
        )

        # Set discovery to 10 days ago
        vuln.discovered_at = datetime.utcnow() - timedelta(days=10)

        days = vuln.days_open()
        assert days >= 9 and days <= 11  # Allow some variance

        # Test with resolved_at
        vuln.resolved_at = vuln.discovered_at + timedelta(days=5)
        assert vuln.days_open() == 5

    def test_to_dict_and_from_dict(self):
        """Test serialization to/from dict."""
        vuln = Vulnerability(
            title="Test Vulnerability",
            description="Test description",
            severity=VulnSeverity.HIGH,
            source=VulnSource.SEMGREP,
            file_path="src/test.py",
            line_number=42,
        )

        # Convert to dict
        vuln_dict = vuln.to_dict()

        # Convert back
        restored = Vulnerability.from_dict(vuln_dict)

        assert restored.title == vuln.title
        assert restored.severity == vuln.severity
        assert restored.source == vuln.source
        assert restored.file_path == vuln.file_path
        assert restored.line_number == vuln.line_number
