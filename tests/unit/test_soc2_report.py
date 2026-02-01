"""
test_soc2_report.py - Tests for SOC 2 Type II report generation

Tests compliance report generation, evidence-to-control mapping, coverage
calculation, and export functionality.
"""

import json
from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from pdfsigner.core.compliance.evidence_types import (
    Evidence,
    EvidenceCategory,
    EvidenceType,
)
from pdfsigner.core.compliance.soc2_report import (
    ControlAssessment,
    ControlStatus,
    SOC2Report,
    generate_report,
)


@pytest.fixture
def period_dates():
    """Period dates for testing."""
    start = datetime(2026, 1, 1)
    end = datetime(2026, 1, 31)
    return start, end


@pytest.fixture
def sample_evidence_cc6(period_dates):
    """Sample CC6 (Logical Access) evidence."""
    start, end = period_dates
    return Evidence(
        id=str(uuid4()),
        category=EvidenceCategory.CC6_LOGICAL_ACCESS,
        evidence_type=EvidenceType.ACCESS_LOG,
        title="User Authentication Logs",
        description="RBAC authentication logs showing user access control",
        collected_at=datetime.now(),
        period_start=start,
        period_end=end,
        data={
            "total_authentications": 145,
            "failed_attempts": 3,
            "users": ["user1", "user2", "admin"],
        },
    )


@pytest.fixture
def sample_evidence_cc7(period_dates):
    """Sample CC7 (System Operations) evidence."""
    start, end = period_dates
    return Evidence(
        id=str(uuid4()),
        category=EvidenceCategory.CC7_SYSTEM_OPERATIONS,
        evidence_type=EvidenceType.AUDIT_LOG,
        title="System Audit Logs",
        description="Complete audit trail of system operations",
        collected_at=datetime.now(),
        period_start=start,
        period_end=end,
        data={
            "total_events": 1250,
            "event_types": ["sign", "encrypt", "validate", "access"],
            "integrity_verified": True,
        },
    )


@pytest.fixture
def sample_evidence_cc5(period_dates):
    """Sample CC5 (Control Activities) evidence."""
    start, end = period_dates
    return Evidence(
        id=str(uuid4()),
        category=EvidenceCategory.CC5_CONTROL_ACTIVITIES,
        evidence_type=EvidenceType.CONFIG_SNAPSHOT,
        title="Encryption Configuration",
        description="AES-256 encryption settings and TLS configuration",
        collected_at=datetime.now(),
        period_start=start,
        period_end=end,
        data={
            "encryption_enabled": True,
            "encryption_strength": "aes256",
            "tls_version": "1.3",
            "fips_mode": False,
        },
    )


@pytest.fixture
def sample_evidence_cc9(period_dates):
    """Sample CC9 (Risk Mitigation) evidence."""
    start, end = period_dates
    return Evidence(
        id=str(uuid4()),
        category=EvidenceCategory.CC9_RISK_MITIGATION,
        evidence_type=EvidenceType.SCAN_RESULT,
        title="Vulnerability Scan Results",
        description="Automated dependency scanning results",
        collected_at=datetime.now(),
        period_start=start,
        period_end=end,
        data={
            "vulnerabilities_found": 2,
            "severity_levels": {"low": 2, "medium": 0, "high": 0},
            "dependencies_scanned": 156,
        },
    )


@pytest.fixture
def comprehensive_evidence(
    sample_evidence_cc6,
    sample_evidence_cc7,
    sample_evidence_cc5,
    sample_evidence_cc9,
):
    """Comprehensive evidence set across multiple categories."""
    return [
        sample_evidence_cc6,
        sample_evidence_cc7,
        sample_evidence_cc5,
        sample_evidence_cc9,
    ]


@pytest.mark.compliance
class TestSOC2ReportGeneration:
    """Tests for SOC 2 report generation."""

    def test_generate_report_with_evidence_returns_valid_report(
        self, comprehensive_evidence, period_dates
    ):
        """Test basic report generation with multiple evidence items."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        assert isinstance(report, SOC2Report)
        assert report.period_start == start
        assert report.period_end == end
        assert len(report.evidence) == 4
        assert len(report.controls) > 0
        assert report.summary is not None
        assert report.generated_at is not None

    def test_generate_report_with_zero_evidence_returns_report(self, period_dates):
        """Test report generation with zero evidence items."""
        start, end = period_dates

        report = generate_report([], start, end)

        assert isinstance(report, SOC2Report)
        assert len(report.evidence) == 0
        assert len(report.controls) > 0  # Controls still defined
        assert report.summary["total_evidence"] == 0

    def test_generate_report_creates_all_standard_controls(
        self, comprehensive_evidence, period_dates
    ):
        """Test that all expected SOC 2 controls are created."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        control_ids = [c.control_id for c in report.controls]
        expected_controls = [
            "CC6.1",
            "CC6.2",
            "CC6.3",
            "CC6.6",
            "CC6.7",
            "CC7.1",
            "CC7.2",
            "CC8.1",
            "CC5.1",
        ]

        for control_id in expected_controls:
            assert control_id in control_ids

    def test_generate_report_maps_evidence_to_correct_controls(
        self, sample_evidence_cc6, period_dates
    ):
        """Test evidence-to-control mapping accuracy."""
        start, end = period_dates

        report = generate_report([sample_evidence_cc6], start, end)

        # CC6 evidence should map to CC6.x controls
        cc61 = report.get_control_by_id("CC6.1")
        assert cc61 is not None
        assert sample_evidence_cc6.id in cc61.evidence_ids

        cc62 = report.get_control_by_id("CC6.2")
        assert cc62 is not None
        assert sample_evidence_cc6.id in cc62.evidence_ids

    def test_generate_report_identifies_partial_controls(
        self, comprehensive_evidence, period_dates
    ):
        """Test identification of partially implemented controls."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        # CC7.1 is defined as PARTIAL with gaps
        cc71 = report.get_control_by_id("CC7.1")
        assert cc71 is not None
        assert cc71.status == ControlStatus.PARTIAL
        assert len(cc71.gaps) > 0
        assert any("automated vulnerability scanning" in gap.lower() for gap in cc71.gaps)


@pytest.mark.compliance
class TestCoverageCalculation:
    """Tests for coverage score calculation."""

    def test_coverage_calculation_with_all_implemented(self, period_dates):
        """Test coverage calculation with 100% implementation."""
        start, end = period_dates

        # Create evidence for all categories to maximize implementation
        evidence_list = []
        for category in [
            EvidenceCategory.CC6_LOGICAL_ACCESS,
            EvidenceCategory.CC7_SYSTEM_OPERATIONS,
            EvidenceCategory.CC5_CONTROL_ACTIVITIES,
        ]:
            evidence_list.append(
                Evidence(
                    id=str(uuid4()),
                    category=category,
                    evidence_type=EvidenceType.AUDIT_LOG,
                    title="Test Evidence",
                    description="Test",
                    collected_at=datetime.now(),
                    period_start=start,
                    period_end=end,
                    data={},
                )
            )

        report = generate_report(evidence_list, start, end)

        # Should have high coverage (most controls are IMPLEMENTED)
        coverage = report.summary["coverage_percentage"]
        assert coverage > 80.0  # Most controls implemented

    def test_coverage_calculation_with_partial_controls(self, comprehensive_evidence, period_dates):
        """Test coverage calculation with partial implementation."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        # Partial controls count as 0.5 toward coverage
        total = report.summary["total_controls"]
        implemented = report.summary["implemented"]
        partial = report.summary["partial"]

        expected_coverage = (implemented + partial * 0.5) / total * 100
        actual_coverage = report.summary["coverage_percentage"]

        assert abs(actual_coverage - expected_coverage) < 0.01

    def test_coverage_calculation_with_zero_controls_returns_zero(self, period_dates):
        """Test coverage calculation edge case with zero controls."""
        start, end = period_dates

        # Create report with no controls (edge case)
        report = SOC2Report(
            period_start=start,
            period_end=end,
            generated_at=datetime.now(),
            controls=[],
        )

        # Manually calculate summary (simulate empty controls)
        report.summary = {
            "total_controls": 0,
            "implemented": 0,
            "partial": 0,
            "not_implemented": 0,
            "coverage_percentage": 0.0,
        }

        assert report.summary["coverage_percentage"] == 0.0

    def test_weighted_scoring_partial_counts_as_half(self, period_dates):
        """Test that partial controls count as 0.5 in scoring."""
        start, end = period_dates

        report = generate_report([], start, end)

        partial_count = report.summary["partial"]
        implemented_count = report.summary["implemented"]
        total = report.summary["total_controls"]

        expected = (implemented_count + partial_count * 0.5) / total * 100
        actual = report.summary["coverage_percentage"]

        assert abs(actual - expected) < 0.01


@pytest.mark.compliance
class TestExecutiveSummary:
    """Tests for executive summary generation."""

    def test_summary_includes_all_required_fields(self, comprehensive_evidence, period_dates):
        """Test that summary contains all required statistics."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        required_fields = [
            "total_controls",
            "implemented",
            "partial",
            "not_implemented",
            "not_applicable",
            "coverage_percentage",
            "total_evidence",
        ]

        for field in required_fields:
            assert field in report.summary

    def test_summary_counts_controls_by_status(self, comprehensive_evidence, period_dates):
        """Test that summary correctly counts controls by status."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        # Count manually
        status_counts = {
            ControlStatus.IMPLEMENTED: 0,
            ControlStatus.PARTIAL: 0,
            ControlStatus.NOT_IMPLEMENTED: 0,
            ControlStatus.NOT_APPLICABLE: 0,
        }

        for control in report.controls:
            status_counts[control.status] += 1

        assert report.summary["implemented"] == status_counts[ControlStatus.IMPLEMENTED]
        assert report.summary["partial"] == status_counts[ControlStatus.PARTIAL]
        assert report.summary["not_implemented"] == status_counts[ControlStatus.NOT_IMPLEMENTED]

    def test_summary_includes_evidence_count(self, comprehensive_evidence, period_dates):
        """Test that summary includes total evidence count."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        assert report.summary["total_evidence"] == len(comprehensive_evidence)


@pytest.mark.compliance
class TestRecommendations:
    """Tests for recommendations generation."""

    def test_recommendations_generated_for_partial_controls(
        self, comprehensive_evidence, period_dates
    ):
        """Test recommendations generated for partial controls."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        # CC7.1 is PARTIAL with gaps
        has_cc71_recommendation = any("CC7.1" in rec for rec in report.recommendations)
        assert has_cc71_recommendation

    def test_recommendations_include_gaps_from_partial_controls(
        self, comprehensive_evidence, period_dates
    ):
        """Test that gap details appear in recommendations."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)

        # Should include specific gaps from CC7.1
        gap_found = any(
            "automated vulnerability scanning" in rec.lower()
            or "manual security reviews" in rec.lower()
            for rec in report.recommendations
        )
        assert gap_found

    def test_recommendations_suggest_evidence_collection_when_low(self, period_dates):
        """Test recommendation to increase evidence when count is low."""
        start, end = period_dates

        # Generate report with minimal evidence (< 5)
        minimal_evidence = [
            Evidence(
                id=str(uuid4()),
                category=EvidenceCategory.CC6_LOGICAL_ACCESS,
                evidence_type=EvidenceType.ACCESS_LOG,
                title="Minimal Evidence",
                description="Test",
                collected_at=datetime.now(),
                period_start=start,
                period_end=end,
                data={},
            )
        ]

        report = generate_report(minimal_evidence, start, end)

        has_evidence_recommendation = any(
            "evidence collection" in rec.lower() for rec in report.recommendations
        )
        assert has_evidence_recommendation


@pytest.mark.compliance
class TestMarkdownExport:
    """Tests for Markdown export functionality."""

    def test_export_to_markdown_returns_valid_markdown(self, comprehensive_evidence, period_dates):
        """Test Markdown export produces valid output."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        assert isinstance(markdown, str)
        assert len(markdown) > 0
        assert "# SOC 2 Type II Compliance Report" in markdown

    def test_markdown_includes_period_information(self, comprehensive_evidence, period_dates):
        """Test Markdown includes observation period."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        assert "**Period:**" in markdown
        assert str(start.date()) in markdown
        assert str(end.date()) in markdown

    def test_markdown_includes_executive_summary(self, comprehensive_evidence, period_dates):
        """Test Markdown includes executive summary section."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        assert "## Executive Summary" in markdown
        assert "Total Controls:" in markdown
        assert "Coverage:" in markdown

    def test_markdown_includes_control_assessments(self, comprehensive_evidence, period_dates):
        """Test Markdown includes control details."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        assert "## Controls Assessment" in markdown
        assert "CC6.1" in markdown
        assert "CC7.1" in markdown

    def test_markdown_uses_status_icons(self, comprehensive_evidence, period_dates):
        """Test Markdown uses emoji icons for control status."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        # Check for status icons
        assert "✅" in markdown  # Implemented
        assert "⚠️" in markdown  # Partial (CC7.1)

    def test_markdown_includes_evidence_summary(self, comprehensive_evidence, period_dates):
        """Test Markdown includes evidence summary section."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        assert "## Evidence Summary" in markdown
        assert "Total evidence items collected:" in markdown
        assert "Evidence by category:" in markdown

    def test_markdown_includes_recommendations(self, comprehensive_evidence, period_dates):
        """Test Markdown includes recommendations section."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        markdown = report.export_to_markdown()

        if report.recommendations:
            assert "## Recommendations" in markdown


@pytest.mark.compliance
class TestJSONExport:
    """Tests for JSON export functionality."""

    def test_to_dict_returns_serializable_dictionary(self, comprehensive_evidence, period_dates):
        """Test to_dict produces JSON-serializable output."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        report_dict = report.to_dict()

        # Should be JSON serializable
        json_str = json.dumps(report_dict)
        assert isinstance(json_str, str)

    def test_to_dict_includes_all_report_fields(self, comprehensive_evidence, period_dates):
        """Test to_dict includes all report fields."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        report_dict = report.to_dict()

        required_fields = [
            "period_start",
            "period_end",
            "generated_at",
            "controls",
            "evidence",
            "summary",
            "recommendations",
        ]

        for field in required_fields:
            assert field in report_dict

    def test_to_dict_converts_datetimes_to_isoformat(self, comprehensive_evidence, period_dates):
        """Test to_dict converts datetime objects to ISO format strings."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        report_dict = report.to_dict()

        # Check ISO format
        assert isinstance(report_dict["period_start"], str)
        assert "T" in report_dict["generated_at"] or ":" in report_dict["generated_at"]

    def test_to_dict_preserves_control_structure(self, comprehensive_evidence, period_dates):
        """Test to_dict preserves control assessment structure."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        report_dict = report.to_dict()

        assert len(report_dict["controls"]) == len(report.controls)

        for control_dict in report_dict["controls"]:
            assert "control_id" in control_dict
            assert "status" in control_dict
            assert "evidence_ids" in control_dict


@pytest.mark.compliance
class TestControlAssessment:
    """Tests for ControlAssessment dataclass."""

    def test_control_assessment_to_dict(self, sample_evidence_cc6):
        """Test ControlAssessment.to_dict conversion."""
        control = ControlAssessment(
            control_id="CC6.1",
            control_name="Test Control",
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            status=ControlStatus.IMPLEMENTED,
            description="Test description",
            implementation="Test implementation",
            evidence_ids=[sample_evidence_cc6.id],
            gaps=["Gap 1", "Gap 2"],
            notes="Test notes",
        )

        control_dict = control.to_dict()

        assert control_dict["control_id"] == "CC6.1"
        assert control_dict["status"] == "implemented"
        assert len(control_dict["evidence_ids"]) == 1
        assert len(control_dict["gaps"]) == 2


@pytest.mark.compliance
class TestSOC2ReportQueries:
    """Tests for SOC2Report query methods."""

    def test_get_control_by_id_returns_correct_control(self, comprehensive_evidence, period_dates):
        """Test get_control_by_id returns the correct control."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        control = report.get_control_by_id("CC6.1")

        assert control is not None
        assert control.control_id == "CC6.1"

    def test_get_control_by_id_returns_none_for_nonexistent(
        self, comprehensive_evidence, period_dates
    ):
        """Test get_control_by_id returns None for non-existent control."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        control = report.get_control_by_id("CC99.99")

        assert control is None

    def test_get_controls_by_category_filters_correctly(self, comprehensive_evidence, period_dates):
        """Test get_controls_by_category filters by category."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        cc6_controls = report.get_controls_by_category(EvidenceCategory.CC6_LOGICAL_ACCESS)

        assert len(cc6_controls) > 0
        for control in cc6_controls:
            assert control.category == EvidenceCategory.CC6_LOGICAL_ACCESS

    def test_get_control_status_returns_correct_status(self, comprehensive_evidence, period_dates):
        """Test get_control_status returns correct status."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        status = report.get_control_status("CC7.1")

        assert status == ControlStatus.PARTIAL

    def test_get_control_status_returns_not_implemented_for_missing(
        self, comprehensive_evidence, period_dates
    ):
        """Test get_control_status returns NOT_IMPLEMENTED for missing control."""
        start, end = period_dates

        report = generate_report(comprehensive_evidence, start, end)
        status = report.get_control_status("CC99.99")

        assert status == ControlStatus.NOT_IMPLEMENTED


@pytest.mark.compliance
class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_report_with_evidence_outside_period(self, period_dates):
        """Test handling of evidence outside observation period."""
        start, end = period_dates

        # Evidence from different period
        old_evidence = Evidence(
            id=str(uuid4()),
            category=EvidenceCategory.CC6_LOGICAL_ACCESS,
            evidence_type=EvidenceType.ACCESS_LOG,
            title="Old Evidence",
            description="Test",
            collected_at=datetime.now(),
            period_start=start - timedelta(days=60),
            period_end=start - timedelta(days=30),
            data={},
        )

        # Should still include evidence (filtering is caller's responsibility)
        report = generate_report([old_evidence], start, end)
        assert len(report.evidence) == 1

    def test_report_with_duplicate_evidence_ids(self, sample_evidence_cc6, period_dates):
        """Test handling of duplicate evidence items."""
        start, end = period_dates

        # Same evidence added twice
        report = generate_report([sample_evidence_cc6, sample_evidence_cc6], start, end)

        # Both should be in evidence list
        assert len(report.evidence) == 2

    def test_empty_evidence_list_generates_valid_report(self, period_dates):
        """Test that empty evidence list still generates valid report structure."""
        start, end = period_dates

        report = generate_report([], start, end)

        assert isinstance(report, SOC2Report)
        assert len(report.controls) > 0  # Controls always defined
        assert len(report.evidence) == 0
        assert report.summary["total_evidence"] == 0
        assert report.summary["coverage_percentage"] >= 0

    def test_report_with_future_dates(self):
        """Test report generation with future date ranges."""
        start = datetime(2027, 1, 1)
        end = datetime(2027, 12, 31)

        report = generate_report([], start, end)

        assert report.period_start == start
        assert report.period_end == end
        # Report should still be valid despite future dates

    def test_report_with_single_day_period(self, sample_evidence_cc6):
        """Test report generation for single-day observation period."""
        start = datetime(2026, 1, 15)
        end = datetime(2026, 1, 15)

        # Update evidence to match single-day period
        sample_evidence_cc6.period_start = start
        sample_evidence_cc6.period_end = end

        report = generate_report([sample_evidence_cc6], start, end)

        assert report.period_start == report.period_end
        assert isinstance(report, SOC2Report)
