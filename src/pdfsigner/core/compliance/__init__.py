"""
HIPAA Compliance Monitoring.

This module provides tools for monitoring HIPAA compliance status
across all implemented controls in PDFSigner.

Key Components:
    - ComplianceStatusChecker: Main compliance checking engine (HIPAA-specific)
    - ComplianceChecker: Multi-standard compliance checker
    - ComplianceReport: Complete compliance status report
    - ComplianceCheck: Individual check result
    - ComplianceStatus: Status enum (compliant/warning/non_compliant)
    - ComplianceCategory: Category enum (encryption/audit/access/etc.)
    - ComplianceStandard: Standard enum (hipaa/nist/fedramp/eidas/gdpr/soc2)
    - ComplianceReportGenerator: Generate reports in multiple formats
    - ReportFormat: Available report formats (PDF, JSON, CSV, CEF)
    - EvidenceCollector: SOC 2 evidence collection engine
    - SOC2Report: SOC 2 Type II compliance report generator
    - GovernanceChecker: SOC 2 CC1 (Control Environment) checks
    - CommunicationChecker: SOC 2 CC2 (Communication) checks
    - RiskAssessmentChecker: SOC 2 CC3 (Risk Assessment) checks
    - MonitoringChecker: SOC 2 CC4 (Monitoring Activities) checks

Usage:
    # HIPAA-specific checker (existing)
    >>> from pdfsigner.core.compliance import get_compliance_checker
    >>> checker = get_compliance_checker()
    >>> report = checker.check_all()
    >>> print(f"HIPAA Compliant: {report.is_hipaa_compliant}")

    # Multi-standard checker (new)
    >>> from pdfsigner.core.compliance import ComplianceChecker, ComplianceStandard
    >>> from pdfsigner.config.settings import get_settings
    >>> checker = ComplianceChecker(get_settings())
    >>> hipaa_report = checker.check_hipaa()
    >>> print(f"HIPAA Score: {hipaa_report.score:.1f}%")

    # SOC 2 evidence collection
    >>> from pdfsigner.core.compliance import get_evidence_collector
    >>> from datetime import UTC, datetime, timedelta
    >>> collector = get_evidence_collector()
    >>> end = datetime.now(UTC)
    >>> start = end - timedelta(days=90)
    >>> collection = collector.collect_all_evidence(start, end)

    # SOC 2 CC1-CC4 checks (new)
    >>> from pdfsigner.core.compliance import get_governance_checker
    >>> governance = get_governance_checker()
    >>> results = governance.run_all_checks()
"""

# Legacy HIPAA-specific compliance (existing)
# New multi-standard compliance checker
from pdfsigner.core.compliance.checker import (
    ComplianceChecker,
    ControlCheck,
)
from pdfsigner.core.compliance.checker import (
    ComplianceReport as MultiStandardReport,
)
from pdfsigner.core.compliance.checker import (
    get_compliance_checker as get_multi_standard_checker,
)
from pdfsigner.core.compliance.communication import (
    CommunicationChecker,
    get_communication_checker,
)
from pdfsigner.core.compliance.controls import (
    ComplianceStandard,
    ControlDefinition,
    ControlStatus,
    get_all_controls,
    get_controls_for_standard,
)

# Per-standard sub-checkers
from pdfsigner.core.compliance.eidas_checker import EIDASChecker
from pdfsigner.core.compliance.evidence_collector import (
    EvidenceCollector,
    get_evidence_collector,
)
from pdfsigner.core.compliance.evidence_types import (
    Evidence,
    EvidenceCategory,
    EvidenceCollection,
    EvidenceType,
)
from pdfsigner.core.compliance.fedramp_checker import FedRAMPChecker
from pdfsigner.core.compliance.gdpr_checker import GDPRChecker
from pdfsigner.core.compliance.governance import (
    GovernanceChecker,
    get_governance_checker,
)
from pdfsigner.core.compliance.hipaa_checker import HIPAAChecker
from pdfsigner.core.compliance.monitoring import (
    MonitoringChecker,
    get_monitoring_checker,
)
from pdfsigner.core.compliance.nist_audit_checker import NISTAuditChecker
from pdfsigner.core.compliance.nist_checker import NISTChecker
from pdfsigner.core.compliance.report_generator import (
    ComplianceReportGenerator,
    GeneratedReport,
    ReportConfig,
    ReportFormat,
    get_report_generator,
)
from pdfsigner.core.compliance.risk_assessment import (
    RiskAssessmentChecker,
    get_risk_assessment_checker,
)
from pdfsigner.core.compliance.soc2_checker import SOC2Checker
from pdfsigner.core.compliance.soc2_report import (
    ControlAssessment,
    SOC2Report,
    generate_report,
)
from pdfsigner.core.compliance.soc2_report import (
    ControlStatus as SOC2ControlStatus,
)
from pdfsigner.core.compliance.status_checker import (
    ComplianceCategory,
    ComplianceCheck,
    ComplianceReport,
    ComplianceStatus,
    ComplianceStatusChecker,
    get_compliance_checker,
)

__all__ = [
    # Legacy HIPAA-specific
    "ComplianceStatus",
    "ComplianceCategory",
    "ComplianceCheck",
    "ComplianceReport",
    "ComplianceStatusChecker",
    "get_compliance_checker",
    "ComplianceReportGenerator",
    "ReportFormat",
    "ReportConfig",
    "GeneratedReport",
    "get_report_generator",
    # New multi-standard
    "ComplianceChecker",
    "MultiStandardReport",
    "ControlCheck",
    "ControlDefinition",
    "ComplianceStandard",
    "ControlStatus",
    "get_multi_standard_checker",
    "get_controls_for_standard",
    "get_all_controls",
    # SOC 2 evidence collection
    "EvidenceCollector",
    "get_evidence_collector",
    "Evidence",
    "EvidenceCategory",
    "EvidenceCollection",
    "EvidenceType",
    "SOC2Report",
    "ControlAssessment",
    "SOC2ControlStatus",
    "generate_report",
    # SOC 2 CC1-CC4 checkers
    "GovernanceChecker",
    "get_governance_checker",
    "CommunicationChecker",
    "get_communication_checker",
    "RiskAssessmentChecker",
    "get_risk_assessment_checker",
    "MonitoringChecker",
    "get_monitoring_checker",
    # Per-standard sub-checkers
    "HIPAAChecker",
    "NISTChecker",
    "NISTAuditChecker",
    "FedRAMPChecker",
    "EIDASChecker",
    "GDPRChecker",
    "SOC2Checker",
]
