"""
controls_soc2.py - SOC 2 Type II Trust Services Criteria control definitions

Includes:
- CC1: Control Environment
- CC2: Communication and Information
- CC3: Risk Assessment
- CC4: Monitoring Activities
- CC6: Logical and Physical Access Controls
- CC7: System Operations
- CC8: Change Management
- CC9: Risk Mitigation
"""

from pdfsigner.core.compliance.controls import ComplianceStandard, ControlDefinition

SOC2_CONTROLS = [
    # CC1: Control Environment
    ControlDefinition(
        control_id="CC1.1",
        name="Organization Structure",
        description="Define organizational structure with security responsibilities",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=1.5,
        tags=["governance", "rbac", "roles"],
    ),
    ControlDefinition(
        control_id="CC1.2",
        name="Management Philosophy",
        description="Demonstrate commitment to integrity and ethical values",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=1.5,
        tags=["governance", "policies", "documentation"],
    ),
    ControlDefinition(
        control_id="CC1.3",
        name="Board Oversight",
        description="Establish oversight responsibilities for security and compliance",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=1.5,
        tags=["governance", "audit", "oversight"],
    ),
    ControlDefinition(
        control_id="CC1.4",
        name="Competence and Separation of Duties",
        description="Demonstrate commitment to competence and enforce separation of duties",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=2.0,
        tags=["governance", "rbac", "permissions"],
    ),
    ControlDefinition(
        control_id="CC1.5",
        name="Accountability",
        description="Hold individuals accountable for internal control responsibilities",
        standard=ComplianceStandard.SOC2,
        category="Control Environment",
        check_func="_check_soc2_governance",
        weight=2.0,
        tags=["governance", "audit", "accountability"],
    ),
    # CC2: Communication and Information
    ControlDefinition(
        control_id="CC2.1",
        name="Internal Communication",
        description="Communicate information internally to support internal control",
        standard=ComplianceStandard.SOC2,
        category="Communication",
        check_func="_check_soc2_communication",
        weight=1.0,
        tags=["communication", "policies", "documentation"],
    ),
    ControlDefinition(
        control_id="CC2.2",
        name="External Communication",
        description="Communicate with external parties regarding security matters",
        standard=ComplianceStandard.SOC2,
        category="Communication",
        check_func="_check_soc2_communication",
        weight=1.0,
        tags=["communication", "documentation", "api"],
    ),
    ControlDefinition(
        control_id="CC2.3",
        name="Communication Channels",
        description="Select and develop communication channels for security information",
        standard=ComplianceStandard.SOC2,
        category="Communication",
        check_func="_check_soc2_communication",
        weight=1.5,
        tags=["communication", "tls", "audit"],
    ),
    # CC3: Risk Assessment
    ControlDefinition(
        control_id="CC3.1",
        name="Risk Identification",
        description="Identify and assess changes that could impact the control system",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=1.5,
        tags=["risk", "threats", "documentation"],
    ),
    ControlDefinition(
        control_id="CC3.2",
        name="Risk Analysis",
        description="Analyze identified risks to determine their impact",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=1.5,
        tags=["risk", "vulnerabilities", "analysis"],
    ),
    ControlDefinition(
        control_id="CC3.3",
        name="Risk Mitigation",
        description="Manage risks through response and mitigation activities",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=2.0,
        tags=["risk", "remediation", "sla"],
    ),
    ControlDefinition(
        control_id="CC3.4",
        name="Risk Monitoring",
        description="Continuously monitor risk factors and control effectiveness",
        standard=ComplianceStandard.SOC2,
        category="Risk Assessment",
        check_func="_check_soc2_risk_assessment",
        weight=2.0,
        tags=["risk", "monitoring", "breach_detection"],
    ),
    # CC4: Monitoring Activities
    ControlDefinition(
        control_id="CC4.1",
        name="Monitoring Controls",
        description="Establish baseline comparisons and evaluate monitoring results",
        standard=ComplianceStandard.SOC2,
        category="Monitoring",
        check_func="_check_soc2_monitoring_activities",
        weight=2.0,
        tags=["monitoring", "audit", "siem"],
    ),
    ControlDefinition(
        control_id="CC4.2",
        name="Reporting Deficiencies",
        description="Report control deficiencies to appropriate personnel",
        standard=ComplianceStandard.SOC2,
        category="Monitoring",
        check_func="_check_soc2_monitoring_activities",
        weight=1.5,
        tags=["monitoring", "reporting", "compliance"],
    ),
    # CC6: Logical and Physical Access Controls
    ControlDefinition(
        control_id="CC6.1",
        name="Logical Access Controls",
        description="Restrict logical access through use of access control software",
        standard=ComplianceStandard.SOC2,
        category="Security",
        check_func="_check_soc2_access_controls",
        weight=2.0,
        tags=["access", "authentication"],
    ),
    ControlDefinition(
        control_id="CC6.6",
        name="System Operations Monitoring",
        description="Implement detective controls through use of monitoring tools",
        standard=ComplianceStandard.SOC2,
        category="Security",
        check_func="_check_soc2_monitoring",
        weight=1.5,
        tags=["audit", "monitoring"],
    ),
    ControlDefinition(
        control_id="CC6.7",
        name="Encryption of Data in Transit and at Rest",
        description="Encrypt data transmissions and data at rest",
        standard=ComplianceStandard.SOC2,
        category="Security",
        check_func="_check_soc2_encryption",
        weight=2.0,
        tags=["encryption", "confidentiality"],
    ),
    # CC7: System Operations
    ControlDefinition(
        control_id="CC7.2",
        name="System Monitoring",
        description="Monitor system components and operation of those components",
        standard=ComplianceStandard.SOC2,
        category="System Operations",
        check_func="_check_soc2_system_monitoring",
        weight=1.5,
        tags=["audit", "logging"],
    ),
    # CC8: Change Management
    ControlDefinition(
        control_id="CC8.1",
        name="Change Detection",
        description="Detect changes to system components",
        standard=ComplianceStandard.SOC2,
        category="Change Management",
        check_func="_check_soc2_change_detection",
        weight=1.0,
        required=False,
        tags=["integrity", "audit"],
    ),
    # CC9: Risk Mitigation
    ControlDefinition(
        control_id="CC9.1",
        name="Vulnerability Management",
        description="Identify, prioritize, and remediate security vulnerabilities",
        standard=ComplianceStandard.SOC2,
        category="Risk Mitigation",
        check_func="_check_soc2_risk_mitigation",
        weight=1.5,
        tags=["vulnerabilities", "remediation", "scanning"],
    ),
    ControlDefinition(
        control_id="CC9.2",
        name="Vendor Risk Management",
        description="Assess and manage third-party vendor security risks",
        standard=ComplianceStandard.SOC2,
        category="Risk Mitigation",
        check_func="_check_soc2_risk_mitigation",
        weight=1.0,
        required=False,
        tags=["vendors", "dependencies", "supply_chain"],
    ),
]
