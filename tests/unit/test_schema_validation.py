"""
Test schema validation for API schemas.

Verifies that all string fields have appropriate max_length constraints
to prevent oversized input and potential DoS attacks.
"""

import pytest
from pydantic import ValidationError

from pdfsigner.api.schemas.backup import BackupRestoreRequest
from pdfsigner.api.schemas.breach import (
    BreachIncidentCreate,
)
from pdfsigner.api.schemas.common import ErrorResponse
from pdfsigner.api.schemas.consent import ConsentRequest
from pdfsigner.api.schemas.emergency import EmergencyRequestCreate
from pdfsigner.api.schemas.evidence import EvidenceItemResponse
from pdfsigner.api.schemas.mfa import MFAVerifyRequest
from pdfsigner.api.schemas.phi import PIIMatchResponse
from pdfsigner.api.schemas.redact import RedactionRegionSchema
from pdfsigner.api.schemas.retention import RetentionPolicyCreate
from pdfsigner.api.schemas.seal import OrganizationInfoSchema
from pdfsigner.api.schemas.sign import SignRequest, SignResponse
from pdfsigner.api.schemas.users import UserResponse
from pdfsigner.api.schemas.vulnerabilities import ScanRequest, VulnerabilityCreate


def test_sign_request_max_length():
    """Test SignRequest enforces max_length on string fields."""
    # Valid request
    valid_req = SignRequest(
        reason="A" * 255,
        location="B" * 255,
        contact_info="C" * 255,
        signature_page="last",
        tsa_url="http://example.com/tsa",
    )
    assert valid_req.reason == "A" * 255

    # Exceed max_length for reason
    with pytest.raises(ValidationError) as exc_info:
        SignRequest(reason="A" * 256)
    assert "String should have at most 255 characters" in str(exc_info.value)

    # Exceed max_length for tsa_url
    with pytest.raises(ValidationError) as exc_info:
        SignRequest(tsa_url="http://" + "a" * 1020)
    assert "String should have at most 1024 characters" in str(exc_info.value)


def test_sign_response_max_length():
    """Test SignResponse enforces max_length on string fields."""
    # Valid response
    valid_resp = SignResponse(
        job_id="a" * 64,
        status="pending",
        message="A" * 4096,
        download_url="http://example.com/" + "a" * 1000,
    )
    assert valid_resp.job_id == "a" * 64

    # Exceed max_length for job_id
    with pytest.raises(ValidationError) as exc_info:
        SignResponse(job_id="a" * 65, status="pending")
    assert "String should have at most 64 characters" in str(exc_info.value)

    # Exceed max_length for message
    with pytest.raises(ValidationError) as exc_info:
        SignResponse(job_id="123", status="pending", message="A" * 4097)
    assert "String should have at most 4096 characters" in str(exc_info.value)


def test_breach_incident_create_max_length():
    """Test BreachIncidentCreate enforces max_length."""
    # Valid request
    valid_req = BreachIncidentCreate(
        breach_type="mass_data_export",
        severity="high",
        description="A" * 4096,
        source_ip="192.168.1.1",
        user_id="user123",
    )
    assert valid_req.description == "A" * 4096

    # Exceed max_length for description
    with pytest.raises(ValidationError) as exc_info:
        BreachIncidentCreate(
            breach_type="test",
            severity="high",
            description="A" * 4097,
        )
    assert "String should have at most 4096 characters" in str(exc_info.value)


def test_consent_request_max_length():
    """Test ConsentRequest enforces max_length."""
    # Valid request
    valid_req = ConsentRequest(
        consent_type="analytics",
        policy_version="1.0.0",
    )
    assert valid_req.policy_version == "1.0.0"

    # Exceed max_length for policy_version
    with pytest.raises(ValidationError) as exc_info:
        ConsentRequest(
            consent_type="analytics",
            policy_version="v" * 65,
        )
    assert "String should have at most 64 characters" in str(exc_info.value)


def test_emergency_request_max_length():
    """Test EmergencyRequestCreate enforces max_length."""
    # Valid request
    valid_req = EmergencyRequestCreate(
        reason="Patient critical care access required for immediate treatment"
    )
    assert len(valid_req.reason) < 500

    # Exceed max_length for reason
    with pytest.raises(ValidationError) as exc_info:
        EmergencyRequestCreate(reason="A" * 501)
    assert "String should have at most 500 characters" in str(exc_info.value)


def test_evidence_item_max_length():
    """Test EvidenceItemResponse enforces max_length."""
    from datetime import datetime

    # Valid response
    valid_resp = EvidenceItemResponse(
        id="123e4567-e89b-12d3-a456-426614174000",
        category="cc6",
        evidence_type="access_log",
        title="A" * 255,
        description="B" * 4096,
        collected_at=datetime.now(),
        period_start=datetime.now(),
        period_end=datetime.now(),
        file_path="/home/user/" + "a" * 1000,
        checksum="a" * 64,
    )
    assert valid_resp.title == "A" * 255

    # Exceed max_length for title
    with pytest.raises(ValidationError) as exc_info:
        EvidenceItemResponse(
            id="123",
            category="cc6",
            evidence_type="test",
            title="A" * 256,
            description="desc",
            collected_at=datetime.now(),
            period_start=datetime.now(),
            period_end=datetime.now(),
        )
    assert "String should have at most 255 characters" in str(exc_info.value)


def test_mfa_verify_max_length():
    """Test MFAVerifyRequest enforces max_length."""
    # Valid request
    valid_req = MFAVerifyRequest(code="123456")
    assert valid_req.code == "123456"

    # Exceed max_length for code
    with pytest.raises(ValidationError) as exc_info:
        MFAVerifyRequest(code="1" * 9)
    assert "String should have at most 8 characters" in str(exc_info.value)


def test_pii_match_max_length():
    """Test PIIMatchResponse enforces max_length."""
    # Valid response
    valid_resp = PIIMatchResponse(
        pii_type="ssn",
        pii_type_display="Social Security Number",
        redacted_value="***-**-1234",
        confidence=0.95,
        start_pos=0,
        end_pos=11,
        context="A" * 4096,
    )
    assert valid_resp.context == "A" * 4096

    # Exceed max_length for context
    with pytest.raises(ValidationError) as exc_info:
        PIIMatchResponse(
            pii_type="ssn",
            pii_type_display="SSN",
            redacted_value="***-**-1234",
            confidence=0.95,
            start_pos=0,
            end_pos=11,
            context="A" * 4097,
        )
    assert "String should have at most 4096 characters" in str(exc_info.value)


def test_redaction_region_max_length():
    """Test RedactionRegionSchema enforces max_length."""
    # Valid request
    valid_req = RedactionRegionSchema(
        page=0,
        x0=10.0,
        y0=10.0,
        x1=100.0,
        y1=100.0,
        replacement_text="[REDACTED]",
    )
    assert valid_req.replacement_text == "[REDACTED]"

    # Exceed max_length for replacement_text
    with pytest.raises(ValidationError) as exc_info:
        RedactionRegionSchema(
            page=0,
            x0=10.0,
            y0=10.0,
            x1=100.0,
            y1=100.0,
            replacement_text="A" * 256,
        )
    assert "String should have at most 255 characters" in str(exc_info.value)


def test_retention_policy_max_length():
    """Test RetentionPolicyCreate enforces max_length."""
    # Valid request
    valid_req = RetentionPolicyCreate(
        name="A" * 255,
        description="B" * 1000,
        target="audit_logs",
        retention_days=365,
        action="archive",
        hipaa_reference="§164.530(j)",
    )
    assert valid_req.name == "A" * 255

    # Exceed max_length for name
    with pytest.raises(ValidationError) as exc_info:
        RetentionPolicyCreate(
            name="A" * 256,
            target="audit_logs",
            retention_days=365,
            action="archive",
        )
    assert "String should have at most 255 characters" in str(exc_info.value)


def test_organization_info_max_length():
    """Test OrganizationInfoSchema enforces max_length."""
    # Valid request
    valid_req = OrganizationInfoSchema(
        name="A" * 200,
        country="DE",
        organization_id="VAT123",
        department="Sales",
        address="123 Main St",
        email="test@example.com",
        website="https://example.com",
    )
    assert valid_req.name == "A" * 200

    # Exceed max_length for name
    with pytest.raises(ValidationError) as exc_info:
        OrganizationInfoSchema(name="A" * 201, country="DE")
    assert "String should have at most 200 characters" in str(exc_info.value)


def test_user_response_max_length():
    """Test UserResponse enforces max_length."""
    from datetime import datetime

    # Valid response
    valid_resp = UserResponse(
        id="550e8400-e29b-41d4-a716-446655440000",
        username="john.doe",
        display_name="John Doe",
        email="john.doe@example.com",
        role="signer",
        status="active",
        created_at=datetime.now(),
    )
    assert valid_resp.username == "john.doe"

    # Exceed max_length for username
    with pytest.raises(ValidationError) as exc_info:
        UserResponse(
            id="123",
            username="a" * 256,
            display_name="Test",
            email="test@example.com",
            role="signer",
            status="active",
            created_at=datetime.now(),
        )
    assert "String should have at most 255 characters" in str(exc_info.value)


def test_vulnerability_create_max_length():
    """Test VulnerabilityCreate enforces max_length."""
    # Valid request
    valid_req = VulnerabilityCreate(
        title="A" * 500,
        description="B" * 4096,
        severity="high",
        file_path="/home/user/test.py",
        remediation="Fix the issue",
    )
    assert valid_req.title == "A" * 500

    # Exceed max_length for title
    with pytest.raises(ValidationError) as exc_info:
        VulnerabilityCreate(
            title="A" * 501,
            description="desc",
            severity="high",
        )
    assert "String should have at most 500 characters" in str(exc_info.value)


def test_scan_request_max_length():
    """Test ScanRequest enforces max_length."""
    # Valid request
    valid_req = ScanRequest(
        scan_type="all",
        path="/home/user/projects/test",
        semgrep_config="p/security-audit",
    )
    assert valid_req.path == "/home/user/projects/test"

    # Exceed max_length for path
    with pytest.raises(ValidationError) as exc_info:
        ScanRequest(path="/" + "a" * 1024)
    assert "String should have at most 1024 characters" in str(exc_info.value)


def test_error_response_max_length():
    """Test ErrorResponse enforces max_length."""
    # Valid response
    valid_resp = ErrorResponse(
        detail="A" * 4096,
        code="ERR_001",
    )
    assert valid_resp.detail == "A" * 4096

    # Exceed max_length for detail
    with pytest.raises(ValidationError) as exc_info:
        ErrorResponse(detail="A" * 4097)
    assert "String should have at most 4096 characters" in str(exc_info.value)


def test_backup_restore_max_length():
    """Test BackupRestoreRequest enforces max_length."""
    # Valid request
    valid_req = BackupRestoreRequest(
        backup_id="550e8400-e29b-41d4-a716-446655440000",
        password="secure_password_123",
    )
    assert valid_req.password == "secure_password_123"

    # Exceed max_length for password
    with pytest.raises(ValidationError) as exc_info:
        BackupRestoreRequest(
            backup_id="123",
            password="p" * 256,
        )
    assert "String should have at most 255 characters" in str(exc_info.value)
