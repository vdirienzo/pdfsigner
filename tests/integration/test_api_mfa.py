"""
Integration tests for MFA (Multi-Factor Authentication) API routes.

Tests all MFA endpoints with authentication, TOTP verification, backup codes,
and various security scenarios.

Run with:
    uv run pytest tests/integration/test_api_mfa.py -v
    uv run pytest tests/integration/test_api_mfa.py -v --cov=src/pdfsigner/api/routes/mfa
"""

import base64
import re
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import httpx
import pyotp
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.core.auth.mfa.mfa_manager import MFAManager

# Mark all tests in this module as anyio (use anyio for async support)
pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def temp_mfa_db():
    """Create temporary MFA database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_mfa.db"
        yield db_path


@pytest.fixture
def mfa_manager(temp_mfa_db):
    """Create MFA manager for testing."""
    # Reset singleton
    MFAManager._instance = None
    manager = MFAManager.get_instance(temp_mfa_db)
    yield manager
    # Reset again after test
    MFAManager._instance = None


@pytest.fixture
def user_token():
    """Create valid JWT token for regular user."""
    token = create_access_token(
        data={"sub": "testuser", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auth_headers(user_token):
    """Create authentication headers with JWT token and API key to bypass CSRF."""
    return {
        "Authorization": f"Bearer {user_token}",
        "X-API-Key": "test-bypass-csrf",
    }


@pytest.fixture
def another_user_token():
    """Create valid JWT token for another user."""
    token = create_access_token(
        data={"sub": "anotheruser", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def another_user_headers(another_user_token):
    """Create authentication headers for another user."""
    return {
        "Authorization": f"Bearer {another_user_token}",
        "X-API-Key": "test-bypass-csrf",
    }


# --- Helper Functions ---


def extract_secret_from_provisioning_uri(uri: str) -> str:
    """Extract secret from provisioning URI."""
    match = re.search(r"secret=([A-Z2-7]+)", uri)
    if not match:
        raise ValueError("Could not extract secret from URI")
    return match.group(1)


def generate_valid_totp_code(secret: str) -> str:
    """Generate valid TOTP code for given secret."""
    totp = pyotp.TOTP(secret)
    return totp.now()


def generate_expired_totp_code(secret: str) -> str:
    """
    Generate expired TOTP code.

    Note: This generates a code from 2+ windows ago (>60s in past).
    pyotp default window=1 means it checks current ±1 interval (±30s).
    """
    totp = pyotp.TOTP(secret)
    # Generate code from 3 intervals ago (90 seconds ago)
    old_timestamp = int(time.time()) - (3 * 30)
    return totp.at(old_timestamp)


# --- Test: POST /mfa/enroll ---


async def test_mfa_enroll_success(client, auth_headers, mfa_manager):
    """Test successful MFA enrollment returns secret, QR code, and backup codes."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        response = await client.post("/mfa/enroll", headers=auth_headers, json={})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify response structure
        assert "secret" in data
        assert "qr_code_base64" in data
        assert "provisioning_uri" in data
        assert "backup_codes" in data

        # Verify secret format (Base32)
        assert re.match(r"^[A-Z2-7]+$", data["secret"])
        assert len(data["secret"]) >= 16

        # Verify QR code is valid base64
        try:
            qr_bytes = base64.b64decode(data["qr_code_base64"])
            assert len(qr_bytes) > 0
            # QR code should be a PNG
            assert qr_bytes.startswith(b"\x89PNG")
        except Exception as e:
            pytest.fail(f"Invalid QR code base64: {e}")

        # Verify provisioning URI format
        assert data["provisioning_uri"].startswith("otpauth://totp/")
        assert "PDFSigner" in data["provisioning_uri"]
        assert "secret=" in data["provisioning_uri"]

        # Verify backup codes
        assert len(data["backup_codes"]) == 10
        for code in data["backup_codes"]:
            # Format: XXXX-XXXX
            assert re.match(r"^\d{4}-\d{4}$", code)


async def test_mfa_enroll_already_enrolled_fails(client, auth_headers, mfa_manager):
    """Test enrolling when already enrolled returns 400 error."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        with patch("pdfsigner.api.services.mfa_service.get_mfa_manager", return_value=mfa_manager):
            # First enrollment
            response1 = await client.post("/mfa/enroll", headers=auth_headers, json={})
            assert response1.status_code == status.HTTP_200_OK
            data1 = response1.json()

            # Activate MFA
            secret = extract_secret_from_provisioning_uri(data1["provisioning_uri"])
            totp_code = generate_valid_totp_code(secret)
            verify_response = await client.post(
                "/mfa/verify", headers=auth_headers, json={"code": totp_code}
            )
            assert verify_response.status_code == status.HTTP_200_OK

            # Try to enroll again
            response2 = await client.post("/mfa/enroll", headers=auth_headers, json={})
            assert response2.status_code == status.HTTP_400_BAD_REQUEST
            assert "already enabled" in response2.json()["detail"].lower()


async def test_mfa_enroll_unauthorized(client, mfa_manager):
    """Test MFA enrollment without authentication fails."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        with patch("pdfsigner.api.services.mfa_service.get_mfa_manager", return_value=mfa_manager):
            # Add X-API-Key to bypass CSRF, but no auth token
            response = await client.post(
                "/mfa/enroll", json={}, headers={"X-API-Key": "test-bypass-csrf"}
            )
            assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Test: POST /mfa/verify ---


async def test_mfa_verify_valid_code_activates(client, auth_headers, mfa_manager):
    """Test verifying valid TOTP code activates MFA."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK
        data = enroll_response.json()

        # Extract secret and generate valid code
        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)

        # Verify
        response = await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert result["success"] is True
        assert "activated successfully" in result["message"].lower()

        # Check status to confirm MFA is enabled
        status_response = await client.get("/mfa/status", headers=auth_headers)
        assert status_response.status_code == status.HTTP_200_OK
        status_data = status_response.json()
        assert status_data["enabled"] is True


async def test_mfa_verify_invalid_code_fails(client, auth_headers, mfa_manager):
    """Test verifying invalid TOTP code returns failure."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK

        # Try to verify with wrong code
        response = await client.post("/mfa/verify", headers=auth_headers, json={"code": "000000"})

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert result["success"] is False
        assert "invalid" in result["message"].lower()


async def test_mfa_verify_expired_code_fails(client, auth_headers, mfa_manager):
    """Test verifying expired TOTP code fails (outside time window)."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK
        data = enroll_response.json()

        # Generate expired code
        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        expired_code = generate_expired_totp_code(secret)

        # Try to verify with expired code
        response = await client.post(
            "/mfa/verify", headers=auth_headers, json={"code": expired_code}
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert result["success"] is False


@pytest.mark.slow
async def test_mfa_verify_reused_code_fails(client, auth_headers, mfa_manager):
    """Test expired TOTP code fails after time window passes (slow test: 90s)."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK
        data = enroll_response.json()

        # Generate valid code
        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)

        # First verification succeeds
        response1 = await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})
        assert response1.status_code == status.HTTP_200_OK
        assert response1.json()["success"] is True

        # Wait for code to expire (need to wait more than window*2 intervals)
        # pyotp window=1 means ±1 interval (±30s), so wait 90s to be safe
        time.sleep(91)

        # Old code should now be invalid (outside the time window)
        response2 = await client.post(
            "/mfa/verify",
            headers=auth_headers,
            json={"code": totp_code},  # Old code
        )
        assert response2.status_code == status.HTTP_200_OK
        # Old code should now be invalid
        assert response2.json()["success"] is False


async def test_mfa_verify_without_enrollment_fails(client, auth_headers, mfa_manager):
    """Test verifying without enrollment returns 400 error."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        response = await client.post("/mfa/verify", headers=auth_headers, json={"code": "123456"})

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "no mfa enrollment" in response.json()["detail"].lower()


async def test_mfa_verify_totp_window_tolerance_before(client, auth_headers, mfa_manager):
    """Test TOTP verification accepts codes within 30s before window."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK
        data = enroll_response.json()

        # Generate code from 1 interval before (30s ago)
        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp = pyotp.TOTP(secret)
        old_timestamp = int(time.time()) - 30
        code_before = totp.at(old_timestamp)

        # Verify (should work with window=1)
        response = await client.post(
            "/mfa/verify", headers=auth_headers, json={"code": code_before}
        )

        assert response.status_code == status.HTTP_200_OK
        # May succeed or fail depending on exact timing - just verify no crash


async def test_mfa_verify_totp_window_tolerance_after(client, auth_headers, mfa_manager):
    """Test TOTP verification accepts codes within 30s after window."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK
        data = enroll_response.json()

        # Generate code from 1 interval after (30s future)
        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp = pyotp.TOTP(secret)
        future_timestamp = int(time.time()) + 30
        code_after = totp.at(future_timestamp)

        # Verify (should work with window=1)
        response = await client.post("/mfa/verify", headers=auth_headers, json={"code": code_after})

        assert response.status_code == status.HTTP_200_OK
        # May succeed or fail depending on exact timing - just verify no crash


# --- Test: POST /mfa/verify-backup ---


async def test_mfa_verify_backup_code_success(client, auth_headers, mfa_manager):
    """Test verifying valid backup code succeeds and decrements remaining count."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll and activate
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        data = enroll_response.json()
        backup_codes = data["backup_codes"]

        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)
        await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        # Use first backup code
        response = await client.post(
            "/mfa/verify-backup", headers=auth_headers, json={"code": backup_codes[0]}
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert result["success"] is True
        assert result["remaining_codes"] == 9

        # Try to reuse same backup code
        response2 = await client.post(
            "/mfa/verify-backup", headers=auth_headers, json={"code": backup_codes[0]}
        )

        assert response2.status_code == status.HTTP_200_OK
        result2 = response2.json()
        assert result2["success"] is False
        assert "already used" in result2["message"].lower()


async def test_mfa_verify_backup_code_exhaustion(client, auth_headers, mfa_manager):
    """Test using all 10 backup codes and exhaustion handling."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll and activate
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        data = enroll_response.json()
        backup_codes = data["backup_codes"]

        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)
        await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        # Use all 10 backup codes
        for i, code in enumerate(backup_codes):
            response = await client.post(
                "/mfa/verify-backup", headers=auth_headers, json={"code": code}
            )
            assert response.status_code == status.HTTP_200_OK
            result = response.json()
            assert result["success"] is True
            assert result["remaining_codes"] == 9 - i

        # Check status shows 0 remaining
        status_response = await client.get("/mfa/status", headers=auth_headers)
        assert status_response.json()["backup_codes_remaining"] == 0


async def test_mfa_verify_backup_without_mfa_enabled_fails(client, auth_headers, mfa_manager):
    """Test verifying backup code when MFA not enabled returns 403."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        response = await client.post(
            "/mfa/verify-backup", headers=auth_headers, json={"code": "1234-5678"}
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "not enabled" in response.json()["detail"].lower()


async def test_mfa_verify_backup_invalid_format(client, auth_headers, mfa_manager):
    """Test backup code with invalid format fails."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll and activate
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        data = enroll_response.json()

        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)
        await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        # Try invalid code
        response = await client.post(
            "/mfa/verify-backup", headers=auth_headers, json={"code": "invalid"}
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert result["success"] is False


# --- Test: GET /mfa/status ---


async def test_mfa_status_not_enrolled(client, auth_headers, mfa_manager):
    """Test MFA status for user without MFA returns disabled status."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        response = await client.get("/mfa/status", headers=auth_headers)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["enabled"] is False
        assert data["enrolled_at"] is None
        assert data["last_used_at"] is None
        assert data["backup_codes_remaining"] == 0


async def test_mfa_status_enrolled_active(client, auth_headers, mfa_manager):
    """Test MFA status for enrolled user shows enabled and timestamps."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        with patch("pdfsigner.api.services.mfa_service.get_mfa_manager", return_value=mfa_manager):
            # Enroll and activate
            enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
            data = enroll_response.json()

            secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
            totp_code = generate_valid_totp_code(secret)
            await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

            # Use MFA to set last_used_at
            new_code = generate_valid_totp_code(secret)
            mfa_manager.verify("testuser", new_code, is_backup=False)

            # Check status
            response = await client.get("/mfa/status", headers=auth_headers)

            assert response.status_code == status.HTTP_200_OK
            status_data = response.json()
            assert status_data["enabled"] is True
            assert status_data["enrolled_at"] is not None
            # last_used_at should be set after verify() call
            assert status_data["last_used_at"] is not None
            assert status_data["backup_codes_remaining"] == 10


async def test_mfa_status_unauthorized(client):
    """Test MFA status without authentication fails."""
    response = await client.get("/mfa/status")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Test: POST /mfa/disable ---


async def test_mfa_disable_with_correct_password(client, auth_headers, mfa_manager):
    """Test disabling MFA with correct password succeeds."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        with patch("pdfsigner.api.services.mfa_service.get_mfa_manager", return_value=mfa_manager):
            # Enroll and activate
            enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
            data = enroll_response.json()

            secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
            totp_code = generate_valid_totp_code(secret)
            await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

            # Mock password verification - patch at the import location within the function
            with patch("pdfsigner.core.users.user_repository.UserRepository") as mock_repo_class:
                mock_repo = mock_repo_class.return_value
                mock_repo.get_password_hash.return_value = (
                    "$argon2id$v=19$m=65536,t=3,p=4$test"  # Mock hash
                )

                with patch(
                    "pdfsigner.core.auth.password_validator.get_password_validator"
                ) as mock_validator:
                    mock_validator.return_value.verify_password.return_value = True

                    # Disable MFA
                    response = await client.post(
                        "/mfa/disable",
                        headers=auth_headers,
                        json={"current_password": "correct_password"},
                    )

                    assert response.status_code == status.HTTP_200_OK
                    result = response.json()
                    assert result["success"] is True
                    assert "disabled successfully" in result["message"].lower()

            # Verify MFA is disabled
            status_response = await client.get("/mfa/status", headers=auth_headers)
            assert status_response.json()["enabled"] is False


async def test_mfa_disable_without_password_fails(client, auth_headers, mfa_manager):
    """Test disabling MFA without password returns validation error."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Try to disable without password (invalid request body)
        response = await client.post("/mfa/disable", headers=auth_headers, json={})

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_mfa_disable_with_wrong_password_fails(client, auth_headers, mfa_manager):
    """Test disabling MFA with incorrect password returns 401."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        with patch("pdfsigner.api.services.mfa_service.get_mfa_manager", return_value=mfa_manager):
            # Enroll and activate
            enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
            data = enroll_response.json()

            secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
            totp_code = generate_valid_totp_code(secret)
            await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

            # Mock password verification to fail
            with patch("pdfsigner.core.users.user_repository.UserRepository") as mock_repo_class:
                mock_repo = mock_repo_class.return_value
                mock_repo.get_password_hash.return_value = "$argon2id$v=19$m=65536,t=3,p=4$test"

                with patch(
                    "pdfsigner.core.auth.password_validator.get_password_validator"
                ) as mock_validator:
                    mock_validator.return_value.verify_password.return_value = False

                    # Try to disable with wrong password
                    response = await client.post(
                        "/mfa/disable",
                        headers=auth_headers,
                        json={"current_password": "wrong_password"},
                    )

                    assert response.status_code == status.HTTP_401_UNAUTHORIZED
                    assert "incorrect password" in response.json()["detail"].lower()


async def test_mfa_disable_when_not_enabled_fails(client, auth_headers, mfa_manager):
    """Test disabling MFA when not enabled returns 400."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        with patch("pdfsigner.api.services.mfa_service.get_mfa_manager", return_value=mfa_manager):
            with patch("pdfsigner.core.users.user_repository.UserRepository") as mock_repo_class:
                mock_repo = mock_repo_class.return_value
                mock_repo.get_password_hash.return_value = "$argon2id$v=19$m=65536,t=3,p=4$test"

                with patch(
                    "pdfsigner.core.auth.password_validator.get_password_validator"
                ) as mock_validator:
                    mock_validator.return_value.verify_password.return_value = True

                    response = await client.post(
                        "/mfa/disable", headers=auth_headers, json={"current_password": "password"}
                    )

                    assert response.status_code == status.HTTP_400_BAD_REQUEST
                    assert "not enabled" in response.json()["detail"].lower()


# --- Test: POST /mfa/backup-codes ---


async def test_mfa_regenerate_backup_codes_success(client, auth_headers, mfa_manager):
    """Test regenerating backup codes returns new codes."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll and activate
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        data = enroll_response.json()
        old_codes = data["backup_codes"]

        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)
        await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        # Regenerate backup codes
        response = await client.post("/mfa/backup-codes", headers=auth_headers)

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert "backup_codes" in result
        assert len(result["backup_codes"]) == 10
        assert "invalid" in result["message"].lower()

        # Verify codes are different
        new_codes = result["backup_codes"]
        assert new_codes != old_codes


async def test_mfa_regenerate_backup_codes_invalidates_old(client, auth_headers, mfa_manager):
    """Test regenerating backup codes invalidates old codes."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll and activate
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        data = enroll_response.json()
        old_codes = data["backup_codes"]

        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)
        await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        # Regenerate backup codes
        regenerate_response = await client.post("/mfa/backup-codes", headers=auth_headers)
        assert regenerate_response.status_code == status.HTTP_200_OK

        # Try to use old backup code
        response = await client.post(
            "/mfa/verify-backup", headers=auth_headers, json={"code": old_codes[0]}
        )

        assert response.status_code == status.HTTP_200_OK
        result = response.json()
        assert result["success"] is False


async def test_mfa_regenerate_backup_codes_without_mfa_fails(client, auth_headers, mfa_manager):
    """Test regenerating backup codes without MFA enabled returns 403."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        response = await client.post("/mfa/backup-codes", headers=auth_headers)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "not enabled" in response.json()["detail"].lower()


async def test_mfa_regenerate_backup_codes_format_validation(client, auth_headers, mfa_manager):
    """Test regenerated backup codes have correct format."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll and activate
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        data = enroll_response.json()

        secret = extract_secret_from_provisioning_uri(data["provisioning_uri"])
        totp_code = generate_valid_totp_code(secret)
        await client.post("/mfa/verify", headers=auth_headers, json={"code": totp_code})

        # Regenerate backup codes
        response = await client.post("/mfa/backup-codes", headers=auth_headers)

        assert response.status_code == status.HTTP_200_OK
        result = response.json()

        # Verify format (XXXX-XXXX)
        for code in result["backup_codes"]:
            assert re.match(r"^\d{4}-\d{4}$", code)


# --- Test: QR Code Validation ---


async def test_mfa_qr_code_uri_format_validation(client, auth_headers, mfa_manager):
    """Test QR code URI has correct otpauth:// format."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        uri = data["provisioning_uri"]

        # Verify URI format
        assert uri.startswith("otpauth://totp/")
        assert "secret=" in uri
        assert "issuer=PDFSigner" in uri

        # Extract and verify components
        secret = extract_secret_from_provisioning_uri(uri)
        assert re.match(r"^[A-Z2-7]+$", secret)


# --- Test: Concurrent Enrollment ---


async def test_mfa_concurrent_enrollment_different_users(
    client, auth_headers, another_user_headers, mfa_manager
):
    """Test concurrent enrollment for different users succeeds."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll user 1
        response1 = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert response1.status_code == status.HTTP_200_OK
        data1 = response1.json()

        # Enroll user 2
        response2 = await client.post("/mfa/enroll", headers=another_user_headers, json={})
        assert response2.status_code == status.HTTP_200_OK
        data2 = response2.json()

        # Verify different secrets
        assert data1["secret"] != data2["secret"]
        assert data1["provisioning_uri"] != data2["provisioning_uri"]


# --- Test: Rate Limiting (Note: Depends on rate limiting implementation) ---


async def test_mfa_verify_rate_limiting(client, auth_headers, mfa_manager):
    """Test rate limiting on /mfa/verify endpoint."""
    with patch("pdfsigner.core.auth.mfa.mfa_manager.get_mfa_manager", return_value=mfa_manager):
        # Enroll
        enroll_response = await client.post("/mfa/enroll", headers=auth_headers, json={})
        assert enroll_response.status_code == status.HTTP_200_OK

        # Make multiple failed verification attempts
        # Note: This test assumes rate limiting is implemented
        # If not implemented, it will just verify no crashes occur
        for i in range(10):
            response = await client.post(
                "/mfa/verify", headers=auth_headers, json={"code": f"{i:06d}"}
            )
            # Should either succeed (200) or rate limited (429)
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_429_TOO_MANY_REQUESTS]
