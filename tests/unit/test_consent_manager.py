"""
Test consent manager (GDPR Article 7).

Tests cover:
- Consent granting and withdrawal
- Active consent queries
- Audit trail
- Policy version tracking
- Error handling
"""

import tempfile
from pathlib import Path

import pytest

from pdfsigner.core.gdpr import (
    ConsentManager,
    ConsentRepository,
    ConsentType,
)


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def consent_repo(temp_db):
    """Create consent repository with temporary database."""
    return ConsentRepository(db_path=temp_db)


@pytest.fixture
def consent_manager(consent_repo):
    """Create consent manager with test repository and disabled audit."""
    from unittest.mock import Mock

    # Mock audit logger to avoid side effects
    mock_audit_logger = Mock()
    mock_audit_logger.enabled = False

    return ConsentManager(
        consent_repository=consent_repo,
        audit_logger=mock_audit_logger,
    )


# --- Grant Consent Tests ---


def test_grant_consent_success(consent_manager):
    """Test successful consent grant."""
    user_id = "test_user_1"
    consent_type = ConsentType.ANALYTICS

    consent = consent_manager.grant_consent(
        user_id=user_id,
        consent_type=consent_type,
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
        policy_version="1.0.0",
    )

    assert consent.user_id == user_id
    assert consent.consent_type == consent_type
    assert consent.granted is True
    assert consent.withdrawn_at is None
    assert consent.ip_address == "192.168.1.100"
    assert consent.policy_version == "1.0.0"


def test_grant_consent_creates_unique_id(consent_manager):
    """Test that each consent grant creates unique ID."""
    user_id = "test_user_2"

    consent1 = consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent2 = consent_manager.grant_consent(user_id, ConsentType.MARKETING)

    assert consent1.id != consent2.id


def test_grant_consent_updates_existing(consent_manager):
    """Test that granting existing consent creates new record."""
    user_id = "test_user_3"
    consent_type = ConsentType.ANALYTICS

    # Grant consent
    consent1 = consent_manager.grant_consent(user_id, consent_type, policy_version="1.0.0")

    # Grant again (user re-consents after withdrawal)
    consent2 = consent_manager.grant_consent(user_id, consent_type, policy_version="2.0.0")

    # Should create new record
    assert consent1.id != consent2.id

    # Both should exist in history
    history = consent_manager.get_consent_audit_trail(user_id)
    assert len(history) == 2


def test_grant_consent_without_optional_fields(consent_manager):
    """Test granting consent without IP/user agent/policy version."""
    user_id = "test_user_4"

    consent = consent_manager.grant_consent(user_id, ConsentType.PROCESSING)

    assert consent.user_id == user_id
    assert consent.granted is True
    assert consent.ip_address is None
    assert consent.user_agent is None
    assert consent.policy_version is None


# --- Withdraw Consent Tests ---


def test_withdraw_consent_success(consent_manager):
    """Test successful consent withdrawal."""
    user_id = "test_user_5"
    consent_type = ConsentType.MARKETING

    # Grant consent first
    consent_manager.grant_consent(user_id, consent_type)

    # Withdraw consent
    withdrawal = consent_manager.withdraw_consent(
        user_id=user_id,
        consent_type=consent_type,
        ip_address="192.168.1.200",
    )

    assert withdrawal.user_id == user_id
    assert withdrawal.consent_type == consent_type
    assert withdrawal.granted is False
    assert withdrawal.withdrawn_at is not None
    assert withdrawal.ip_address == "192.168.1.200"


def test_withdraw_consent_not_granted(consent_manager):
    """Test withdrawing consent that was never granted."""
    user_id = "test_user_6"

    with pytest.raises(ValueError, match="No active consent found"):
        consent_manager.withdraw_consent(user_id, ConsentType.ANALYTICS)


def test_withdraw_consent_already_withdrawn(consent_manager):
    """Test withdrawing already withdrawn consent."""
    user_id = "test_user_7"
    consent_type = ConsentType.RESEARCH

    # Grant and withdraw
    consent_manager.grant_consent(user_id, consent_type)
    consent_manager.withdraw_consent(user_id, consent_type)

    # Try to withdraw again
    with pytest.raises(ValueError, match="No active consent found"):
        consent_manager.withdraw_consent(user_id, consent_type)


def test_withdraw_consent_creates_new_record(consent_manager):
    """Test that withdrawal creates a new record, not modifies existing."""
    user_id = "test_user_8"
    consent_type = ConsentType.THIRD_PARTY

    # Grant consent
    original = consent_manager.grant_consent(user_id, consent_type)

    # Withdraw consent
    withdrawal = consent_manager.withdraw_consent(user_id, consent_type)

    # Should be different records
    assert original.id != withdrawal.id

    # Original should still exist in database
    history = consent_manager.get_consent_audit_trail(user_id)
    assert len(history) == 2
    assert history[0].id == withdrawal.id  # Most recent first
    assert history[1].id == original.id


# --- Active Consents Tests ---


def test_get_active_consents_returns_only_active(consent_manager):
    """Test that get_active_consents returns only granted, non-withdrawn consents."""
    user_id = "test_user_9"

    # Grant multiple consents
    consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.grant_consent(user_id, ConsentType.MARKETING)
    consent_manager.grant_consent(user_id, ConsentType.RESEARCH)

    # Withdraw one
    consent_manager.withdraw_consent(user_id, ConsentType.MARKETING)

    # Get active consents
    active = consent_manager.get_active_consents(user_id)

    assert len(active) == 2
    active_types = {c.consent_type for c in active}
    assert ConsentType.ANALYTICS in active_types
    assert ConsentType.RESEARCH in active_types
    assert ConsentType.MARKETING not in active_types


def test_get_active_consents_empty(consent_manager):
    """Test get_active_consents for user with no consents."""
    active = consent_manager.get_active_consents("nonexistent_user")
    assert active == []


def test_get_active_consents_all_withdrawn(consent_manager):
    """Test get_active_consents when all consents are withdrawn."""
    user_id = "test_user_10"

    # Grant and withdraw all
    consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.grant_consent(user_id, ConsentType.MARKETING)
    consent_manager.withdraw_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.withdraw_consent(user_id, ConsentType.MARKETING)

    active = consent_manager.get_active_consents(user_id)
    assert active == []


def test_get_active_consents_handles_regrant(consent_manager):
    """Test that regranted consent shows as active."""
    user_id = "test_user_11"
    consent_type = ConsentType.ANALYTICS

    # Grant, withdraw, grant again
    consent_manager.grant_consent(user_id, consent_type)
    consent_manager.withdraw_consent(user_id, consent_type)
    consent_manager.grant_consent(user_id, consent_type)

    # Should show as active
    active = consent_manager.get_active_consents(user_id)
    assert len(active) == 1
    assert active[0].consent_type == consent_type
    assert active[0].granted is True


# --- Has Consent Tests ---


def test_has_consent_true(consent_manager):
    """Test has_consent returns True for active consent."""
    user_id = "test_user_12"

    consent_manager.grant_consent(user_id, ConsentType.PROCESSING)

    assert consent_manager.has_consent(user_id, ConsentType.PROCESSING) is True


def test_has_consent_false_not_granted(consent_manager):
    """Test has_consent returns False for non-granted consent."""
    assert consent_manager.has_consent("user_13", ConsentType.ANALYTICS) is False


def test_has_consent_false_withdrawn(consent_manager):
    """Test has_consent returns False for withdrawn consent."""
    user_id = "test_user_14"

    consent_manager.grant_consent(user_id, ConsentType.MARKETING)
    consent_manager.withdraw_consent(user_id, ConsentType.MARKETING)

    assert consent_manager.has_consent(user_id, ConsentType.MARKETING) is False


def test_has_consent_true_after_regrant(consent_manager):
    """Test has_consent returns True after withdraw and regrant."""
    user_id = "test_user_15"
    consent_type = ConsentType.RESEARCH

    consent_manager.grant_consent(user_id, consent_type)
    consent_manager.withdraw_consent(user_id, consent_type)
    consent_manager.grant_consent(user_id, consent_type)

    assert consent_manager.has_consent(user_id, consent_type) is True


# --- Audit Trail Tests ---


def test_get_consent_audit_trail_ordered_by_date(consent_manager):
    """Test that audit trail is ordered by granted_at descending."""
    user_id = "test_user_16"

    # Create consents at different times (simulate with multiple operations)
    consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.grant_consent(user_id, ConsentType.MARKETING)
    consent_manager.withdraw_consent(user_id, ConsentType.ANALYTICS)

    trail = consent_manager.get_consent_audit_trail(user_id)

    assert len(trail) == 3
    # Should be ordered newest first
    for i in range(len(trail) - 1):
        assert trail[i].granted_at >= trail[i + 1].granted_at


def test_get_consent_audit_trail_includes_all_records(consent_manager):
    """Test that audit trail includes both grants and withdrawals."""
    user_id = "test_user_17"

    consent_manager.grant_consent(user_id, ConsentType.PROCESSING)
    consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.withdraw_consent(user_id, ConsentType.ANALYTICS)

    trail = consent_manager.get_consent_audit_trail(user_id)

    assert len(trail) == 3

    # Check that we have both granted and withdrawn records
    granted_count = sum(1 for c in trail if c.granted)
    withdrawn_count = sum(1 for c in trail if not c.granted)

    assert granted_count == 2
    assert withdrawn_count == 1


def test_get_consent_audit_trail_empty(consent_manager):
    """Test audit trail for user with no consents."""
    trail = consent_manager.get_consent_audit_trail("nonexistent_user")
    assert trail == []


# --- Policy Version Tracking Tests ---


def test_grant_consent_tracks_policy_version(consent_manager):
    """Test that policy version is stored with consent."""
    user_id = "test_user_18"

    consent = consent_manager.grant_consent(
        user_id=user_id,
        consent_type=ConsentType.ANALYTICS,
        policy_version="2.1.0",
    )

    assert consent.policy_version == "2.1.0"


def test_regrant_consent_updates_policy_version(consent_manager):
    """Test that regranting updates policy version."""
    user_id = "test_user_19"
    consent_type = ConsentType.MARKETING

    # Grant with old policy
    consent_manager.grant_consent(user_id, consent_type, policy_version="1.0.0")

    # Withdraw
    consent_manager.withdraw_consent(user_id, consent_type)

    # Grant again with new policy
    new_consent = consent_manager.grant_consent(user_id, consent_type, policy_version="2.0.0")

    assert new_consent.policy_version == "2.0.0"

    # Verify audit trail has both versions
    trail = consent_manager.get_consent_audit_trail(user_id)
    versions = [c.policy_version for c in trail if c.granted]
    assert "1.0.0" in versions
    assert "2.0.0" in versions


# --- Consent Summary Tests ---


def test_get_consent_summary_all_types(consent_manager):
    """Test consent summary includes all consent types."""
    user_id = "test_user_20"

    summary = consent_manager.get_consent_summary(user_id)

    # Should have all consent types
    assert len(summary) == len(ConsentType)
    for consent_type in ConsentType:
        assert consent_type in summary


def test_get_consent_summary_reflects_active_status(consent_manager):
    """Test consent summary correctly reflects active/inactive status."""
    user_id = "test_user_21"

    # Grant some consents
    consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.grant_consent(user_id, ConsentType.MARKETING)

    summary = consent_manager.get_consent_summary(user_id)

    assert summary[ConsentType.ANALYTICS] is True
    assert summary[ConsentType.MARKETING] is True
    assert summary[ConsentType.PROCESSING] is False
    assert summary[ConsentType.RESEARCH] is False
    assert summary[ConsentType.THIRD_PARTY] is False


def test_get_consent_summary_after_withdrawal(consent_manager):
    """Test consent summary updates after withdrawal."""
    user_id = "test_user_22"

    consent_manager.grant_consent(user_id, ConsentType.RESEARCH)
    consent_manager.withdraw_consent(user_id, ConsentType.RESEARCH)

    summary = consent_manager.get_consent_summary(user_id)

    assert summary[ConsentType.RESEARCH] is False


# --- Integration Tests ---


def test_full_consent_lifecycle(consent_manager):
    """Test complete consent lifecycle: grant -> withdraw -> regrant."""
    user_id = "test_user_23"
    consent_type = ConsentType.THIRD_PARTY

    # 1. Grant consent
    grant1 = consent_manager.grant_consent(user_id, consent_type, policy_version="1.0.0")
    assert consent_manager.has_consent(user_id, consent_type) is True

    # 2. Withdraw consent
    withdrawal = consent_manager.withdraw_consent(user_id, consent_type)
    assert consent_manager.has_consent(user_id, consent_type) is False

    # 3. Grant again
    grant2 = consent_manager.grant_consent(user_id, consent_type, policy_version="2.0.0")
    assert consent_manager.has_consent(user_id, consent_type) is True

    # 4. Verify audit trail
    trail = consent_manager.get_consent_audit_trail(user_id)
    assert len(trail) == 3
    assert trail[0].id == grant2.id
    assert trail[1].id == withdrawal.id
    assert trail[2].id == grant1.id


def test_multiple_users_isolated(consent_manager):
    """Test that consents for different users are isolated."""
    user1 = "user_24"
    user2 = "user_25"

    # User 1 grants consent
    consent_manager.grant_consent(user1, ConsentType.ANALYTICS)

    # User 2 should not have consent
    assert consent_manager.has_consent(user2, ConsentType.ANALYTICS) is False

    # User 2's consent should not affect user 1
    consent_manager.grant_consent(user2, ConsentType.MARKETING)

    assert consent_manager.has_consent(user1, ConsentType.ANALYTICS) is True
    assert consent_manager.has_consent(user1, ConsentType.MARKETING) is False
    assert consent_manager.has_consent(user2, ConsentType.ANALYTICS) is False
    assert consent_manager.has_consent(user2, ConsentType.MARKETING) is True


def test_concurrent_consent_types(consent_manager):
    """Test user can have multiple active consents simultaneously."""
    user_id = "test_user_26"

    # Grant multiple consents
    consent_manager.grant_consent(user_id, ConsentType.PROCESSING)
    consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent_manager.grant_consent(user_id, ConsentType.MARKETING)
    consent_manager.grant_consent(user_id, ConsentType.RESEARCH)

    # All should be active
    active = consent_manager.get_active_consents(user_id)
    assert len(active) == 4

    # Withdraw one should not affect others
    consent_manager.withdraw_consent(user_id, ConsentType.MARKETING)

    active = consent_manager.get_active_consents(user_id)
    assert len(active) == 3
    assert consent_manager.has_consent(user_id, ConsentType.PROCESSING) is True
    assert consent_manager.has_consent(user_id, ConsentType.ANALYTICS) is True
    assert consent_manager.has_consent(user_id, ConsentType.MARKETING) is False
    assert consent_manager.has_consent(user_id, ConsentType.RESEARCH) is True


# --- Edge Cases ---


def test_consent_with_empty_strings(consent_manager):
    """Test consent with empty string metadata."""
    user_id = "test_user_27"

    consent = consent_manager.grant_consent(
        user_id=user_id,
        consent_type=ConsentType.ANALYTICS,
        ip_address="",
        user_agent="",
        policy_version="",
    )

    assert consent.ip_address == ""
    assert consent.user_agent == ""
    assert consent.policy_version == ""


def test_consent_repository_persistence(temp_db):
    """Test that consents persist across repository instances."""
    user_id = "test_user_28"

    # Create first repository and add consent
    repo1 = ConsentRepository(db_path=temp_db)
    manager1 = ConsentManager(consent_repository=repo1)
    manager1.grant_consent(user_id, ConsentType.ANALYTICS)

    # Create second repository with same database
    repo2 = ConsentRepository(db_path=temp_db)
    manager2 = ConsentManager(consent_repository=repo2)

    # Should be able to retrieve consent
    assert manager2.has_consent(user_id, ConsentType.ANALYTICS) is True


def test_consent_timestamp_ordering(consent_manager):
    """Test that consent timestamps maintain correct ordering."""
    user_id = "test_user_29"

    # Create multiple consents
    consent1 = consent_manager.grant_consent(user_id, ConsentType.ANALYTICS)
    consent2 = consent_manager.grant_consent(user_id, ConsentType.MARKETING)
    consent3 = consent_manager.grant_consent(user_id, ConsentType.RESEARCH)

    # Timestamps should be ordered
    assert consent1.granted_at <= consent2.granted_at
    assert consent2.granted_at <= consent3.granted_at

    # Audit trail should reflect this
    trail = consent_manager.get_consent_audit_trail(user_id)
    assert trail[0].granted_at >= trail[1].granted_at
    assert trail[1].granted_at >= trail[2].granted_at
