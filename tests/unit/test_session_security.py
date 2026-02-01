"""
test_session_security.py - Security tests for session management

Tests session regeneration to prevent Session Fixation attacks.
"""

import time
from datetime import datetime

import pytest

from pdfsigner.core.session.session_manager import SessionManager


@pytest.fixture
def session_manager(tmp_path):
    """Create session manager with temporary database."""
    db_path = tmp_path / "test_sessions.db"
    return SessionManager(db_path=db_path)


# --- Session Regeneration Tests (Session Fixation Prevention) ---


def test_regenerate_session_id_creates_new_session(session_manager):
    """Test regenerate_session_id creates new session with different ID."""
    # Create original session
    original_session = session_manager.create_session(
        user_id="user123", ip_address="192.168.1.100", user_agent="Mozilla/5.0"
    )
    original_id = original_session.id

    # Regenerate session ID
    new_session = session_manager.regenerate_session_id(original_id)

    # Verify new session has different ID
    assert new_session.id != original_id
    assert len(new_session.id) > 0

    # Verify new session is in database
    retrieved_session = session_manager.get_session(new_session.id)
    assert retrieved_session is not None
    assert retrieved_session.id == new_session.id


def test_regenerate_session_id_copies_user_data(session_manager):
    """Test regenerate_session_id copies user_id and metadata."""
    # Create original session with metadata
    original_session = session_manager.create_session(
        user_id="alice",
        ip_address="10.0.0.1",
        user_agent="Chrome/96.0 (Windows)",
    )

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original_session.id)

    # Verify user data is copied
    assert new_session.user_id == original_session.user_id
    assert new_session.ip_address == original_session.ip_address
    assert new_session.user_agent == original_session.user_agent


def test_regenerate_session_id_updates_timestamps(session_manager):
    """Test regenerate_session_id creates fresh timestamps."""
    # Create original session
    original_session = session_manager.create_session(user_id="user123")
    original_created = original_session.created_at
    original_activity = original_session.last_activity

    # Wait a bit to ensure time difference
    time.sleep(0.1)

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original_session.id)

    # Verify timestamps are updated
    assert new_session.created_at > original_created
    assert new_session.last_activity > original_activity
    assert new_session.created_at == new_session.last_activity  # Fresh session


def test_regenerate_session_id_deletes_old_session(session_manager):
    """Test regenerate_session_id removes the old session."""
    # Create original session
    original_session = session_manager.create_session(user_id="user123")
    original_id = original_session.id

    # Verify original exists
    assert session_manager.get_session(original_id) is not None

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original_id)

    # Verify old session is deleted
    assert session_manager.get_session(original_id) is None

    # Verify new session exists
    assert session_manager.get_session(new_session.id) is not None


def test_regenerate_session_id_raises_if_session_not_found(session_manager):
    """Test regenerate_session_id raises ValueError if session doesn't exist."""
    with pytest.raises(ValueError, match="Session .* not found"):
        session_manager.regenerate_session_id("nonexistent-session-id")


def test_regenerate_session_id_extends_expiration(session_manager):
    """Test regenerate_session_id resets expiration time."""
    # Create original session
    original_session = session_manager.create_session(user_id="user123")
    original_expires = original_session.expires_at

    # Wait a bit
    time.sleep(0.1)

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original_session.id)

    # Verify expiration is extended
    assert new_session.expires_at > original_expires
    assert new_session.is_active


def test_regenerate_session_id_atomic_operation(session_manager):
    """Test regenerate_session_id is atomic (both insert and delete succeed)."""
    # Create original session
    original_session = session_manager.create_session(user_id="user123")
    original_id = original_session.id

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original_id)

    # Count total sessions
    all_sessions = session_manager.get_user_sessions("user123")
    assert len(all_sessions) == 1  # Only new session exists
    assert all_sessions[0].id == new_session.id


def test_regenerate_session_id_preserves_user_session_count(session_manager):
    """Test regenerate_session_id doesn't increase total session count."""
    user_id = "user123"

    # Create original session
    original = session_manager.create_session(user_id=user_id)
    assert len(session_manager.get_user_sessions(user_id)) == 1

    # Regenerate session
    session_manager.regenerate_session_id(original.id)

    # Verify still only 1 session
    sessions = session_manager.get_user_sessions(user_id)
    assert len(sessions) == 1


# --- Session Fixation Attack Prevention Tests ---


def test_session_fixation_prevention_scenario(session_manager):
    """
    Test Session Fixation attack prevention scenario.

    Simulates:
    1. Attacker gets a session ID (pre-authentication)
    2. Victim authenticates
    3. Session ID is regenerated (attacker's ID is invalidated)
    4. Attacker cannot use the old ID
    """
    # 1. Attacker obtains a session ID (pre-auth)
    attacker_session = session_manager.create_session(user_id="anonymous", ip_address="10.0.0.99")
    attacker_session_id = attacker_session.id

    # 2. Victim authenticates - session is regenerated
    legitimate_session = session_manager.regenerate_session_id(attacker_session_id)

    # 3. Verify attacker's session is now invalid
    assert session_manager.get_session(attacker_session_id) is None

    # 4. Verify only the new session works
    assert session_manager.get_session(legitimate_session.id) is not None
    assert legitimate_session.id != attacker_session_id


def test_multiple_regenerations_maintain_single_session(session_manager):
    """Test multiple regenerations don't create session leaks."""
    user_id = "user123"

    # Create initial session
    session1 = session_manager.create_session(user_id=user_id)

    # Regenerate multiple times
    session2 = session_manager.regenerate_session_id(session1.id)
    session3 = session_manager.regenerate_session_id(session2.id)
    session4 = session_manager.regenerate_session_id(session3.id)

    # Verify only the latest session exists
    assert session_manager.get_session(session1.id) is None
    assert session_manager.get_session(session2.id) is None
    assert session_manager.get_session(session3.id) is None
    assert session_manager.get_session(session4.id) is not None

    # Verify only 1 session total
    sessions = session_manager.get_user_sessions(user_id)
    assert len(sessions) == 1
    assert sessions[0].id == session4.id


def test_regenerate_session_maintains_session_validity(session_manager):
    """Test regenerated session is valid and active."""
    # Create and regenerate session
    original = session_manager.create_session(user_id="user123")
    new_session = session_manager.regenerate_session_id(original.id)

    # Verify new session is valid
    assert session_manager.validate_session(new_session.id)
    assert new_session.is_active
    assert not new_session.is_expired


def test_regenerate_expired_session_creates_fresh_session(session_manager):
    """Test regenerating an expired session creates a fresh active session."""
    # Create session
    original = session_manager.create_session(user_id="user123")

    # Manually expire it by setting expires_at in past
    with session_manager._get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (datetime(2020, 1, 1).isoformat(), original.id),
        )

    # Verify it's expired
    expired_session = session_manager.get_session(original.id)
    assert expired_session.is_expired

    # Regenerate the expired session
    new_session = session_manager.regenerate_session_id(original.id)

    # Verify new session is active (not expired)
    assert new_session.is_active
    assert not new_session.is_expired
    assert new_session.expires_at > datetime.now()


# --- Integration with Login Flow ---


def test_login_invalidates_previous_sessions(session_manager):
    """
    Test that login flow invalidates any previous sessions for the user.

    This simulates the pattern in auth.py where existing sessions are
    terminated before creating a new one after successful authentication.
    """
    user_id = "alice"

    # Simulate user has 2 existing sessions (e.g., from different devices)
    session1 = session_manager.create_session(user_id=user_id, ip_address="10.0.0.1")
    session2 = session_manager.create_session(user_id=user_id, ip_address="10.0.0.2")

    # Verify both sessions exist
    assert len(session_manager.get_user_sessions(user_id)) == 2

    # Simulate login: terminate all existing sessions
    existing_sessions = session_manager.get_user_sessions(user_id)
    for old_session in existing_sessions:
        session_manager.terminate_session(old_session.id)

    # Create new session (fresh session ID after login)
    new_session = session_manager.create_session(user_id=user_id, ip_address="10.0.0.3")

    # Verify only new session exists
    sessions = session_manager.get_user_sessions(user_id)
    assert len(sessions) == 1
    assert sessions[0].id == new_session.id

    # Verify old sessions are invalid
    assert session_manager.get_session(session1.id) is None
    assert session_manager.get_session(session2.id) is None


def test_concurrent_login_from_different_devices(session_manager):
    """Test concurrent logins create separate sessions correctly."""
    user_id = "bob"

    # Simulate concurrent logins from 3 devices
    session_laptop = session_manager.create_session(
        user_id=user_id, ip_address="192.168.1.10", user_agent="Chrome/Laptop"
    )
    session_phone = session_manager.create_session(
        user_id=user_id, ip_address="192.168.1.20", user_agent="Safari/iPhone"
    )
    session_tablet = session_manager.create_session(
        user_id=user_id, ip_address="192.168.1.30", user_agent="Chrome/iPad"
    )

    # Verify all 3 sessions exist
    sessions = session_manager.get_user_sessions(user_id)
    assert len(sessions) == 3

    session_ids = {s.id for s in sessions}
    assert session_laptop.id in session_ids
    assert session_phone.id in session_ids
    assert session_tablet.id in session_ids


# --- Edge Cases ---


def test_regenerate_session_with_null_metadata(session_manager):
    """Test regenerate_session_id works with null IP and user_agent."""
    # Create session without metadata
    original = session_manager.create_session(user_id="user123", ip_address=None, user_agent=None)

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original.id)

    # Verify metadata is preserved (None values)
    assert new_session.ip_address is None
    assert new_session.user_agent is None


def test_regenerate_session_with_special_characters_in_user_id(session_manager):
    """Test regenerate_session_id handles special characters in user_id."""
    # Create session with special characters
    original = session_manager.create_session(user_id="user@example.com")

    # Regenerate session
    new_session = session_manager.regenerate_session_id(original.id)

    # Verify user_id is preserved
    assert new_session.user_id == "user@example.com"
