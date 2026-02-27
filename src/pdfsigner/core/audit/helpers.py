"""Audit event emission helpers to reduce boilerplate.

Provides a single function to replace the try/except audit emission
pattern duplicated across 13+ modules in the codebase.
"""

from __future__ import annotations

from typing import Any

from loguru import logger


def emit_audit_event(
    event_type: str | Any,
    details: dict[str, Any] | None = None,
    user_id: str | None = None,
    **kwargs: Any,
) -> None:
    """Emit an audit event with standard error handling.

    Wraps the try/except pattern used across 13+ modules.
    Lazy-imports audit internals to avoid circular dependencies.

    Args:
        event_type: AuditEventType enum value for the event.
        details: Dictionary of event-specific details.
        user_id: User identifier for the event.
        **kwargs: Additional AuditEvent fields (status, session_id, etc).
    """
    try:
        from pdfsigner.core.audit.audit_event import AuditEvent
        from pdfsigner.core.audit.audit_logger import AuditLogger

        audit_logger = AuditLogger.get_instance()
        event = AuditEvent(
            event_type=event_type,
            details=details or {},
            user_id=user_id,
            **kwargs,
        )
        audit_logger.log_event(event)
    except Exception as e:
        logger.debug(f"Failed to emit audit event '{event_type}': {e}")
