"""
break_glass.py - Emergency access (break-glass) service

Implements HIPAA SS164.312(a)(2)(ii) emergency access procedure.
Manages approval workflow, access expiration, and audit logging.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.emergency.emergency_access import (
    EmergencyAccessRepository,
    get_emergency_repository,
)
from pdfsigner.core.emergency.emergency_types import (
    EmergencyAccessRequest,
    EmergencyAccessStatus,
)
from pdfsigner.exceptions import EmergencyAccessError


class BreakGlassService:
    """
    Service for managing emergency access (break-glass) procedures.

    Provides high-level operations for requesting, approving, denying,
    and revoking emergency access. Integrates with audit logging for
    full compliance tracking.
    """

    def __init__(
        self,
        repository: EmergencyAccessRepository | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.repository = repository or get_emergency_repository()
        self.audit_logger = audit_logger or AuditLogger.get_instance()
        self.settings = get_settings()

    def _require_healthcare_mode(self) -> None:
        """Raise if healthcare mode is not enabled."""
        if not self.settings.healthcare_mode:
            raise EmergencyAccessError("Emergency access requires healthcare_mode to be enabled")

    def _fetch_request_or_raise(self, request_id: str) -> EmergencyAccessRequest:
        """Fetch request by ID, raise EmergencyAccessError if not found."""
        request = self.repository.get_request(request_id)
        if request is None:
            raise EmergencyAccessError(f"Emergency access request not found: {request_id}")
        return request

    def _verify_status(
        self, request: EmergencyAccessRequest, expected: EmergencyAccessStatus, action: str
    ) -> None:
        """Verify request has the expected status, raise if not."""
        if request.status != expected:
            raise EmergencyAccessError(
                f"Request {request.id} cannot be {action} (current status: {request.status.value})"
            )

    def request_emergency_access(self, requester_id: str, reason: str) -> EmergencyAccessRequest:
        """
        Request emergency access.

        Args:
            requester_id: User ID requesting emergency access
            reason: Justification for emergency access (required for audit trail)

        Returns:
            Created EmergencyAccessRequest

        Raises:
            EmergencyAccessError: If healthcare mode is disabled or request fails
        """
        self._require_healthcare_mode()

        if not reason or not reason.strip():
            raise EmergencyAccessError("Reason for emergency access is required")

        request = self.repository.create_request(requester_id, reason)

        self._log_event(
            event_type=AuditEventType.EMERGENCY_ACCESS_REQUESTED,
            request=request,
            status="SUCCESS",
            details={
                "reason": reason,
                "require_approval": self.settings.healthcare_emergency_require_approval,
            },
        )

        logger.info(
            f"Emergency access requested by user {requester_id}: {request.id} "
            f"(approval_required={self.settings.healthcare_emergency_require_approval})"
        )

        if not self.settings.healthcare_emergency_require_approval:
            logger.info(f"Auto-approving emergency request {request.id} (require_approval=False)")
            request = self.approve_request(request.id, admin_id="system")

        return request

    def approve_request(self, request_id: str, admin_id: str) -> EmergencyAccessRequest:
        """
        Approve emergency access request.

        Args:
            request_id: Request ID to approve
            admin_id: Admin user ID performing approval (or "system" for auto-approval)

        Returns:
            Updated EmergencyAccessRequest

        Raises:
            EmergencyAccessError: If request not found or not in pending status
        """
        self._require_healthcare_mode()
        request = self._fetch_request_or_raise(request_id)
        self._verify_status(request, EmergencyAccessStatus.PENDING, "approved")

        request.status = EmergencyAccessStatus.APPROVED
        request.approved_by = admin_id
        request.approved_at = datetime.now(UTC)
        request.expires_at = datetime.now(UTC) + timedelta(
            hours=self.settings.healthcare_emergency_duration_hours
        )

        self.repository.update_request(request)

        self._log_event(
            event_type=AuditEventType.EMERGENCY_ACCESS_APPROVED,
            request=request,
            status="SUCCESS",
            details={
                "approved_by": admin_id,
                "duration_hours": self.settings.healthcare_emergency_duration_hours,
                "expires_at": request.expires_at.isoformat(),
            },
        )

        logger.info(
            f"Emergency access approved: {request_id} by {admin_id} "
            f"(expires: {request.expires_at.isoformat()})"
        )
        return request

    def deny_request(
        self, request_id: str, admin_id: str, reason: str = ""
    ) -> EmergencyAccessRequest:
        """
        Deny emergency access request.

        Args:
            request_id: Request ID to deny
            admin_id: Admin user ID performing denial
            reason: Optional reason for denial

        Returns:
            Updated EmergencyAccessRequest

        Raises:
            EmergencyAccessError: If request not found or not in pending status
        """
        self._require_healthcare_mode()
        request = self._fetch_request_or_raise(request_id)
        self._verify_status(request, EmergencyAccessStatus.PENDING, "denied")

        request.status = EmergencyAccessStatus.DENIED
        request.approved_by = admin_id
        request.approved_at = datetime.now(UTC)

        self.repository.update_request(request)

        self._log_event(
            event_type=AuditEventType.EMERGENCY_ACCESS_DENIED,
            request=request,
            status="SUCCESS",
            details={"denied_by": admin_id, "denial_reason": reason},
        )

        logger.info(f"Emergency access denied: {request_id} by {admin_id}")
        return request

    def revoke_access(
        self, request_id: str, admin_id: str, reason: str = ""
    ) -> EmergencyAccessRequest:
        """
        Revoke active emergency access.

        Args:
            request_id: Request ID to revoke
            admin_id: Admin user ID performing revocation
            reason: Optional reason for revocation

        Returns:
            Updated EmergencyAccessRequest

        Raises:
            EmergencyAccessError: If request not found or not currently approved
        """
        self._require_healthcare_mode()
        request = self._fetch_request_or_raise(request_id)
        self._verify_status(request, EmergencyAccessStatus.APPROVED, "revoked")

        request.status = EmergencyAccessStatus.REVOKED
        request.revoked_by = admin_id
        request.revoked_at = datetime.now(UTC)

        self.repository.update_request(request)

        self._log_event(
            event_type=AuditEventType.EMERGENCY_ACCESS_REVOKED,
            request=request,
            status="SUCCESS",
            details={"revoked_by": admin_id, "revocation_reason": reason},
        )

        logger.info(f"Emergency access revoked: {request_id} by {admin_id}")
        return request

    def check_emergency_access(self, user_id: str) -> bool:
        """
        Check if user has active emergency access.

        Args:
            user_id: User ID to check

        Returns:
            True if user has active emergency access, False otherwise
        """
        if not self.settings.healthcare_mode:
            return False

        self.repository.cleanup_expired_requests()
        request = self.repository.get_active_request(user_id)
        return request is not None and request.is_active

    def log_document_access(self, request_id: str, document_path: str | Path) -> None:
        """
        Log document access using emergency access.

        Args:
            request_id: Emergency access request ID
            document_path: Path to document accessed

        Raises:
            EmergencyAccessError: If request not found or not active
        """
        if not self.settings.healthcare_mode:
            return

        request = self._fetch_request_or_raise(request_id)

        if not request.is_active:
            raise EmergencyAccessError(f"Emergency access {request_id} is not active")

        doc_path_str = str(document_path)
        if doc_path_str not in request.documents_accessed:
            request.documents_accessed.append(doc_path_str)
            self.repository.update_request(request)

        self._log_event(
            event_type=AuditEventType.EMERGENCY_ACCESS_USED,
            request=request,
            status="SUCCESS",
            details={
                "document_path": doc_path_str,
                "access_count": len(request.documents_accessed),
            },
        )

        logger.debug(
            f"Emergency access {request_id} used for document: {doc_path_str} "
            f"(total accessed: {len(request.documents_accessed)})"
        )

    def get_user_requests(self, user_id: str, limit: int = 50) -> list[EmergencyAccessRequest]:
        """Get emergency access requests for a user."""
        if not self.settings.healthcare_mode:
            return []
        return self.repository.get_user_requests(user_id, limit=limit)

    def get_pending_requests(self) -> list[EmergencyAccessRequest]:
        """Get all pending emergency access requests."""
        if not self.settings.healthcare_mode:
            return []
        return self.repository.get_pending_requests()

    def _log_event(
        self,
        event_type: AuditEventType,
        request: EmergencyAccessRequest,
        status: str,
        details: dict | None = None,
    ) -> None:
        """Log emergency access event to audit trail."""
        event_details = details or {}
        event_details.update(
            {
                "request_id": request.id,
                "requester_id": request.requester_id,
                "reason": request.reason,
                "request_status": request.status.value,
            }
        )

        event = AuditEvent(
            event_type=event_type,
            status=status,
            user_id=request.requester_id,
            details=event_details,
            phi_accessed=False,
        )

        self.audit_logger.log_event(event)


# Singleton instance
_break_glass_service: BreakGlassService | None = None


def get_break_glass_service() -> BreakGlassService:
    """Get singleton break-glass service."""
    global _break_glass_service
    if _break_glass_service is None:
        _break_glass_service = BreakGlassService()
    return _break_glass_service
