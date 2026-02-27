"""
encryption_policy.py - Encryption policy engine for document protection

Enforces mandatory encryption based on configurable triggers:
- PHI detection (HIPAA compliance)
- Department-based rules
- Always-encrypt policies
- Manual user requests

Author: PDFSigner Team
"""

from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.policies.policy_types import (
    EncryptionPolicy,
    PolicyAction,
    PolicyResult,
    PolicyTrigger,
)

# Re-export types for backward compatibility
__all__ = [
    "EncryptionPolicy",
    "PolicyAction",
    "PolicyEngine",
    "PolicyResult",
    "PolicyTrigger",
    "get_policy_engine",
]


class PolicyEngine:
    """
    Evaluates encryption policies against documents.

    Policies are checked in priority order. The first triggered policy
    determines the action to take. If no policies trigger, returns
    a non-triggered result with WARN action.
    """

    def __init__(self, policies: list[EncryptionPolicy] | None = None):
        """
        Initialize policy engine.

        Args:
            policies: List of policies to evaluate. If None, loads default HIPAA policies.
        """
        self._policies = policies if policies is not None else self._load_default_policies()
        # Sort by priority (descending)
        self._policies.sort(key=lambda p: p.priority, reverse=True)

    def evaluate(
        self,
        pdf_path: Path,
        user_department: str | None = None,
    ) -> PolicyResult:
        """
        Evaluate all policies against a document.

        Args:
            pdf_path: Path to the PDF document to evaluate
            user_department: User's department for department-based policies

        Returns:
            PolicyResult with the highest-priority triggered policy,
            or non-triggered result if no policies match.
        """
        # Check if healthcare mode is enabled
        from pdfsigner.config.settings import get_settings

        settings = get_settings()
        if not settings.healthcare_mode:
            logger.debug("Healthcare mode disabled, skipping policy enforcement")
            return PolicyResult(
                triggered=False,
                policy=None,
                action=PolicyAction.WARN,
                reason="Healthcare mode disabled in settings",
            )

        # Evaluate policies in priority order
        for policy in self._policies:
            if not policy.enabled:
                logger.debug(f"Skipping disabled policy: {policy.name}")
                continue

            logger.debug(f"Evaluating policy: {policy.name} (trigger: {policy.trigger})")

            # Check trigger conditions
            triggered, phi_result = self._check_trigger(policy, pdf_path, user_department)

            if triggered:
                reason = self._build_reason(policy, user_department, phi_result)
                logger.info(
                    f"Policy triggered: {policy.name} | Action: {policy.action} | Reason: {reason}"
                )
                return PolicyResult(
                    triggered=True,
                    policy=policy,
                    action=policy.action,
                    reason=reason,
                    phi_scan_result=phi_result,
                )

        # No policies triggered
        logger.debug("No encryption policies triggered for document")
        return PolicyResult(
            triggered=False,
            policy=None,
            action=PolicyAction.WARN,
            reason="No encryption policies matched this document",
        )

    def _check_trigger(
        self,
        policy: EncryptionPolicy,
        pdf_path: Path,
        user_department: str | None,
    ) -> tuple[bool, Any]:
        """
        Check if a policy's trigger condition is met.

        Returns:
            Tuple of (triggered: bool, phi_scan_result: Any)
        """
        if policy.trigger == PolicyTrigger.ALWAYS:
            return True, None

        elif policy.trigger == PolicyTrigger.PHI_DETECTED:
            return self._check_phi_trigger(policy, pdf_path)

        elif policy.trigger == PolicyTrigger.DEPARTMENT:
            triggered = self._check_department_trigger(policy, user_department)
            return triggered, None

        elif policy.trigger == PolicyTrigger.MANUAL:
            # Manual triggers are handled externally
            return False, None

        elif policy.trigger == PolicyTrigger.FILE_TYPE:
            # Future: implement file type checks (size, page count, etc.)
            logger.debug(f"FILE_TYPE trigger not yet implemented for policy: {policy.name}")
            return False, None

        logger.warning(f"Unknown policy trigger: {policy.trigger}")
        return False, None

    def _check_phi_trigger(self, policy: EncryptionPolicy, pdf_path: Path) -> tuple[bool, Any]:
        """
        Check if PHI detection trigger condition is met.

        Returns:
            Tuple of (triggered: bool, phi_scan_result: Any)
        """
        try:
            # Try to import PHI scanner (may not exist yet)
            from pdfsigner.core.phi import Confidence, get_phi_scanner
        except ImportError:
            logger.warning(
                f"PHI scanner not available, skipping PHI_DETECTED policy: {policy.name}"
            )
            return False, None

        try:
            scanner = get_phi_scanner()
            result = scanner.scan_pdf(pdf_path)

            if not result.has_phi:
                logger.debug("No PHI detected in document")
                return False, result

            # Check if specific PHI types are required
            if policy.phi_types:
                found_types = set(result.by_type.keys())
                required_types = set(policy.phi_types)
                if not (found_types & required_types):
                    logger.debug(
                        f"PHI detected but not required types. "
                        f"Found: {found_types}, Required: {required_types}"
                    )
                    return False, result

            # Check confidence threshold
            try:
                min_conf = Confidence(policy.min_confidence)
            except ValueError:
                logger.warning(
                    f"Invalid confidence level '{policy.min_confidence}', defaulting to MEDIUM"
                )
                min_conf = Confidence.MEDIUM

            conf_order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]

            if conf_order.index(result.overall_confidence) >= conf_order.index(min_conf):
                logger.info(
                    f"PHI detected with sufficient confidence: "
                    f"{result.overall_confidence.value} >= {min_conf.value}"
                )
                return True, result
            else:
                logger.debug(
                    f"PHI detected but confidence too low: "
                    f"{result.overall_confidence.value} < {min_conf.value}"
                )
                return False, result

        except Exception as e:
            logger.error(f"Error scanning PDF for PHI: {e}")
            return False, None

    def _check_department_trigger(
        self, policy: EncryptionPolicy, user_department: str | None
    ) -> bool:
        """Check if department trigger condition is met."""
        if not user_department:
            logger.debug("No user department provided")
            return False

        if not policy.departments:
            logger.debug(f"Policy {policy.name} has no departments configured")
            return False

        matched = user_department in policy.departments
        if matched:
            logger.debug(
                f"Department '{user_department}' matches policy departments: {policy.departments}"
            )
        else:
            logger.debug(
                f"Department '{user_department}' not in policy departments: {policy.departments}"
            )

        return matched

    def _build_reason(
        self,
        policy: EncryptionPolicy,
        user_department: str | None,
        phi_result: Any,
    ) -> str:
        """Build human-readable reason for policy trigger."""
        if policy.trigger == PolicyTrigger.ALWAYS:
            return f"Policy '{policy.name}' requires all documents to be encrypted"

        elif policy.trigger == PolicyTrigger.PHI_DETECTED:
            if phi_result and hasattr(phi_result, "has_phi") and phi_result.has_phi:
                phi_count = phi_result.total_findings
                confidence = getattr(phi_result, "overall_confidence", "unknown")
                return f"PHI detected in document ({phi_count} findings, {confidence} confidence)"
            return f"Policy '{policy.name}' triggered by PHI detection"

        elif policy.trigger == PolicyTrigger.DEPARTMENT:
            return (
                f"User department '{user_department}' requires encryption "
                f"per policy '{policy.name}'"
            )

        return f"Policy '{policy.name}' triggered"

    def add_policy(self, policy: EncryptionPolicy) -> None:
        """
        Add a new policy to the engine.

        Policies are automatically sorted by priority.
        """
        self._policies.append(policy)
        self._policies.sort(key=lambda p: p.priority, reverse=True)
        logger.info(f"Added encryption policy: {policy.name} (priority: {policy.priority})")

    def remove_policy(self, policy_id: str) -> bool:
        """
        Remove a policy by ID.

        Args:
            policy_id: UUID of the policy to remove

        Returns:
            True if policy was found and removed, False otherwise
        """
        initial_count = len(self._policies)
        self._policies = [p for p in self._policies if p.id != policy_id]
        removed = len(self._policies) < initial_count

        if removed:
            logger.info(f"Removed encryption policy: {policy_id}")
        else:
            logger.warning(f"Policy not found for removal: {policy_id}")

        return removed

    def get_policies(self) -> list[EncryptionPolicy]:
        """Get all policies (sorted by priority)."""
        return list(self._policies)

    def _load_default_policies(self) -> list[EncryptionPolicy]:
        """
        Load default HIPAA-compliant policies.

        These policies enforce encryption for:
        1. Documents containing PHI
        2. Documents from medical departments
        """
        return [
            EncryptionPolicy(
                name="HIPAA PHI Protection",
                description=(
                    "Automatically encrypt documents containing Protected Health Information"
                ),
                trigger=PolicyTrigger.PHI_DETECTED,
                action=PolicyAction.ENCRYPT,
                min_confidence="medium",
                priority=100,
            ),
            EncryptionPolicy(
                name="Medical Records Department",
                description=(
                    "Encrypt all documents from medical records, radiology, "
                    "and laboratory departments"
                ),
                trigger=PolicyTrigger.DEPARTMENT,
                action=PolicyAction.ENCRYPT,
                departments=["medical_records", "radiology", "laboratory"],
                priority=90,
            ),
        ]


# Singleton instance
_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """
    Get the global PolicyEngine singleton.

    Returns:
        The global PolicyEngine instance with default HIPAA policies
    """
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
        logger.debug(
            f"Initialized PolicyEngine with {len(_policy_engine.get_policies())} default policies"
        )
    return _policy_engine
