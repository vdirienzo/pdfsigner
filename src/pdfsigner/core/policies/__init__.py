"""
Encryption policy enforcement module for PDFSigner.

Provides mandatory encryption policies based on document content,
user departments, and configurable triggers. Supports HIPAA compliance
by enforcing encryption when PHI is detected.

Usage:
    from pdfsigner.core.policies import (
        PolicyEngine,
        EncryptionPolicy,
        PolicyTrigger,
        PolicyResult,
        get_policy_engine,
    )

    # Evaluate policies against a document
    engine = get_policy_engine()
    result = engine.evaluate(Path("document.pdf"), user_department="medical_records")

    if result.triggered:
        # Apply encryption according to result.policy
        print(f"Policy triggered: {result.policy.name}")
        print(f"Action required: {result.action}")
"""

from pdfsigner.core.policies.encryption_policy import (
    PolicyEngine,
    get_policy_engine,
)
from pdfsigner.core.policies.policy_types import (
    EncryptionPolicy,
    PolicyAction,
    PolicyResult,
    PolicyTrigger,
)

__all__ = [
    "EncryptionPolicy",
    "PolicyTrigger",
    "PolicyAction",
    "PolicyResult",
    "PolicyEngine",
    "get_policy_engine",
]
