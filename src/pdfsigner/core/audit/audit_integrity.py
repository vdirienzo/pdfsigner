"""
audit_integrity.py - Audit log integrity protection

Implements HMAC signing and chain hashing for tamper detection.
HIPAA compliance: §164.312(b) - Audit controls
"""

import hashlib
import hmac
import json
from datetime import datetime
from pathlib import Path

from pdfsigner.core.audit.audit_event import AuditEvent


class AuditIntegrityManager:
    """
    Manages audit log integrity using HMAC and chain hashing.

    Each record includes:
    - HMAC signature (proves authenticity)
    - Hash of previous record (proves sequence integrity)
    - Hash of current record (for next record's chain)
    """

    def __init__(self, secret_key: bytes | None = None):
        """
        Initialize integrity manager.

        Args:
            secret_key: HMAC secret key. If None, generates from machine ID.
        """
        self._secret_key = secret_key or self._get_default_secret()
        self._last_hash: str | None = None

    def sign_event(self, event: AuditEvent, previous_hash: str | None = None) -> AuditEvent:
        """
        Sign an audit event with HMAC and chain hash.

        Args:
            event: Event to sign
            previous_hash: Hash of previous event (for chain)

        Returns:
            Event with integrity fields populated
        """
        # Set previous hash (chain)
        event.previous_hash = previous_hash or self._last_hash

        # Calculate record hash (excludes signature fields)
        record_hash = self._calculate_record_hash(event)
        event.record_hash = record_hash

        # Calculate HMAC signature
        event.hmac_signature = self._calculate_hmac(record_hash)

        # Update last hash for chain
        self._last_hash = record_hash

        return event

    def verify_event(self, event: AuditEvent) -> tuple[bool, str]:
        """
        Verify integrity of a single audit event.

        Args:
            event: Event to verify

        Returns:
            Tuple of (is_valid, reason)
        """
        if not event.record_hash:
            return False, "Missing record hash"

        if not event.hmac_signature:
            return False, "Missing HMAC signature"

        # Recalculate hash
        expected_hash = self._calculate_record_hash(event)
        if event.record_hash != expected_hash:
            return False, "Record hash mismatch - content may have been modified"

        # Verify HMAC
        expected_hmac = self._calculate_hmac(event.record_hash)
        if not hmac.compare_digest(event.hmac_signature, expected_hmac):
            return False, "HMAC signature invalid - record may have been tampered"

        return True, "Valid"

    def verify_chain(self, events: list[AuditEvent]) -> tuple[bool, list[dict]]:
        """
        Verify integrity of a chain of audit events.

        Args:
            events: List of events in chronological order

        Returns:
            Tuple of (all_valid, list of issues)
        """
        issues = []
        previous_hash = None

        for i, event in enumerate(events):
            # Verify individual event
            is_valid, reason = self.verify_event(event)
            if not is_valid:
                issues.append(
                    {
                        "index": i,
                        "event_id": event.event_id,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "issue": reason,
                        "severity": "critical",
                    }
                )

            # Verify chain linkage
            if previous_hash is not None and event.previous_hash != previous_hash:
                issues.append(
                    {
                        "index": i,
                        "event_id": event.event_id,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                        "issue": "Chain broken - previous_hash mismatch",
                        "severity": "critical",
                        "expected_previous": previous_hash,
                        "actual_previous": event.previous_hash,
                    }
                )

            previous_hash = event.record_hash

        return len(issues) == 0, issues

    def verify_audit_file(self, file_path: Path) -> tuple[bool, dict]:
        """
        Verify integrity of an entire audit log file.

        Args:
            file_path: Path to .jsonl audit file

        Returns:
            Tuple of (is_valid, detailed_report)
        """
        report = {
            "file": str(file_path),
            "verified_at": datetime.now().isoformat(),
            "total_records": 0,
            "valid_records": 0,
            "invalid_records": 0,
            "chain_intact": True,
            "issues": [],
        }

        try:
            events = []
            with open(file_path) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        event = AuditEvent.from_dict(data)
                        events.append(event)
                        report["total_records"] += 1
                    except Exception as e:
                        report["issues"].append(
                            {
                                "line": line_num,
                                "issue": f"Parse error: {e}",
                                "severity": "warning",
                            }
                        )

            # Verify chain
            chain_valid, chain_issues = self.verify_chain(events)
            report["chain_intact"] = chain_valid
            report["issues"].extend(chain_issues)

            # Count valid/invalid
            report["valid_records"] = report["total_records"] - len(
                [i for i in report["issues"] if i.get("severity") == "critical"]
            )
            report["invalid_records"] = report["total_records"] - report["valid_records"]

        except FileNotFoundError:
            report["issues"].append(
                {
                    "issue": "File not found",
                    "severity": "critical",
                }
            )
        except Exception as e:
            report["issues"].append(
                {
                    "issue": f"Verification error: {e}",
                    "severity": "critical",
                }
            )

        # Check for any critical issues (including file not found)
        has_critical_issues = any(i.get("severity") == "critical" for i in report["issues"])
        is_valid = (
            report["invalid_records"] == 0 and report["chain_intact"] and not has_critical_issues
        )
        return is_valid, report

    def _calculate_record_hash(self, event: AuditEvent) -> str:
        """Calculate SHA-256 hash of event content (excluding signature fields)."""
        # Create dict without integrity fields
        data = event.to_dict()
        data.pop("record_hash", None)
        data.pop("hmac_signature", None)
        # Keep previous_hash as it's part of the chain

        # Deterministic JSON encoding
        content = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    def _calculate_hmac(self, data: str) -> str:
        """Calculate HMAC-SHA256 signature."""
        return hmac.new(self._secret_key, data.encode(), hashlib.sha256).hexdigest()

    def _get_default_secret(self) -> bytes:
        """Generate default secret from machine-specific data."""
        import socket
        import uuid

        # Combine machine-specific identifiers
        machine_id = f"{socket.gethostname()}-{uuid.getnode()}"

        # Derive key using SHA-256
        return hashlib.sha256(machine_id.encode()).digest()

    def set_last_hash(self, hash_value: str | None) -> None:
        """Set the last hash for chain continuation."""
        self._last_hash = hash_value

    def get_last_hash(self) -> str | None:
        """Get the last hash in the chain."""
        return self._last_hash


# Singleton instance
_integrity_manager: AuditIntegrityManager | None = None


def get_audit_integrity_manager() -> AuditIntegrityManager:
    """Get singleton integrity manager."""
    global _integrity_manager
    if _integrity_manager is None:
        _integrity_manager = AuditIntegrityManager()
    return _integrity_manager


def verify_audit_integrity(file_path: Path) -> tuple[bool, dict]:
    """
    Convenience function to verify audit file integrity.

    Args:
        file_path: Path to audit log file

    Returns:
        Tuple of (is_valid, report)
    """
    manager = get_audit_integrity_manager()
    return manager.verify_audit_file(file_path)
