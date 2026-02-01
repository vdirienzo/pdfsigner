"""
json_formatter.py - JSON Lines formatter

Author: Homero Thompson del Lago del Terror

Implements JSON Lines format for SIEM systems and log aggregators.
Each event is a single line of JSON.
"""

import json

from pdfsigner.core.audit.audit_event import AuditEvent


class JSONFormatter:
    """
    Format audit events as JSON Lines.

    JSON Lines format (one JSON object per line) is widely supported
    by modern SIEM systems, log aggregators (Elasticsearch, Splunk),
    and cloud services (AWS CloudWatch, Azure Monitor).
    """

    @classmethod
    def format(cls, event: AuditEvent) -> str:
        """
        Format audit event as JSON string.

        Args:
            event: AuditEvent to format

        Returns:
            JSON string (single line, no trailing newline)
        """
        # Start with event's to_dict() method
        data = event.to_dict()

        # Add SIEM-friendly fields
        data["@timestamp"] = event.timestamp.isoformat()  # Elasticsearch/Logstash
        data["severity"] = cls._get_severity(event)
        data["severity_label"] = cls._get_severity_label(event)

        # Convert None values to empty strings for compatibility
        for key, value in data.items():
            if value is None:
                data[key] = ""

        # Serialize to JSON (compact, no newlines)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def _get_severity(cls, event: AuditEvent) -> int:
        """
        Get numeric severity level.

        Returns:
            Severity level (0-10)
        """
        if event.status == "SUCCESS":
            return 3  # INFO
        elif event.status == "FAILURE":
            return 5  # WARNING
        else:  # ERROR
            return 7  # ERROR

    @classmethod
    def _get_severity_label(cls, event: AuditEvent) -> str:
        """
        Get human-readable severity label.

        Returns:
            Severity label (INFO, WARNING, ERROR)
        """
        if event.status == "SUCCESS":
            return "INFO"
        elif event.status == "FAILURE":
            return "WARNING"
        else:
            return "ERROR"
