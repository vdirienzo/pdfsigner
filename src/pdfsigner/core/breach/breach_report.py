"""
breach_report.py - Breach incident reporting

Generates detailed reports and summaries for breach incidents.
"""

from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.breach.breach_repository import get_breach_repository
from pdfsigner.core.breach.breach_types import BreachSeverity, BreachStatus


def generate_incident_report(incident_id: str) -> dict:
    """
    Generate detailed incident report.

    Creates a comprehensive report for a specific breach incident
    suitable for PDF generation or detailed analysis.

    Args:
        incident_id: Incident ID

    Returns:
        Dictionary with complete incident details

    Raises:
        ValueError: If incident not found
    """
    repository = get_breach_repository()
    incident = repository.get_incident(incident_id)

    if not incident:
        raise ValueError(f"Incident not found: {incident_id}")

    # Calculate time metrics
    time_to_resolve = None
    if incident.resolved_at:
        time_to_resolve = (incident.resolved_at - incident.detected_at).total_seconds() / 3600

    time_to_notify = None
    if incident.notified_at:
        time_to_notify = (incident.notified_at - incident.detected_at).total_seconds() / 3600

    report = {
        # Basic information
        "incident_id": incident.id,
        "breach_type": incident.breach_type.value,
        "severity": incident.severity.value,
        "status": incident.status.value,
        # Timeline
        "detected_at": incident.detected_at.isoformat(),
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "notified_at": incident.notified_at.isoformat() if incident.notified_at else None,
        "time_to_resolve_hours": time_to_resolve,
        "time_to_notify_hours": time_to_notify,
        # Impact
        "affected_users": incident.affected_users,
        "affected_records": incident.affected_records,
        # Source
        "source_ip": incident.source_ip,
        "user_id": incident.user_id,
        # Description
        "description": incident.description,
        # Timeline of status changes
        "status_history": incident.status_history,
        # Additional context
        "metadata": incident.metadata,
        # Report generation
        "report_generated_at": datetime.now(UTC).isoformat(),
    }

    logger.info(f"Generated incident report: {incident_id}")

    return report


def generate_summary_report(
    start_date: datetime,
    end_date: datetime,
) -> dict:
    """
    Generate summary report for time period.

    Creates aggregate statistics and trends for breach incidents
    within a specified time range.

    Args:
        start_date: Start of reporting period
        end_date: End of reporting period

    Returns:
        Dictionary with aggregate statistics
    """
    repository = get_breach_repository()

    # Get all incidents in range
    incidents = repository.list_incidents(
        start_date=start_date,
        end_date=end_date,
        limit=10000,  # High limit for statistics
    )

    # Count by severity
    by_severity = {severity.value: 0 for severity in BreachSeverity}
    for incident in incidents:
        by_severity[incident.severity.value] += 1

    # Count by status
    by_status = {status.value: 0 for status in BreachStatus}
    for incident in incidents:
        by_status[incident.status.value] += 1

    # Count by type
    from pdfsigner.core.breach.breach_types import BreachType

    by_type = {btype.value: 0 for btype in BreachType}
    for incident in incidents:
        by_type[incident.breach_type.value] += 1

    # Calculate totals
    total_affected_users = sum(inc.affected_users for inc in incidents)
    total_affected_records = sum(inc.affected_records for inc in incidents)

    # Calculate average resolution time
    resolved = [inc for inc in incidents if inc.resolved_at]
    avg_resolution_hours = None
    if resolved:
        resolution_times = [
            (inc.resolved_at - inc.detected_at).total_seconds() / 3600
            for inc in resolved
            if inc.resolved_at is not None
        ]
        avg_resolution_hours = sum(resolution_times) / len(resolution_times)

    # Most affected users/IPs
    user_counts: dict[str, int] = {}
    ip_counts: dict[str, int] = {}
    for incident in incidents:
        if incident.user_id:
            user_counts[incident.user_id] = user_counts.get(incident.user_id, 0) + 1
        if incident.source_ip:
            ip_counts[incident.source_ip] = ip_counts.get(incident.source_ip, 0) + 1

    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    report = {
        # Report metadata
        "report_type": "breach_summary",
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        # Overall statistics
        "total_incidents": len(incidents),
        "total_affected_users": total_affected_users,
        "total_affected_records": total_affected_records,
        # Breakdowns
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
        # Performance metrics
        "avg_resolution_hours": avg_resolution_hours,
        "resolved_count": len(resolved),
        "unresolved_count": len(incidents) - len(resolved),
        # Top offenders
        "top_users": [{"user_id": u, "incident_count": c} for u, c in top_users],
        "top_source_ips": [{"ip": ip, "incident_count": c} for ip, c in top_ips],
        # Recent incidents (last 10)
        "recent_incidents": [
            {
                "id": inc.id,
                "type": inc.breach_type.value,
                "severity": inc.severity.value,
                "detected_at": inc.detected_at.isoformat(),
            }
            for inc in incidents[:10]
        ],
    }

    logger.info(
        f"Generated summary report: {start_date.date()} to {end_date.date()}, "
        f"total_incidents={len(incidents)}"
    )

    return report
