"""Emergency access module for healthcare compliance (HIPAA §164.312(a)(2)(ii))."""

from pdfsigner.core.emergency.break_glass import (
    BreakGlassService,
    get_break_glass_service,
)
from pdfsigner.core.emergency.emergency_access import (
    EmergencyAccessRepository,
    EmergencyAccessRequest,
    EmergencyAccessStatus,
    get_emergency_repository,
)

__all__ = [
    "EmergencyAccessRequest",
    "EmergencyAccessStatus",
    "EmergencyAccessRepository",
    "get_emergency_repository",
    "BreakGlassService",
    "get_break_glass_service",
]
