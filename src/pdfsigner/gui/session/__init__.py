"""
GUI session management module.

Provides activity monitoring and automatic logoff functionality for
healthcare compliance (HIPAA §164.312(a)(2)(iii)).
"""

from pdfsigner.gui.session.activity_monitor import ActivityMonitor

__all__ = ["ActivityMonitor"]
