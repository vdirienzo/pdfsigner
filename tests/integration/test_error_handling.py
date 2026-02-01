"""
Tests for global exception handler to prevent stack trace exposure.

Verifies that:
- Unhandled exceptions return generic error messages (no stack traces)
- Errors are logged internally for debugging
- DEBUG mode shows exception type, production mode does not
- All unhandled exceptions return 500 status
"""

from unittest.mock import patch

import pytest
from fastapi import APIRouter

from pdfsigner.api.main import app

# Mark all tests in this module as anyio (use anyio for async support)
pytestmark = pytest.mark.anyio


# Create test router for exception testing
test_router = APIRouter(prefix="/test", tags=["test"])


@test_router.get("/raise-exception")
async def raise_exception_endpoint():
    """Test endpoint that raises an unhandled exception."""
    raise ValueError("This is a test exception with sensitive data: API_KEY=secret123")


@test_router.get("/runtime-error")
async def raise_runtime_error():
    """Test endpoint that raises RuntimeError."""
    raise RuntimeError("Runtime error test")


@test_router.get("/key-error")
async def raise_key_error():
    """Test endpoint that raises KeyError."""
    raise KeyError("missing_key")


@pytest.fixture
def test_routes():
    """
    Add test routes to the app for testing.

    Uses FastAPI's include_router to add routes, and removes them after test.
    """
    # Add test router
    app.include_router(test_router)

    yield

    # Cleanup: Remove test router by filtering out routes with /test prefix
    # This is a workaround since FastAPI doesn't have a remove_router method
    original_routes = app.router.routes
    app.router.routes = [
        route
        for route in original_routes
        if not hasattr(route, "path") or not route.path.startswith("/test")
    ]


async def test_exception_handler_prevents_stack_trace_exposure(client, test_routes):
    """
    Test that unhandled exceptions do not expose stack traces.

    Ensures that implementation details and sensitive information
    are not leaked to the client.
    """
    response = await client.get("/test/raise-exception")

    assert response.status_code == 500

    data = response.json()

    # Should not contain stack trace
    assert "Traceback" not in str(data)
    assert "traceback" not in str(data)

    # Should not contain file paths
    assert "/home/" not in str(data)
    assert ".py" not in str(data)

    # Should not contain sensitive data from exception message
    assert "API_KEY" not in str(data)
    assert "secret123" not in str(data)

    # Should contain generic error message
    assert "detail" in data
    assert "error" in data["detail"].lower()


async def test_exception_handler_production_mode(client, test_routes, api_settings):
    """
    Test exception handler in production mode (non-DEBUG).

    Should return completely generic error without any implementation details.
    """
    # Ensure we're in non-DEBUG mode
    original_log_level = api_settings.log_level
    api_settings.log_level = "INFO"

    try:
        response = await client.get("/test/raise-exception")

        assert response.status_code == 500
        data = response.json()

        # Production mode: completely generic message
        assert data["detail"] == "Internal server error"

        # Should not contain exception type
        assert "ValueError" not in str(data)
        assert "Exception" not in data["detail"]

    finally:
        # Restore original setting
        api_settings.log_level = original_log_level


async def test_exception_handler_debug_mode(client, test_routes, api_settings):
    """
    Test exception handler in DEBUG mode.

    Should include exception type for easier troubleshooting,
    but still no stack traces or sensitive data.
    """
    # Set DEBUG mode
    original_log_level = api_settings.log_level
    api_settings.log_level = "DEBUG"

    try:
        response = await client.get("/test/raise-exception")

        assert response.status_code == 500
        data = response.json()

        # DEBUG mode: includes exception type
        assert "ValueError" in data["detail"]
        assert "Internal server error" in data["detail"]

        # Still should not contain sensitive data or stack traces
        assert "API_KEY" not in str(data)
        assert "secret123" not in str(data)
        assert "Traceback" not in str(data)

    finally:
        # Restore original setting
        api_settings.log_level = original_log_level


async def test_exception_handler_logs_full_error(client, test_routes):
    """
    Test that exceptions are logged internally for debugging.

    Even though we don't expose details to the client,
    we should log the full exception internally.
    """
    with patch("pdfsigner.api.main.logger") as mock_logger:
        response = await client.get("/test/raise-exception")

        assert response.status_code == 500

        # Verify exception was logged
        mock_logger.exception.assert_called_once()

        # Verify log message contains exception details
        log_call_args = mock_logger.exception.call_args[0][0]
        assert "ValueError" in log_call_args
        assert "/test/raise-exception" in log_call_args
        assert "Unhandled exception" in log_call_args


async def test_exception_handler_includes_error_id_field(client, test_routes):
    """
    Test that response includes error_id field for future tracking.

    Currently set to None, but the structure is in place for
    adding request ID tracking in the future.
    """
    response = await client.get("/test/raise-exception")

    assert response.status_code == 500
    data = response.json()

    # Should have error_id field (even if None for now)
    assert "error_id" in data


async def test_exception_handler_different_exception_types(client, test_routes, api_settings):
    """
    Test exception handler with different exception types.

    Ensures consistent handling regardless of exception type.
    """
    # Test RuntimeError
    response = await client.get("/test/runtime-error")
    assert response.status_code == 500
    data = response.json()
    assert "detail" in data
    assert "Runtime error test" not in str(data)  # Sensitive message hidden

    # Test KeyError
    response = await client.get("/test/key-error")
    assert response.status_code == 500
    data = response.json()
    assert "detail" in data
    assert "missing_key" not in str(data)  # Sensitive key name hidden


async def test_exception_handler_http_method_in_log(client, test_routes):
    """
    Test that exception handler logs the HTTP method.

    Helps with debugging by knowing which method triggered the error.
    """
    with patch("pdfsigner.api.main.logger") as mock_logger:
        # Test GET request
        response = await client.get("/test/raise-exception")
        assert response.status_code == 500

        log_call_args = mock_logger.exception.call_args[0][0]
        assert "GET" in log_call_args
        assert "/test/raise-exception" in log_call_args


async def test_health_endpoint_still_works(client):
    """
    Test that health endpoint still works normally.

    Exception handler should not interfere with successful requests.
    """
    response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
