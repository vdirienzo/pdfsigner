"""
Retention management routes.

Provides endpoints for:
- Listing retention policies
- Creating/updating/deleting policies
- Running retention cleanup
- Viewing cleanup history
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.retention import (
    RetentionHistoryResponse,
    RetentionPolicyCreate,
    RetentionPolicyResponse,
    RetentionPolicyUpdate,
    RetentionResultResponse,
    RetentionRunRequest,
)
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.retention import RetentionPolicy, get_retention_manager

router = APIRouter(prefix="/api/v1/retention", tags=["retention"])


# --- Routes ---


@router.get(
    "/policies",
    response_model=list[RetentionPolicyResponse],
    summary="List retention policies",
    description="""
    Get all retention policies.

    **Permissions:** Requires authentication (user or API key).

    Returns all configured retention policies including HIPAA-required defaults.
    """,
)
async def list_retention_policies(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    enabled_only: bool = False,
) -> list[RetentionPolicyResponse]:
    """
    List all retention policies.

    Args:
        current_user: Authenticated user
        enabled_only: Only return enabled policies

    Returns:
        List of RetentionPolicyResponse objects
    """
    manager = get_retention_manager()
    policies = manager.list_policies(enabled_only=enabled_only)

    logger.info(f"User {current_user.username} retrieved {len(policies)} retention policies")

    return [RetentionPolicyResponse.from_policy(p) for p in policies]


@router.get(
    "/policies/{policy_id}",
    response_model=RetentionPolicyResponse,
    summary="Get retention policy",
    description="""
    Get details for a specific retention policy.

    **Permissions:** Requires authentication (user or API key).

    Returns 404 if policy not found.
    """,
)
async def get_retention_policy(
    policy_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> RetentionPolicyResponse:
    """
    Get specific retention policy.

    Args:
        policy_id: Policy ID
        current_user: Authenticated user

    Returns:
        RetentionPolicyResponse

    Raises:
        HTTPException: 404 if policy not found
    """
    manager = get_retention_manager()
    policy = manager.get_policy(policy_id)

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Retention policy {policy_id} not found",
        )

    return RetentionPolicyResponse.from_policy(policy)


@router.post(
    "/policies",
    response_model=RetentionPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create retention policy",
    description="""
    Create a new retention policy.

    **Permissions:** Requires admin authorization.

    Creates a custom retention policy for data cleanup automation.
    """,
)
async def create_retention_policy(
    policy_data: RetentionPolicyCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> RetentionPolicyResponse:
    """
    Create new retention policy.

    Args:
        policy_data: Policy creation data
        current_user: Authenticated user

    Returns:
        Created RetentionPolicyResponse
    """
    manager = get_retention_manager()

    # Create policy from request data
    policy = RetentionPolicy(
        name=policy_data.name,
        description=policy_data.description,
        target=policy_data.target,
        retention_days=policy_data.retention_days,
        action=policy_data.action,
        enabled=policy_data.enabled,
        hipaa_reference=policy_data.hipaa_reference,
    )

    created = manager.add_policy(policy)
    logger.info(f"User {current_user.username} created retention policy: {created.name}")

    return RetentionPolicyResponse.from_policy(created)


@router.patch(
    "/policies/{policy_id}",
    response_model=RetentionPolicyResponse,
    summary="Update retention policy",
    description="""
    Update an existing retention policy.

    **Permissions:** Requires admin authorization.

    **Restrictions:**
    - Cannot modify HIPAA-required policies in ways that violate compliance
    - Target cannot be changed after creation
    """,
)
async def update_retention_policy(
    policy_id: str,
    policy_data: RetentionPolicyUpdate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> RetentionPolicyResponse:
    """
    Update existing retention policy.

    Args:
        policy_id: Policy ID to update
        policy_data: Updated policy data
        current_user: Authenticated user

    Returns:
        Updated RetentionPolicyResponse

    Raises:
        HTTPException: 404 if policy not found
    """
    manager = get_retention_manager()
    policy = manager.get_policy(policy_id)

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Retention policy {policy_id} not found",
        )

    # Update fields if provided
    if policy_data.name is not None:
        policy.name = policy_data.name
    if policy_data.description is not None:
        policy.description = policy_data.description
    if policy_data.retention_days is not None:
        policy.retention_days = policy_data.retention_days
    if policy_data.action is not None:
        policy.action = policy_data.action
    if policy_data.enabled is not None:
        policy.enabled = policy_data.enabled

    updated = manager.update_policy(policy)
    logger.info(f"User {current_user.username} updated retention policy: {updated.name}")

    return RetentionPolicyResponse.from_policy(updated)


@router.delete(
    "/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete retention policy",
    description="""
    Delete a retention policy.

    **Permissions:** Requires admin authorization.

    **Restrictions:**
    - Cannot delete HIPAA-required policies
    - Policy must not have hipaa_reference set
    """,
)
async def delete_retention_policy(
    policy_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> None:
    """
    Delete retention policy.

    Args:
        policy_id: Policy ID to delete
        current_user: Authenticated user

    Raises:
        HTTPException: 404 if policy not found
        HTTPException: 400 if policy is HIPAA-required
    """
    manager = get_retention_manager()
    policy = manager.get_policy(policy_id)

    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Retention policy {policy_id} not found",
        )

    # Check if HIPAA-required
    if policy.hipaa_reference:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete HIPAA-required policy: {policy.name}",
        )

    success = manager.delete_policy(policy_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete policy {policy_id}",
        )

    logger.info(f"User {current_user.username} deleted retention policy: {policy.name}")


@router.post(
    "/run",
    response_model=list[RetentionResultResponse],
    summary="Run retention cleanup",
    description="""
    Execute retention cleanup for one or all policies.

    **Permissions:** Requires admin authorization.

    Runs cleanup based on retention policies and returns detailed results.
    If policy_id is not provided, runs cleanup for all enabled policies.
    """,
)
async def run_retention_cleanup(
    request: RetentionRunRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> list[RetentionResultResponse]:
    """
    Run retention cleanup.

    Args:
        request: Cleanup request with optional policy_id
        current_user: Authenticated user

    Returns:
        List of RetentionResultResponse objects

    Raises:
        HTTPException: 404 if specific policy not found
    """
    manager = get_retention_manager()

    # Validate policy exists if specified
    if request.policy_id:
        policy = manager.get_policy(request.policy_id)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Retention policy {request.policy_id} not found",
            )

    # Run cleanup
    results = manager.run_cleanup(policy_id=request.policy_id)

    logger.info(
        f"User {current_user.username} executed retention cleanup: "
        f"{len(results)} policies processed"
    )

    return [
        RetentionResultResponse(
            policy_id=r.policy_id,
            policy_name=r.policy_name,
            target=r.target,
            action=r.action,
            items_processed=r.items_processed,
            items_deleted=r.items_deleted,
            items_archived=r.items_archived,
            items_failed=r.items_failed,
            started_at=r.started_at,
            completed_at=r.completed_at,
            duration_seconds=r.duration_seconds,
            errors=r.errors,
        )
        for r in results
    ]


@router.get(
    "/history",
    response_model=list[RetentionHistoryResponse],
    summary="Get retention history",
    description="""
    Get historical cleanup records.

    **Permissions:** Requires authentication (user or API key).

    Returns history of retention cleanup operations with optional filtering by policy.
    """,
)
async def get_retention_history(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    policy_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
) -> list[RetentionHistoryResponse]:
    """
    Get retention cleanup history.

    Args:
        current_user: Authenticated user
        policy_id: Optional policy ID filter
        limit: Maximum number of records to return

    Returns:
        List of RetentionHistoryResponse objects
    """
    manager = get_retention_manager()
    history = manager.get_history(policy_id=policy_id, limit=limit)

    logger.info(f"User {current_user.username} retrieved {len(history)} retention history records")

    return [RetentionHistoryResponse(**record) for record in history]


# --- Public Exports ---

__all__ = ["router"]
