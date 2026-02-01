"""
User management routes.

Provides endpoints for:
- List users (admin only)
- Get user by ID
- Get current user info
- Update user (admin only)
- Deactivate user (admin only)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.users import UserListResponse, UserResponse, UserUpdate
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users import UserRole, UserStatus, get_user_repository

router = APIRouter(prefix="/api/v1/users", tags=["users"])


# --- Helper Functions ---


def _user_to_response(user: User) -> UserResponse:
    """
    Convert User model to UserResponse schema.

    Args:
        user: User domain model

    Returns:
        UserResponse schema for API response
    """
    return UserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        email=user.email,
        role=user.role.value,
        status=user.status.value,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


# --- Routes ---


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get information about the currently authenticated user.",
)
async def get_current_user_info(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> UserResponse:
    """
    Get current authenticated user information.

    Args:
        current_user: Authenticated user from JWT token or API key

    Returns:
        Current user information
    """
    return _user_to_response(current_user)


@router.get(
    "/",
    response_model=UserListResponse,
    summary="List users",
    description="""
    List all users with optional filters (admin only).

    **Requires:** Admin role

    **Filters:**
    - status: active, inactive, locked, pending
    - role: viewer, signer, admin, auditor, emergency
    - limit: max results (default 100)
    - offset: pagination offset (default 0)
    """,
)
async def list_users(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
    status: str | None = Query(None, description="Filter by status"),
    role: str | None = Query(None, description="Filter by role"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> UserListResponse:
    """
    List users with optional filters (admin only).

    Args:
        current_user: Authenticated admin user
        _perm: Permission check dependency (admin required)
        status: Optional status filter
        role: Optional role filter
        limit: Maximum number of results
        offset: Pagination offset

    Returns:
        List of users and total count

    Raises:
        HTTPException: 400 if invalid status or role value
    """
    # Parse filters
    status_filter = None
    if status:
        try:
            status_filter = UserStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status}. Must be: active, inactive, locked, pending",
            )

    role_filter = None
    if role:
        try:
            role_filter = UserRole(role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {role}. Must be: viewer, signer, admin, auditor, emergency",
            )

    # Query users
    user_repo = get_user_repository()
    users = user_repo.list_users(
        status=status_filter,
        role=role_filter,
        limit=limit,
        offset=offset,
    )

    # Count total (for pagination)
    total = user_repo.count_users(status=status_filter)

    logger.debug(
        f"Listed {len(users)} users (total={total}, filters: status={status}, role={role})"
    )

    return UserListResponse(
        users=[_user_to_response(u) for u in users],
        total=total,
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description="""
    Get user information by ID.

    **Permissions:**
    - Admins can view any user
    - Users can only view their own profile
    """,
)
async def get_user_by_id(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> UserResponse:
    """
    Get user by ID.

    Args:
        user_id: User ID to retrieve
        current_user: Authenticated user

    Returns:
        User information

    Raises:
        HTTPException: 403 if user tries to view another user's profile
        HTTPException: 404 if user not found
    """
    # Check permissions: admin can view anyone, users can only view themselves
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile",
        )

    # Fetch user
    user_repo = get_user_repository()
    user = user_repo.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_id}",
        )

    return _user_to_response(user)


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user",
    description="""
    Update user information (admin only).

    **Requires:** Admin role

    **Updatable fields:**
    - display_name
    - email
    - role
    """,
)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> UserResponse:
    """
    Update user information (admin only).

    Args:
        user_id: User ID to update
        user_update: Fields to update
        current_user: Authenticated admin user
        _perm: Permission check dependency (admin required)

    Returns:
        Updated user information

    Raises:
        HTTPException: 404 if user not found
        HTTPException: 400 if invalid role value
    """
    # Fetch existing user
    user_repo = get_user_repository()
    user = user_repo.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_id}",
        )

    # Apply updates
    if user_update.display_name is not None:
        user.display_name = user_update.display_name

    if user_update.email is not None:
        user.email = user_update.email

    if user_update.role is not None:
        try:
            user.role = UserRole(user_update.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {user_update.role}. "
                "Must be: viewer, signer, admin, auditor, emergency",
            )

    # Save changes
    updated_user = user_repo.update_user(user)

    logger.info(
        f"User updated: {updated_user.username} (id={updated_user.id}) by {current_user.username}"
    )

    return _user_to_response(updated_user)


@router.delete(
    "/{user_id}",
    response_model=dict,
    summary="Deactivate user",
    description="""
    Deactivate user account (soft delete, admin only).

    **Requires:** Admin role

    User account will be set to 'inactive' status but data is retained.
    """,
)
async def deactivate_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> dict:
    """
    Deactivate user account (admin only).

    Args:
        user_id: User ID to deactivate
        current_user: Authenticated admin user
        _perm: Permission check dependency (admin required)

    Returns:
        Success message with deactivated user ID

    Raises:
        HTTPException: 404 if user not found
        HTTPException: 400 if trying to deactivate self
    """
    # Prevent self-deactivation
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account",
        )

    # Verify user exists
    user_repo = get_user_repository()
    user = user_repo.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_id}",
        )

    # Deactivate
    success = user_repo.deactivate_user(user_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user",
        )

    logger.info(f"User deactivated: {user.username} (id={user_id}) by {current_user.username}")

    return {
        "message": f"User '{user.username}' deactivated successfully",
        "user_id": user_id,
    }


# --- Public Exports ---

__all__ = ["router"]
