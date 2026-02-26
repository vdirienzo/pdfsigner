"""
Backup and recovery routes.

Provides endpoints for:
- Creating backups
- Listing available backups
- Restoring from backups
- Deleting backups

All endpoints require authentication and admin privileges.
"""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.backup import (
    BackupCreateRequest,
    BackupDeleteResponse,
    BackupListResponse,
    BackupResponse,
    BackupRestoreRequest,
    BackupRestoreResponse,
)
from pdfsigner.core.backup import get_backup_manager
from pdfsigner.core.rbac import Permission, check_permission

router = APIRouter(prefix="/api/v1/backup", tags=["backup"])


# --- Routes ---


@router.post(
    "/create",
    response_model=BackupResponse,
    summary="Create backup",
    description="""
    Create a new backup of PDFSigner data.

    **Backup Types:**
    - `full`: All data (config, audit logs, databases)
    - `config`: Configuration files only
    - `audit`: Audit logs only
    - `database`: SQLite databases only

    **Permissions:** Admin only

    **HIPAA Compliance:** §164.308(a)(7) - Contingency plan (backup)
    """,
)
async def create_backup(
    request: BackupCreateRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BackupResponse:
    """
    Create a new backup.

    Args:
        request: Backup creation parameters
        current_user: Authenticated admin user

    Returns:
        BackupResponse with backup metadata

    Raises:
        HTTPException: If backup creation fails
    """
    try:
        manager = get_backup_manager()

        # Validate password if encryption requested
        if request.encrypt and not request.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password required for encrypted backup",
            )

        # Create backup
        metadata = manager.create_backup(
            backup_type=request.backup_type,
            encrypt=request.encrypt,
            password=request.password,
        )

        # Check if backup succeeded
        if metadata.status.value == "failed":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Backup failed: {metadata.error}",
            )

        logger.info(f"Backup created by {current_user.username}: {metadata.backup_id}")

        return BackupResponse.from_metadata(metadata)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Backup creation failed",
        ) from e


@router.get(
    "/list",
    response_model=BackupListResponse,
    summary="List backups",
    description="""
    List all available backups.

    Returns backups sorted by creation date (newest first).

    **Permissions:** Admin only

    **Note:** Encrypted backups show limited metadata until decrypted.
    """,
)
async def list_backups(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BackupListResponse:
    """
    List all available backups.

    Args:
        current_user: Authenticated admin user

    Returns:
        BackupListResponse with list of backups
    """
    try:
        manager = get_backup_manager()
        backups = manager.list_backups()

        logger.info(f"User {current_user.username} listed {len(backups)} backups")

        return BackupListResponse(
            backups=[BackupResponse.from_metadata(b) for b in backups],
            total=len(backups),
        )

    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list backups",
        ) from e


@router.post(
    "/restore",
    response_model=BackupRestoreResponse,
    summary="Restore backup",
    description="""
    Restore data from a backup.

    **Warning:** This will overwrite existing data. Use with caution.

    You can selectively restore:
    - Configuration files
    - Audit logs
    - Databases

    **Permissions:** Admin only

    **HIPAA Compliance:** §164.308(a)(7) - Contingency plan (recovery)
    """,
)
async def restore_backup(
    request: BackupRestoreRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BackupRestoreResponse:
    """
    Restore from a backup.

    Args:
        request: Restore parameters
        current_user: Authenticated admin user

    Returns:
        BackupRestoreResponse with status

    Raises:
        HTTPException: If restore fails or backup not found
    """
    try:
        manager = get_backup_manager()

        # Find backup by ID
        backups = manager.list_backups()
        backup_metadata = next((b for b in backups if b.backup_id == request.backup_id), None)

        if not backup_metadata:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Backup not found: {request.backup_id}",
            )

        # Validate password for encrypted backups
        if backup_metadata.encrypted and not request.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password required for encrypted backup",
            )

        # Perform restore
        backup_path = Path(backup_metadata.backup_path)
        success = manager.restore_backup(
            backup_path=backup_path,
            password=request.password,
            restore_config=request.restore_config,
            restore_audit=request.restore_audit,
            restore_databases=request.restore_databases,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Restore operation failed",
            )

        logger.warning(
            f"Backup restored by {current_user.username}: {request.backup_id} "
            f"(config={request.restore_config}, audit={request.restore_audit}, "
            f"db={request.restore_databases})"
        )

        return BackupRestoreResponse(
            success=True,
            message="Backup restored successfully",
            backup_id=request.backup_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore backup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Restore failed",
        ) from e


@router.delete(
    "/{backup_id}",
    response_model=BackupDeleteResponse,
    summary="Delete backup",
    description="""
    Delete a backup file.

    **Warning:** This operation cannot be undone.

    **Permissions:** Admin only
    """,
)
async def delete_backup(
    backup_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BackupDeleteResponse:
    """
    Delete a backup.

    Args:
        backup_id: ID of backup to delete
        current_user: Authenticated admin user

    Returns:
        BackupDeleteResponse with status

    Raises:
        HTTPException: If deletion fails or backup not found
    """
    try:
        manager = get_backup_manager()

        # Delete backup
        success = manager.delete_backup(backup_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Backup not found: {backup_id}",
            )

        logger.warning(f"Backup deleted by {current_user.username}: {backup_id}")

        return BackupDeleteResponse(
            success=True,
            message="Backup deleted successfully",
            backup_id=backup_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete backup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Delete failed",
        ) from e
