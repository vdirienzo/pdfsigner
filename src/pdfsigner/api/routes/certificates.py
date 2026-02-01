"""
Certificate routes for API.

Provides endpoints for:
- Listing available certificates
- Getting certificate details
- Retrieving certificate chains
- Listing available tokens
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.certificates import CertificateChain, CertificateInfo
from pdfsigner.api.services.certificate_service import CertificateService
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    NSSConfigError,
    TokenAuthenticationError,
    TokenNotFoundError,
)

router = APIRouter(prefix="/api/v1/certificates", tags=["certificates"])


# --- Helper Functions ---


def get_certificate_service() -> CertificateService:
    """
    Dependency to get CertificateService instance.

    Returns:
        CertificateService instance
    """
    return CertificateService()


# --- Routes ---


@router.get(
    "/tokens",
    response_model=list[str],
    summary="List available PKCS#11 tokens",
    description="""
    List all available PKCS#11 tokens detected on the system.

    Returns token labels that can be used with other certificate endpoints.
    """,
)
async def list_tokens(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    cert_service: Annotated[CertificateService, Depends(get_certificate_service)],
) -> list[str]:
    """
    List available PKCS#11 tokens.

    Args:
        current_user: Authenticated user
        cert_service: Certificate service instance

    Returns:
        List of token labels

    Raises:
        HTTPException: 503 if NSS not configured or no PKCS#11 library found
    """
    try:
        tokens = cert_service.get_available_tokens()
        logger.info(f"User '{current_user.username}' listed {len(tokens)} tokens")
        return tokens

    except NSSConfigError as e:
        logger.error(f"NSS configuration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"NSS database not configured: {e}",
        ) from e

    except TokenNotFoundError as e:
        logger.error(f"PKCS#11 library not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"No PKCS#11 library found: {e}",
        ) from e

    finally:
        cert_service.close()


@router.get(
    "/",
    response_model=list[CertificateInfo],
    summary="List available certificates",
    description="""
    List all available X.509 certificates from NSS database or connected token.

    **Authentication Required**: Provide token PIN via query parameter to list certificates.

    **Query Parameters**:
    - `token_label`: Optional token label to connect to specific token
    - `pin`: Required PIN for token authentication

    **Note**: Returns empty list if NSS database not configured or no token connected.
    """,
)
async def list_certificates(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    cert_service: Annotated[CertificateService, Depends(get_certificate_service)],
    token_label: str | None = Query(None, description="Token label to connect to"),
    pin: str | None = Query(None, description="Token PIN for authentication"),
) -> list[CertificateInfo]:
    """
    List available certificates.

    Args:
        current_user: Authenticated user
        cert_service: Certificate service instance
        token_label: Optional token label
        pin: Optional PIN for authentication

    Returns:
        List of CertificateInfo objects

    Raises:
        HTTPException: 401 if authentication fails, 503 if service unavailable
    """
    try:
        certs = cert_service.list_certificates(token_label=token_label, pin=pin)
        logger.info(
            f"User '{current_user.username}' listed {len(certs)} certificates "
            f"(token: {token_label or 'default'})"
        )
        return certs

    except NSSConfigError as e:
        logger.error(f"NSS configuration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"NSS database not configured: {e}",
        ) from e

    except TokenNotFoundError as e:
        logger.warning(f"Token not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Token not found: {e}",
        ) from e

    except TokenAuthenticationError as e:
        logger.warning(f"Authentication failed for user '{current_user.username}': {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token authentication failed: {e}",
        ) from e

    finally:
        cert_service.close()


@router.get(
    "/{cert_id}",
    response_model=CertificateInfo,
    summary="Get certificate details",
    description="""
    Get detailed information about a specific certificate by ID.

    **Certificate ID**: SHA-256 fingerprint in hexadecimal format.

    **Query Parameters**:
    - `token_label`: Optional token label
    - `pin`: Required PIN for token authentication
    """,
)
async def get_certificate(
    cert_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    cert_service: Annotated[CertificateService, Depends(get_certificate_service)],
    token_label: str | None = Query(None, description="Token label to connect to"),
    pin: str | None = Query(None, description="Token PIN for authentication"),
) -> CertificateInfo:
    """
    Get certificate details by ID.

    Args:
        cert_id: Certificate ID (SHA-256 fingerprint hex)
        current_user: Authenticated user
        cert_service: Certificate service instance
        token_label: Optional token label
        pin: Optional PIN for authentication

    Returns:
        CertificateInfo object

    Raises:
        HTTPException: 404 if certificate not found, 401 if auth fails
    """
    try:
        cert = cert_service.get_certificate(cert_id, token_label=token_label, pin=pin)
        logger.info(f"User '{current_user.username}' retrieved certificate '{cert_id[:16]}...'")
        return cert

    except CertificateNotFoundError as e:
        logger.warning(f"Certificate not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate not found: {e}",
        ) from e

    except TokenAuthenticationError as e:
        logger.warning(f"Authentication failed for user '{current_user.username}': {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token authentication failed: {e}",
        ) from e

    except NSSConfigError as e:
        logger.error(f"NSS configuration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"NSS database not configured: {e}",
        ) from e

    finally:
        cert_service.close()


@router.get(
    "/{cert_id}/chain",
    response_model=CertificateChain,
    summary="Get certificate chain",
    description="""
    Get complete certificate chain from end-entity certificate to root CA.

    **Certificate ID**: SHA-256 fingerprint in hexadecimal format.

    **Response includes**:
    - Ordered list of certificates (leaf to root)
    - Chain completeness status (whether it reaches trusted root)
    - Validation errors/warnings

    **Query Parameters**:
    - `token_label`: Optional token label
    - `pin`: Required PIN for token authentication
    """,
)
async def get_certificate_chain(
    cert_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    cert_service: Annotated[CertificateService, Depends(get_certificate_service)],
    token_label: str | None = Query(None, description="Token label to connect to"),
    pin: str | None = Query(None, description="Token PIN for authentication"),
) -> CertificateChain:
    """
    Get certificate chain by certificate ID.

    Args:
        cert_id: Certificate ID (SHA-256 fingerprint hex)
        current_user: Authenticated user
        cert_service: Certificate service instance
        token_label: Optional token label
        pin: Optional PIN for authentication

    Returns:
        CertificateChain with certificates and validation status

    Raises:
        HTTPException: 404 if certificate not found, 401 if auth fails
    """
    try:
        chain = cert_service.get_certificate_chain(cert_id, token_label=token_label, pin=pin)
        logger.info(
            f"User '{current_user.username}' retrieved chain for certificate "
            f"'{cert_id[:16]}...' ({len(chain.certificates)} certificates)"
        )
        return chain

    except CertificateNotFoundError as e:
        logger.warning(f"Certificate not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate not found: {e}",
        ) from e

    except TokenAuthenticationError as e:
        logger.warning(f"Authentication failed for user '{current_user.username}': {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token authentication failed: {e}",
        ) from e

    except NSSConfigError as e:
        logger.error(f"NSS configuration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"NSS database not configured: {e}",
        ) from e

    finally:
        cert_service.close()


# --- Public Exports ---

__all__ = ["router"]
