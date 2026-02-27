"""
Validation service for API endpoints.

Provides business logic for PDF signature validation,
bridging core PDFValidator with API schemas.
"""

from pathlib import Path

from loguru import logger

from pdfsigner.api.schemas.validate import (
    BatchValidateResponse,
    ValidateResponse,
)
from pdfsigner.api.schemas.validate import (
    LTVInfo as APILTVInfo,
)
from pdfsigner.api.schemas.validate import (
    SignatureInfo as APISignatureInfo,
)
from pdfsigner.core.validator.pdf_validator import (
    LTVInfo as CoreLTVInfo,
)
from pdfsigner.core.validator.pdf_validator import (
    PDFValidator,
    SignatureStatus,
    ValidationResult,
)
from pdfsigner.core.validator.pdf_validator import (
    SignatureInfo as CoreSignatureInfo,
)


class ValidationService:
    """
    Service for PDF signature validation.

    Converts core validation results to API response schemas.
    """

    def __init__(self) -> None:
        """Initialize validation service with PDFValidator."""
        self.validator = PDFValidator()

    def validate_single(self, pdf_path: Path) -> ValidateResponse:
        """
        Validate a single PDF file.

        Args:
            pdf_path: Path to PDF file to validate

        Returns:
            ValidateResponse with validation results

        Raises:
            ValueError: If PDF file doesn't exist or is invalid
        """
        if not pdf_path.exists():
            raise ValueError(f"PDF file not found: {pdf_path}")

        logger.info(f"Validating PDF: {pdf_path.name}")

        # Validate using core validator
        result = self.validator.validate(pdf_path)

        # Convert to API response
        return self._convert_validation_result(result)

    def validate_batch(self, pdf_paths: list[Path]) -> BatchValidateResponse:
        """
        Validate multiple PDF files.

        Args:
            pdf_paths: List of PDF file paths to validate

        Returns:
            BatchValidateResponse with aggregated results
        """
        logger.info(f"Batch validating {len(pdf_paths)} PDFs")

        results = []
        valid_count = 0

        for pdf_path in pdf_paths:
            try:
                response = self.validate_single(pdf_path)
                results.append(response)

                if response.is_valid:
                    valid_count += 1

            except Exception as e:
                logger.error(f"Error validating {pdf_path.name}: {e}")
                # Add error result
                results.append(
                    ValidateResponse(
                        filename=pdf_path.name,
                        is_signed=False,
                        is_valid=False,
                        signature_count=0,
                        errors=[f"Validation failed: {str(e)}"],
                    )
                )

        return BatchValidateResponse(
            total=len(pdf_paths),
            valid=valid_count,
            invalid=len(pdf_paths) - valid_count,
            results=results,
        )

    def _convert_validation_result(self, result: ValidationResult) -> ValidateResponse:
        """
        Convert core ValidationResult to API ValidateResponse.

        Args:
            result: Core validation result

        Returns:
            API validate response
        """
        errors = []
        if result.error:
            errors.append(result.error)

        # Convert signatures
        api_signatures = [self._convert_signature_info(sig) for sig in result.signatures]

        # Get LTV info from first signature (if available)
        ltv_info = None
        if result.signatures and result.signatures[0].ltv_info:
            ltv_info = self._convert_ltv_info(result.signatures[0].ltv_info)

        # Determine highest PAdES level
        pades_level = self._determine_pades_level(result.signatures)

        return ValidateResponse(
            filename=result.file_path.name,
            is_signed=result.is_signed,
            is_valid=result.all_valid,
            signature_count=result.signature_count,
            signatures=api_signatures,
            ltv_info=ltv_info,
            pades_level=pades_level,
            errors=errors,
        )

    def _convert_signature_info(self, sig: CoreSignatureInfo) -> APISignatureInfo:
        """
        Convert core SignatureInfo to API SignatureInfo.

        Args:
            sig: Core signature information

        Returns:
            API signature information
        """
        # Determine if signature is valid
        is_valid = sig.status == SignatureStatus.VALID

        # Build validation errors list
        validation_errors = []
        if sig.status != SignatureStatus.VALID:
            validation_errors.append(sig.status_message)

        if sig.revocation_status == "revoked":
            validation_errors.append(f"Certificate revoked: {sig.revocation_message}")
        elif sig.revocation_status == "error":
            validation_errors.append(f"Revocation check error: {sig.revocation_message}")

        if sig.chain_validation_result and not sig.chain_validation_result.is_valid:
            # Join all error messages from chain validation
            error_msg = "; ".join(sig.chain_validation_result.errors)
            validation_errors.append(f"Chain validation failed: {error_msg}")

        # Get PAdES level from LTV info
        pades_level = "B-B"
        if sig.ltv_info:
            pades_level = sig.ltv_info.pades_level.value

        return APISignatureInfo(
            signer_name=sig.signer_name,
            signer_email=sig.signer_email,
            signing_time=sig.signing_time,
            reason=None,  # Core SignatureInfo doesn't have reason field
            location=None,  # Core SignatureInfo doesn't have location field
            is_valid=is_valid,
            validation_errors=validation_errors,
            has_timestamp=sig.is_timestamp_valid,
            timestamp_time=sig.signing_time if sig.is_timestamp_valid else None,
            pades_level=pades_level,
        )

    def _convert_ltv_info(self, ltv: CoreLTVInfo) -> APILTVInfo:
        """
        Convert core LTVInfo to API LTVInfo.

        Args:
            ltv: Core LTV information

        Returns:
            API LTV information
        """
        return APILTVInfo(
            has_dss=ltv.has_dss,
            has_ocsp=ltv.has_ocsp_in_dss,
            has_crl=ltv.has_crl_in_dss,
            has_archive_timestamp=ltv.has_archive_timestamp,
            archive_timestamp_count=len(ltv.archive_timestamps),
        )

    def _determine_pades_level(self, signatures: list[CoreSignatureInfo]) -> str:
        """
        Determine highest PAdES level across all signatures.

        Args:
            signatures: List of signature information

        Returns:
            Highest PAdES level string (e.g., "B-LTA")
        """
        if not signatures:
            return "unknown"

        # PAdES level hierarchy
        levels = {
            "B-B": 0,
            "B-T": 1,
            "B-LT": 2,
            "B-LTA": 3,
            "unknown": -1,
        }

        highest_level = "unknown"
        highest_value = -1

        for sig in signatures:
            if sig.ltv_info:
                level = sig.ltv_info.pades_level.value
                value = levels.get(level, -1)
                if value > highest_value:
                    highest_value = value
                    highest_level = level

        return highest_level

    def validate_eidas(self, pdf_path: Path) -> dict:
        """Validate PDF with eIDAS qualification detection.

        Generates a structured validation report per ETSI TS 119 102-2
        including eIDAS qualification level (QES/AdES-QC/AdES/Basic),
        algorithm strength assessment, and revocation freshness.

        Args:
            pdf_path: Path to PDF file to validate

        Returns:
            eIDAS validation report dictionary

        Raises:
            ValueError: If PDF file doesn't exist
        """
        from pdfsigner.core.validator.validation_report import generate_eidas_report

        if not pdf_path.exists():
            raise ValueError(f"PDF file not found: {pdf_path}")

        logger.info(f"eIDAS validating PDF: {pdf_path.name}")

        validation_result = self.validator.validate(pdf_path)
        return generate_eidas_report(validation_result, pdf_path)


# --- Public Exports ---

__all__ = ["ValidationService"]
