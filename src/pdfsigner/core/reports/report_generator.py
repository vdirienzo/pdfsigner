"""
report_generator.py - Validation report generator

Author: Homero Thompson del Lago del Terror

Generates validation reports in multiple formats (PDF, CSV, JSON) from
ValidationResult data.
"""

import csv
import io
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from pdfsigner.core.reports.report_pdf_builder import (
    build_pdf_report,
    result_status_label,
)
from pdfsigner.core.types.report_format import ReportFormat
from pdfsigner.core.validator.pdf_validator import ValidationResult


@dataclass
class ReportOptions:
    """Options for report generation."""

    include_summary: bool = True
    include_details: bool = True
    include_certificate_info: bool = True
    title: str = "PDF Validation Report"


class ValidationReportGenerator:
    """
    Generates validation reports in multiple formats.

    Supports PDF (professional layout), CSV (Excel-compatible),
    and JSON (full details) output formats.
    """

    def __init__(self, options: ReportOptions | None = None):
        """
        Initialize report generator.

        Args:
            options: Report generation options. Uses defaults if None.
        """
        self.options = options or ReportOptions()

    def generate(self, results: list[ValidationResult], format: ReportFormat) -> bytes | str:
        """
        Generate report in specified format.

        Args:
            results: List of validation results
            format: Output format (PDF, CSV, JSON)

        Returns:
            Report as bytes (PDF) or string (CSV, JSON)
        """
        if format == ReportFormat.PDF:
            return self.generate_pdf(results)
        elif format == ReportFormat.CSV:
            return self.generate_csv(results)
        elif format == ReportFormat.JSON:
            return self.generate_json(results)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def generate_pdf(self, results: list[ValidationResult]) -> bytes:
        """
        Generate PDF report with professional layout.

        Args:
            results: List of validation results

        Returns:
            PDF report as bytes
        """
        return build_pdf_report(
            results,
            title=self.options.title,
            include_summary=self.options.include_summary,
            include_details=self.options.include_details,
            include_certificate_info=self.options.include_certificate_info,
        )

    # Keep static methods for backward compatibility (used in CSV)
    @staticmethod
    def _result_status_label(result: ValidationResult) -> str:
        """Determine human-readable status label for a validation result."""
        return result_status_label(result)

    _CSV_HEADERS = [
        "Filename",
        "Status",
        "Signed",
        "Signature Count",
        "All Valid",
        "Signer Name",
        "Signer Email",
        "Signing Time",
        "Certificate Valid Until",
        "Error",
    ]

    def _build_csv_row(self, result: ValidationResult) -> list:
        """Build a single CSV row from a validation result."""
        status = result_status_label(result)

        signer_name = ""
        signer_email = ""
        signing_time = ""
        cert_valid_until = ""

        if result.signatures:
            sig = result.signatures[0]
            signer_name = sig.signer_name
            signer_email = sig.signer_email or ""
            signing_time = (
                sig.signing_time.strftime("%Y-%m-%d %H:%M:%S") if sig.signing_time else ""
            )
            cert_valid_until = (
                sig.certificate_valid_to.strftime("%Y-%m-%d") if sig.certificate_valid_to else ""
            )

        return [
            result.file_path.name,
            status,
            "Yes" if result.is_signed else "No",
            result.signature_count,
            "Yes" if result.all_valid else "No",
            signer_name,
            signer_email,
            signing_time,
            cert_valid_until,
            result.error or "",
        ]

    def generate_csv(self, results: list[ValidationResult]) -> str:
        """Generate CSV report (Excel-compatible).

        Args:
            results: List of validation results

        Returns:
            CSV report as string
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(self._CSV_HEADERS)

        for result in results:
            writer.writerow(self._build_csv_row(result))

        return output.getvalue()

    def generate_json(self, results: list[ValidationResult]) -> str:
        """
        Generate JSON report with full details.

        Args:
            results: List of validation results

        Returns:
            JSON report as string
        """
        files_list: list[dict] = []
        report_data = {
            "metadata": {
                "title": self.options.title,
                "generated_at": datetime.now(UTC).isoformat(),
                "total_files": len(results),
            },
            "summary": self._generate_summary_dict(results),
            "files": files_list,
        }

        for result in results:
            signatures_list: list[dict] = []
            file_data: dict = {
                "file_path": str(result.file_path),
                "filename": result.file_path.name,
                "is_signed": result.is_signed,
                "signature_count": result.signature_count,
                "all_valid": result.all_valid,
                "error": result.error,
                "signatures": signatures_list,
            }

            for sig in result.signatures:
                sig_data = {
                    "signer_name": sig.signer_name,
                    "signer_email": sig.signer_email,
                    "signing_time": sig.signing_time.isoformat() if sig.signing_time else None,
                    "is_timestamp_valid": sig.is_timestamp_valid,
                    "certificate": {
                        "issuer": sig.certificate_issuer,
                        "serial": sig.certificate_serial,
                        "valid_from": (
                            sig.certificate_valid_from.isoformat()
                            if sig.certificate_valid_from
                            else None
                        ),
                        "valid_to": (
                            sig.certificate_valid_to.isoformat()
                            if sig.certificate_valid_to
                            else None
                        ),
                    },
                    "status": sig.status.value,
                    "status_message": sig.status_message,
                    "field_name": sig.field_name,
                    "covers_whole_document": sig.covers_whole_document,
                    "is_modification_allowed": sig.is_modification_allowed,
                    "page_number": sig.page_number,
                }
                signatures_list.append(sig_data)

            files_list.append(file_data)

        return json.dumps(report_data, indent=2)

    def _generate_summary_dict(self, results: list[ValidationResult]) -> dict:
        """Generate summary statistics dictionary."""
        total = len(results)
        signed = sum(1 for r in results if r.is_signed)
        unsigned = total - signed
        all_valid = sum(1 for r in results if r.all_valid and r.is_signed)
        has_issues = signed - all_valid
        errors = sum(1 for r in results if r.error is not None)

        return {
            "total_files": total,
            "signed_files": signed,
            "unsigned_files": unsigned,
            "all_valid": all_valid,
            "has_issues": has_issues,
            "errors": errors,
        }

    def _count_statuses(self, results: list[ValidationResult]) -> dict[str, int]:
        """Count validation results by status."""
        status_counter: Counter[str] = Counter()

        for result in results:
            if result.error:
                status_counter["error"] += 1
            elif not result.is_signed:
                status_counter["unsigned"] += 1
            elif result.all_valid:
                status_counter["valid"] += 1
            else:
                status_counter["invalid"] += 1

        return dict(status_counter)
