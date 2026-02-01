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
from datetime import datetime
from enum import Enum

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from pdfsigner.core.validator.pdf_validator import ValidationResult


class ReportFormat(Enum):
    """Report output format."""

    PDF = "pdf"
    CSV = "csv"
    JSON = "json"


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
        self._styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        """Setup custom paragraph styles for PDF reports."""
        # Title style
        self._styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self._styles["Heading1"],
                fontSize=18,
                textColor=colors.HexColor("#1a5490"),
                spaceAfter=12,
                alignment=1,  # Center
            )
        )

        # Section heading style
        self._styles.add(
            ParagraphStyle(
                name="SectionHeading",
                parent=self._styles["Heading2"],
                fontSize=14,
                textColor=colors.HexColor("#2c3e50"),
                spaceAfter=8,
                spaceBefore=16,
            )
        )

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
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        story: list[Paragraph | Spacer | Table] = []

        # Title
        title = Paragraph(self.options.title, self._styles["ReportTitle"])
        story.append(title)

        # Report metadata
        metadata_text = f"""
        <para>
        <b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>
        <b>Total Files:</b> {len(results)}
        </para>
        """
        story.append(Paragraph(metadata_text, self._styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

        # Summary section
        if self.options.include_summary:
            story.extend(self._generate_pdf_summary(results))

        # Details section
        if self.options.include_details:
            story.extend(self._generate_pdf_details(results))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.read()

    def _generate_pdf_summary(
        self, results: list[ValidationResult]
    ) -> list[Paragraph | Spacer | Table]:
        """Generate summary section for PDF report."""
        elements = []

        # Section heading
        heading = Paragraph("Validation Summary", self._styles["SectionHeading"])
        elements.append(heading)

        # Count files by status
        total_files = len(results)
        signed_files = sum(1 for r in results if r.is_signed)
        unsigned_files = total_files - signed_files
        all_valid = sum(1 for r in results if r.all_valid and r.is_signed)
        has_issues = signed_files - all_valid
        errors = sum(1 for r in results if r.error is not None)

        # Summary table
        summary_data = [
            ["Metric", "Count", "Percentage"],
            ["Total Files", str(total_files), "100%"],
            [
                "Signed Files",
                str(signed_files),
                f"{signed_files / total_files * 100:.1f}%",
            ],
            [
                "Unsigned Files",
                str(unsigned_files),
                f"{unsigned_files / total_files * 100:.1f}%",
            ],
            [
                "All Valid",
                str(all_valid),
                f"{all_valid / total_files * 100:.1f}%" if total_files > 0 else "0%",
            ],
            [
                "Has Issues",
                str(has_issues),
                f"{has_issues / total_files * 100:.1f}%" if total_files > 0 else "0%",
            ],
            [
                "Errors",
                str(errors),
                f"{errors / total_files * 100:.1f}%" if total_files > 0 else "0%",
            ],
        ]

        table = Table(summary_data, colWidths=[8 * cm, 4 * cm, 4 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                ]
            )
        )

        elements.append(table)
        elements.append(Spacer(1, 0.5 * cm))

        return elements

    def _generate_pdf_details(
        self, results: list[ValidationResult]
    ) -> list[Paragraph | Spacer | Table]:
        """Generate details section for PDF report."""
        elements = []

        # Section heading
        heading = Paragraph("File Details", self._styles["SectionHeading"])
        elements.append(heading)

        # Details table
        table_data = [["File", "Status", "Signatures", "Signer"]]

        for result in results:
            filename = result.file_path.name

            # Determine status
            if result.error:
                status = "ERROR"
            elif not result.is_signed:
                status = "UNSIGNED"
            elif result.all_valid:
                status = "VALID"
            else:
                status = "INVALID"

            # Get first signer name if available
            signer = ""
            if result.signatures:
                signer = result.signatures[0].signer_name[:30]  # Truncate if too long

            sig_count = str(result.signature_count)

            table_data.append([filename, status, sig_count, signer])

        # Create table with appropriate column widths
        table = Table(table_data, colWidths=[7 * cm, 3 * cm, 3 * cm, 4 * cm])

        # Apply table styling
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]

        # Color status column based on status
        for i, result in enumerate(results, start=1):
            if result.error:
                color = colors.HexColor("#fee")
            elif not result.is_signed:
                color = colors.HexColor("#eee")
            elif result.all_valid:
                color = colors.HexColor("#efe")
            else:
                color = colors.HexColor("#ffe")

            style_commands.append(("BACKGROUND", (1, i), (1, i), color))

        table.setStyle(TableStyle(style_commands))

        elements.append(table)

        # Add detailed certificate info if enabled
        if self.options.include_certificate_info:
            elements.extend(self._generate_certificate_details(results))

        return elements

    def _generate_certificate_details(self, results: list[ValidationResult]) -> list:
        """Generate detailed certificate information section."""
        elements = []

        for result in results:
            if not result.signatures:
                continue

            elements.append(Spacer(1, 0.5 * cm))

            # File heading
            file_heading = Paragraph(f"<b>{result.file_path.name}</b>", self._styles["Normal"])
            elements.append(file_heading)

            # Certificate details for each signature
            for i, sig in enumerate(result.signatures, start=1):
                valid_from = (
                    sig.certificate_valid_from.strftime("%Y-%m-%d")
                    if sig.certificate_valid_from
                    else "N/A"
                )
                valid_to = (
                    sig.certificate_valid_to.strftime("%Y-%m-%d")
                    if sig.certificate_valid_to
                    else "N/A"
                )
                cert_text = f"""
                <para fontSize="8">
                <b>Signature {i}:</b><br/>
                &nbsp;&nbsp;Signer: {sig.signer_name}<br/>
                &nbsp;&nbsp;Email: {sig.signer_email or "N/A"}<br/>
                &nbsp;&nbsp;Issuer: {sig.certificate_issuer}<br/>
                &nbsp;&nbsp;Valid: {valid_from} to {valid_to}<br/>
                &nbsp;&nbsp;Status: {sig.status.value}<br/>
                &nbsp;&nbsp;Message: {sig.status_message}
                </para>
                """
                elements.append(Paragraph(cert_text, self._styles["Normal"]))

        return elements

    def generate_csv(self, results: list[ValidationResult]) -> str:
        """
        Generate CSV report (Excel-compatible).

        Args:
            results: List of validation results

        Returns:
            CSV report as string
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        # Header
        headers = [
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
        writer.writerow(headers)

        # Data rows
        for result in results:
            # Determine overall status
            if result.error:
                status = "ERROR"
            elif not result.is_signed:
                status = "UNSIGNED"
            elif result.all_valid:
                status = "VALID"
            else:
                status = "INVALID"

            # Get first signature info if available
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
                    sig.certificate_valid_to.strftime("%Y-%m-%d")
                    if sig.certificate_valid_to
                    else ""
                )

            row = [
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
            writer.writerow(row)

        return output.getvalue()

    def generate_json(self, results: list[ValidationResult]) -> str:
        """
        Generate JSON report with full details.

        Args:
            results: List of validation results

        Returns:
            JSON report as string
        """
        report_data = {
            "metadata": {
                "title": self.options.title,
                "generated_at": datetime.now().isoformat(),
                "total_files": len(results),
            },
            "summary": self._generate_summary_dict(results),
            "files": [],
        }

        # Add file details
        for result in results:
            file_data = {
                "file_path": str(result.file_path),
                "filename": result.file_path.name,
                "is_signed": result.is_signed,
                "signature_count": result.signature_count,
                "all_valid": result.all_valid,
                "error": result.error,
                "signatures": [],
            }

            # Add signature details
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
                file_data["signatures"].append(sig_data)

            report_data["files"].append(file_data)

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
