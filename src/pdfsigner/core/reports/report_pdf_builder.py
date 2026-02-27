"""
report_pdf_builder.py - PDF report generation for validation reports

Extracted from report_generator.py to keep modules under 400 lines.
Contains ReportLab-based PDF generation (summary, details, certificate info).
"""

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Flowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from pdfsigner.core.validator.pdf_validator import ValidationResult


def setup_custom_styles() -> dict:
    """Setup and return custom paragraph styles for PDF reports."""
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#1a5490"),
            spaceAfter=12,
            alignment=1,  # Center
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#2c3e50"),
            spaceAfter=8,
            spaceBefore=16,
        )
    )

    return styles


def result_status_label(result: ValidationResult) -> str:
    """Determine human-readable status label for a validation result."""
    if result.error:
        return "ERROR"
    if not result.is_signed:
        return "UNSIGNED"
    if result.all_valid:
        return "VALID"
    return "INVALID"


def result_status_color(result: ValidationResult) -> colors.HexColor:
    """Determine background color for a validation result status cell."""
    if result.error:
        return colors.HexColor("#fee")
    if not result.is_signed:
        return colors.HexColor("#eee")
    if result.all_valid:
        return colors.HexColor("#efe")
    return colors.HexColor("#ffe")


def generate_pdf_summary(results: list[ValidationResult], styles: dict) -> list[Flowable]:
    """Generate summary section for PDF report."""
    elements: list[Flowable] = []

    heading = Paragraph("Validation Summary", styles["SectionHeading"])
    elements.append(heading)

    total_files = len(results)
    signed_files = sum(1 for r in results if r.is_signed)
    unsigned_files = total_files - signed_files
    all_valid = sum(1 for r in results if r.all_valid and r.is_signed)
    has_issues = signed_files - all_valid
    errors = sum(1 for r in results if r.error is not None)

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


def build_details_table(results: list[ValidationResult], cell_style: ParagraphStyle) -> Table:
    """Build the file details table with status coloring."""
    table_data = [["File", "Status", "Signatures", "Signer"]]

    for result in results:
        filename = Paragraph(result.file_path.name, cell_style)
        status = result_status_label(result)
        signer_text = result.signatures[0].signer_name if result.signatures else ""
        signer = Paragraph(signer_text, cell_style)
        table_data.append([filename, status, str(result.signature_count), signer])

    table = Table(table_data, colWidths=[8 * cm, 2.5 * cm, 2 * cm, 4.5 * cm])

    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]

    for i, result in enumerate(results, start=1):
        color = result_status_color(result)
        style_commands.append(("BACKGROUND", (1, i), (1, i), color))

    table.setStyle(TableStyle(style_commands))
    return table


def generate_certificate_details(results: list[ValidationResult], styles: dict) -> list[Flowable]:
    """Generate detailed certificate information section."""
    elements: list[Flowable] = []

    for result in results:
        if not result.signatures:
            continue

        elements.append(Spacer(1, 0.5 * cm))

        file_heading = Paragraph(f"<b>{result.file_path.name}</b>", styles["Normal"])
        elements.append(file_heading)

        for i, sig in enumerate(result.signatures, start=1):
            valid_from = (
                sig.certificate_valid_from.strftime("%Y-%m-%d")
                if sig.certificate_valid_from
                else "N/A"
            )
            valid_to = (
                sig.certificate_valid_to.strftime("%Y-%m-%d") if sig.certificate_valid_to else "N/A"
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
            elements.append(Paragraph(cert_text, styles["Normal"]))

    return elements


def generate_pdf_details(
    results: list[ValidationResult],
    styles: dict,
    include_certificate_info: bool = True,
) -> list[Flowable]:
    """Generate details section for PDF report."""
    elements: list[Flowable] = []

    heading = Paragraph("File Details", styles["SectionHeading"])
    elements.append(heading)

    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
    )

    elements.append(build_details_table(results, cell_style))

    if include_certificate_info:
        elements.extend(generate_certificate_details(results, styles))

    return elements


def build_pdf_report(
    results: list[ValidationResult],
    title: str = "PDF Validation Report",
    include_summary: bool = True,
    include_details: bool = True,
    include_certificate_info: bool = True,
) -> bytes:
    """
    Generate PDF report with professional layout.

    Args:
        results: List of validation results
        title: Report title
        include_summary: Include summary section
        include_details: Include file details section
        include_certificate_info: Include certificate info

    Returns:
        PDF report as bytes
    """
    from datetime import UTC, datetime

    styles = setup_custom_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    story: list[Flowable] = []

    story.append(Paragraph(title, styles["ReportTitle"]))

    metadata_text = f"""
    <para>
    <b>Generated:</b> {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")}<br/>
    <b>Total Files:</b> {len(results)}
    </para>
    """
    story.append(Paragraph(metadata_text, styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    if include_summary:
        story.extend(generate_pdf_summary(results, styles))

    if include_details:
        story.extend(generate_pdf_details(results, styles, include_certificate_info))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
