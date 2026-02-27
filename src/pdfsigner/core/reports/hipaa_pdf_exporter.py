"""
hipaa_pdf_exporter.py - PDF export for HIPAA compliance reports

Handles PDF generation using PyMuPDF (fitz) for HIPAA audit reports.
"""

from pathlib import Path

from loguru import logger

from pdfsigner.core.reports.hipaa_types import HIPAAReport

# PDF Layout Constants
PDF_PAGE_WIDTH = 612
PDF_PAGE_HEIGHT = 792
PDF_MARGIN_LEFT = 72
PDF_INDENT_LEFT = 90
PDF_INDENT_NESTED = 110
PDF_TITLE_FONT_SIZE = 24
PDF_HEADING_FONT_SIZE = 14
PDF_BODY_FONT_SIZE = 12
PDF_ITEM_FONT_SIZE = 11
PDF_DETAIL_FONT_SIZE = 10
PDF_FOOTER_FONT_SIZE = 9
PDF_LINE_HEIGHT = 16
PDF_SECTION_SPACING = 10
PDF_PAGE_BREAK_Y = 650
PDF_FOOTER_Y = 750


def export_hipaa_pdf(report: HIPAAReport, path: Path) -> None:
    """
    Export HIPAA report as PDF using PyMuPDF.

    Args:
        report: HIPAAReport to export
        path: Output file path
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        logger.error("PyMuPDF (fitz) not available. Cannot export PDF.")
        return

    doc = fitz.open()
    try:
        # Title page
        page = doc.new_page(width=PDF_PAGE_WIDTH, height=PDF_PAGE_HEIGHT)

        # Title
        page.insert_text(
            (PDF_MARGIN_LEFT, 100),
            report.title,
            fontsize=PDF_TITLE_FONT_SIZE,
            fontname="helv",
        )

        # Metadata
        page.insert_text(
            (PDF_MARGIN_LEFT, 140),
            f"Organization: {report.organization}",
            fontsize=PDF_BODY_FONT_SIZE,
        )
        page.insert_text(
            (PDF_MARGIN_LEFT, 160),
            f"Report ID: {report.report_id}",
            fontsize=PDF_BODY_FONT_SIZE,
        )
        page.insert_text(
            (PDF_MARGIN_LEFT, 180),
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            fontsize=PDF_BODY_FONT_SIZE,
        )
        period_text = (
            f"Period: {report.period_start.strftime('%Y-%m-%d')} "
            f"to {report.period_end.strftime('%Y-%m-%d')}"
        )
        page.insert_text((PDF_MARGIN_LEFT, 200), period_text, fontsize=PDF_BODY_FONT_SIZE)

        # Compliance Status
        status_color = {
            "compliant": (0, 0.5, 0),
            "warning": (0.8, 0.6, 0),
            "non_compliant": (0.8, 0, 0),
        }.get(report.compliance_status, (0.5, 0.5, 0.5))
        page.insert_text(
            (PDF_MARGIN_LEFT, 240),
            f"Compliance Status: {report.compliance_status.upper()}",
            fontsize=PDF_HEADING_FONT_SIZE,
            color=status_color,
        )

        y = 280

        # User Access Section
        if report.user_access:
            page.insert_text(
                (PDF_MARGIN_LEFT, y), "USER ACCESS SUMMARY", fontsize=PDF_HEADING_FONT_SIZE
            )
            y += 20
            ua = report.user_access
            for label, value in [
                ("Total Users", ua.total_users),
                ("Logins", ua.logins),
                ("Failed Logins", ua.failed_logins),
                ("Documents Accessed", ua.unique_documents_accessed),
            ]:
                page.insert_text(
                    (PDF_INDENT_LEFT, y),
                    f"• {label}: {value}",
                    fontsize=PDF_ITEM_FONT_SIZE,
                )
                y += PDF_LINE_HEIGHT
            y += PDF_SECTION_SPACING

        # Encryption Section
        if report.encryption:
            page.insert_text(
                (PDF_MARGIN_LEFT, y), "ENCRYPTION SUMMARY", fontsize=PDF_HEADING_FONT_SIZE
            )
            y += 20
            enc = report.encryption
            for label, value in [  # type: ignore[assignment]
                ("Documents Encrypted", enc.documents_encrypted),
                ("Documents Decrypted", enc.documents_decrypted),
                ("Encryption Method", enc.encryption_method.upper()),
                ("PHI Documents Encrypted", enc.phi_documents_encrypted),
            ]:
                page.insert_text(
                    (PDF_INDENT_LEFT, y),
                    f"• {label}: {value}",
                    fontsize=PDF_ITEM_FONT_SIZE,
                )
                y += PDF_LINE_HEIGHT
            y += PDF_SECTION_SPACING

        # Emergency Access Section
        if report.emergency_access:
            page.insert_text(
                (PDF_MARGIN_LEFT, y),
                "EMERGENCY ACCESS SUMMARY",
                fontsize=PDF_HEADING_FONT_SIZE,
            )
            y += 20
            ea = report.emergency_access
            for label, value in [
                ("Requests Made", ea.requests_made),
                ("Requests Approved", ea.requests_approved),
                ("Requests Denied", ea.requests_denied),
                ("Documents Accessed", ea.documents_accessed),
            ]:
                page.insert_text(
                    (PDF_INDENT_LEFT, y),
                    f"• {label}: {value}",
                    fontsize=PDF_ITEM_FONT_SIZE,
                )
                y += PDF_LINE_HEIGHT
            y += PDF_SECTION_SPACING

        # PHI Access Section
        if report.phi_access:
            if y > PDF_PAGE_BREAK_Y:
                page = doc.new_page(width=PDF_PAGE_WIDTH, height=PDF_PAGE_HEIGHT)
                y = PDF_MARGIN_LEFT

            page.insert_text(
                (PDF_MARGIN_LEFT, y),
                "PHI DETECTION SUMMARY",
                fontsize=PDF_HEADING_FONT_SIZE,
            )
            y += 20
            phi = report.phi_access
            for label, value in [
                ("Documents Scanned", phi.documents_scanned),
                ("Documents with PHI", phi.documents_with_phi),
                ("Blocked Operations", phi.blocked_operations),
            ]:
                page.insert_text(
                    (PDF_INDENT_LEFT, y),
                    f"• {label}: {value}",
                    fontsize=PDF_ITEM_FONT_SIZE,
                )
                y += PDF_LINE_HEIGHT

            if phi.phi_types_detected:
                page.insert_text(
                    (PDF_INDENT_LEFT, y),
                    "• PHI Types Detected:",
                    fontsize=PDF_ITEM_FONT_SIZE,
                )
                y += PDF_LINE_HEIGHT
                for phi_type, count in phi.phi_types_detected.items():
                    page.insert_text(
                        (PDF_INDENT_NESTED, y),
                        f"- {phi_type}: {count}",
                        fontsize=PDF_DETAIL_FONT_SIZE,
                    )
                    y += 14

        # Footer
        page.insert_text(
            (PDF_MARGIN_LEFT, PDF_FOOTER_Y),
            "Generated by PDFSigner HIPAA Compliance Module",
            fontsize=PDF_FOOTER_FONT_SIZE,
            color=(0.5, 0.5, 0.5),
        )

        doc.save(str(path))
    finally:
        doc.close()
    logger.info(f"Exported PDF report to {path}")
