"""
stamp_builder.py - Stamp building for PDF signatures

Author: Homero Thompson del Lago del Terror

Handles visual stamp creation for PDF signatures:
- Template rendering with QR codes
- Visual stamp placement on PDF pages
- Stamp style configuration (text, image, QR)
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from pdfsigner.config.settings import get_settings

if TYPE_CHECKING:
    from pdfsigner.core.signer.pdf_signer import SignatureAppearance


def create_stretch_layout():
    """Create the standard stretch layout for stamp styles.

    Returns:
        SimpleBoxLayoutRule configured for full-stretch with no margins
    """
    from pyhanko.pdf_utils.layout import (
        AxisAlignment,
        InnerScaling,
        Margins,
        SimpleBoxLayoutRule,
    )

    return SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MIN,
        inner_content_scaling=InnerScaling.STRETCH_TO_FIT,
        margins=Margins(left=0, right=0, top=0, bottom=0),
    )


def render_template_stamp(
    template_name: str,
    signer_name: str | None,
    input_path: Path | None,
    appearance: "SignatureAppearance",
    organization: str | None = None,
) -> Path | None:
    """
    Render a signature stamp using a template.

    Args:
        template_name: Name of template to use
        signer_name: Certificate CN for {signer_name} variable
        input_path: PDF path (for QR hash if template has QR layer)
        appearance: Signature appearance config
        organization: Organization from certificate for {org} variable

    Returns:
        Path to rendered PNG or None if failed
    """
    try:
        from pdfsigner.core.signature import (
            get_builtin_templates_dir,
            load_template,
            render_template,
        )

        template = load_template(template_name)
        if not template:
            logger.warning(f"Template not found: {template_name}")
            return None

        # Prepare variables for substitution
        variables = {
            "signer_name": signer_name or "Digital Signature",
            "date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M"),
            "org": organization or "",
        }

        # Check if template has QR layer and generate QR if needed
        qr_image = None
        has_qr_layer = any(layer.type == "qr" for layer in template.layers)
        if has_qr_layer and input_path:
            try:
                from pdfsigner.core.stamp.qr_generator import (
                    QRData,
                    calculate_document_hash,
                    generate_qr_image,
                )

                doc_hash = calculate_document_hash(input_path)
                qr_data = QRData(
                    document_hash=doc_hash,
                    signer_name=signer_name or "Digital Signature",
                )
                qr_image = generate_qr_image(qr_data)
            except Exception as e:
                logger.warning(f"Could not generate QR for template: {e}")

        templates_dir = get_builtin_templates_dir()
        stamp_path = render_template(
            template,
            variables=variables,
            templates_dir=templates_dir,
            qr_image=qr_image,
        )

        logger.debug(f"Rendered template stamp: {stamp_path}")
        return stamp_path

    except Exception as e:
        logger.error(f"Failed to render template '{template_name}': {e}")
        return None


def add_visual_stamps_to_pdf(
    input_path: Path,
    output_path: Path,
    stamp_positions: list,
    stamp_image_path: Path,
) -> None:
    """
    Add visual stamp images to PDF pages without digital signature.

    Uses PyMuPDF to insert stamp images as annotations on specified pages.
    This is used for multi-page signing where only the first page gets the
    actual digital signature, and other pages get visual copies.

    Args:
        input_path: Source PDF path
        output_path: Output PDF path (can be same as input for temp files)
        stamp_positions: List of StampPosition objects with page/coordinates
        stamp_image_path: Path to the stamp PNG image
    """
    import fitz  # PyMuPDF

    doc = fitz.open(input_path)
    try:
        for pos in stamp_positions:
            if pos.page < len(doc):
                page = doc[pos.page]
                # PDF coordinates: origin at bottom-left, but fitz uses top-left
                # The position from position_finder is already in PDF coords (bottom-left)
                # fitz.Rect uses (x0, y0, x1, y1) with origin at TOP-LEFT
                page_height = page.rect.height
                rect = fitz.Rect(
                    pos.x,
                    page_height - pos.y - pos.height,  # Convert Y from bottom to top
                    pos.x + pos.width,
                    page_height - pos.y,
                )
                page.insert_image(rect, filename=str(stamp_image_path))
                logger.debug(f"Added visual stamp to page {pos.page + 1}")

        doc.save(output_path)
    finally:
        doc.close()


def build_stamp_style(
    appearance: "SignatureAppearance",
    input_path: Path | None = None,
    signer_name: str | None = None,
    organization: str | None = None,
    template_override: str | None = None,
):
    """
    Build the visual stamp style for visible signatures.

    Args:
        appearance: Signature appearance configuration
        input_path: Path to PDF (needed for QR hash calculation)
        signer_name: Name of signer from certificate (for QR)
        organization: Organization name from certificate (for {org} variable)
        template_override: Template name to use instead of settings default

    Returns:
        TextStampStyle if visible signature, None otherwise
    """
    if not appearance.visible:
        return None

    # Import here to avoid circular imports and allow lazy loading
    from pyhanko import stamp
    from pyhanko.pdf_utils import images

    # Use override template if provided, otherwise check settings
    if template_override is not None:
        template_name = template_override
    else:
        settings = get_settings()
        template_name = settings.signature_template

    has_template = bool(template_name)

    if has_template:
        stamp_path = render_template_stamp(
            template_name,
            signer_name,
            input_path,
            appearance,
            organization=organization,
        )
        if stamp_path:
            try:
                bg_layout = create_stretch_layout()
                return stamp.TextStampStyle(
                    stamp_text="",
                    background=images.PdfImage(str(stamp_path)),
                    background_opacity=1.0,  # Full opacity for crisp image
                    background_layout=bg_layout,
                    border_width=0,  # No additional border
                )
            except Exception as e:
                logger.warning(f"Failed to use template stamp: {e}, falling back to text")
        # If template fails, fall through to text-only (NOT QR manual)

    # If QR is enabled (and no template), generate composed stamp image
    # Note: When using templates, QR is controlled by template layers, not this code
    if not has_template and appearance.qr_enabled and input_path:
        try:
            from pdfsigner.core.stamp.qr_generator import QRData, calculate_document_hash
            from pdfsigner.core.stamp.stamp_composer import compose_stamp_with_qr

            # Calculate document hash
            doc_hash = calculate_document_hash(input_path)

            # Get signer name (fallback to generic)
            name = signer_name or "Digital Signature"

            # Create QR data
            qr_data = QRData(
                document_hash=doc_hash,
                signer_name=name,
            )

            # Compose stamp with QR
            stamp_image_path = compose_stamp_with_qr(
                signer_name=name,
                timestamp=datetime.now(UTC),
                qr_data=qr_data,
                qr_position=appearance.qr_position,
            )

            logger.debug(f"Generated QR stamp: {stamp_image_path}")

            bg_layout = create_stretch_layout()
            return stamp.TextStampStyle(
                stamp_text="",
                background=images.PdfImage(str(stamp_image_path)),
                background_opacity=1.0,
                background_layout=bg_layout,
                border_width=0,
            )

        except Exception as e:
            logger.warning(f"Could not generate QR stamp: {e}, falling back to text")

    # Standard text-only stamp
    text_parts = []

    if appearance.show_name:
        text_parts.append("Signed by: %(signer)s")

    if appearance.show_date:
        text_parts.append("Date: %(ts)s")

    # If no parts configured, use default
    if not text_parts:
        text_parts = ["Digitally signed"]

    stamp_text = "\n".join(text_parts)

    # Build stamp style
    style_kwargs = {"stamp_text": stamp_text}

    # Add background image if configured
    if appearance.image_path and appearance.image_path.exists():
        try:
            style_kwargs["background"] = images.PdfImage(str(appearance.image_path))
            logger.debug(f"Using stamp background: {appearance.image_path}")
        except Exception as e:
            logger.warning(f"Could not load stamp image: {e}")

    return stamp.TextStampStyle(**style_kwargs)
