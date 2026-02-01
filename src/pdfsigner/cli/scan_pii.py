"""
CLI command for scanning PDFs for PII/PHI.

Provides command-line interface to detect Protected Health Information
and Personally Identifiable Information in PDF documents.
"""

import argparse

from loguru import logger
from rich.console import Console
from rich.table import Table

from pdfsigner.core.detection import PDFScanner, get_pii_detector

console = Console()


def cmd_scan_pii(args: argparse.Namespace) -> int:
    """
    Scan PDF document for Protected Health Information (PHI) and PII.

    Detects sensitive information including:
    - Social Security Numbers
    - Credit Card Numbers
    - Email Addresses
    - Phone Numbers
    - Dates of Birth
    - Medical Record Numbers
    - Health Plan IDs
    - Diagnosis Codes
    - Prescriptions

    Args:
        args: Parsed command-line arguments with:
            - file: Path to PDF file
            - min_confidence: Minimum confidence threshold (0.0-1.0)
            - show_values: Show redacted PII values
            - verbose: Show detailed information

    Returns:
        Exit code (0 for no PII, 1 for PII detected or error)
    """
    pdf_path = args.file
    min_confidence = args.min_confidence
    show_values = args.show_values
    verbose = args.verbose

    try:
        # Validate input file
        if not pdf_path.exists():
            console.print(f"[red]Error:[/red] File not found: {pdf_path}")
            return 1

        if not pdf_path.suffix.lower() == ".pdf":
            console.print(f"[red]Error:[/red] File must be a PDF: {pdf_path}")
            return 1

        console.print(f"\n[bold]Scanning PDF for PII/PHI:[/bold] {pdf_path.name}")
        console.print(f"Minimum confidence: {min_confidence:.1%}\n")

        # Scan PDF
        scanner = PDFScanner()
        matches = scanner.scan_pdf(str(pdf_path))

        # Filter by confidence
        matches = [m for m in matches if m.confidence >= min_confidence]

        # Calculate risk score
        detector = get_pii_detector()
        risk_score = detector.get_risk_score(matches)

        # Display summary
        if not matches:
            console.print("[green]No PII/PHI detected in document.[/green]")
            console.print(f"Risk Score: {risk_score:.1%}\n")
            return 0

        console.print("[yellow]⚠ PII/PHI detected in document[/yellow]")
        console.print(f"Total matches: {len(matches)}")
        console.print(
            f"Risk Score: [{'red' if risk_score > 0.7 else 'yellow'}]{risk_score:.1%}[/]\n"
        )

        # Count by type
        by_type: dict[str, int] = {}
        for match in matches:
            pii_type = match.pii_type.display_name
            by_type[pii_type] = by_type.get(pii_type, 0) + 1

        # Display by type
        console.print("[bold]Matches by Type:[/bold]")
        for pii_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
            console.print(f"  {pii_type}: {count}")
        console.print()

        # Display detailed table
        if verbose or show_values:
            table = Table(title="Detected PII/PHI", show_header=True)
            table.add_column("Type", style="cyan")
            table.add_column("Page", justify="right", style="magenta")
            table.add_column("Confidence", justify="right", style="green")
            if show_values:
                table.add_column("Value (Redacted)", style="yellow")
            if verbose:
                table.add_column("Context", style="dim")

            for match in matches:
                row = [
                    match.pii_type.display_name,
                    str(match.page + 1) if match.page is not None else "N/A",
                    f"{match.confidence:.1%}",
                ]
                if show_values:
                    row.append(match.redacted_value)
                if verbose:
                    # Truncate context if too long
                    context = (
                        match.context[:60] + "..." if len(match.context) > 60 else match.context
                    )
                    row.append(context)
                table.add_row(*row)

            console.print(table)
            console.print()

        # Display recommendations
        console.print("[bold]Recommendations:[/bold]")
        if risk_score > 0.8:
            console.print("  [red]⚠[/red] High risk - Consider encrypting this document")
            console.print("  [red]⚠[/red] Review document before sharing")
        elif risk_score > 0.5:
            console.print("  [yellow]⚠[/yellow] Medium risk - Review detected information")
        else:
            console.print("  [green]✓[/green] Low risk - Minimal sensitive information")
        console.print()

        # Return code 1 if PII detected (for scripting)
        return 1

    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1
    except Exception as e:
        logger.error(f"PII scan failed: {e}")
        console.print(f"[red]Error scanning PDF:[/red] {e}")
        return 1
