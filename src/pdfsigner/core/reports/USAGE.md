# Validation Report Generator - Usage Guide

## Overview

The validation report generator allows you to export PDF validation results in multiple formats: PDF, CSV, and JSON.

## Basic Usage

### 1. Generate Reports Programmatically

```python
from pathlib import Path
from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.core.reports import (
    ValidationReportGenerator,
    ReportFormat,
    ReportOptions,
)

# Validate some PDFs
validator = PDFValidator()
results = [
    validator.validate(Path("document1.pdf")),
    validator.validate(Path("document2.pdf")),
]

# Create report generator with custom options
options = ReportOptions(
    include_summary=True,
    include_details=True,
    include_certificate_info=True,
    title="My Validation Report",
)
generator = ValidationReportGenerator(options)

# Generate PDF report
pdf_bytes = generator.generate(results, ReportFormat.PDF)
with open("report.pdf", "wb") as f:
    f.write(pdf_bytes)

# Generate CSV report
csv_string = generator.generate(results, ReportFormat.CSV)
with open("report.csv", "w") as f:
    f.write(csv_string)

# Generate JSON report
json_string = generator.generate(results, ReportFormat.JSON)
with open("report.json", "w") as f:
    f.write(json_string)
```

### 2. Using the Export Dialog (GUI)

```python
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk
from pdfsigner.gui.dialogs import ExportReportDialog
from pdfsigner.core.reports import ValidationReportGenerator

# Create and show dialog
dialog = ExportReportDialog(parent_window)
dialog.present()

# After dialog closes, check if user exported
if not dialog.was_cancelled():
    options = dialog.get_options()
    format = dialog.get_format()
    output_path = dialog.get_output_path()

    # Generate report
    generator = ValidationReportGenerator(options)
    report_data = generator.generate(validation_results, format)

    # Save to file
    if format == ReportFormat.PDF:
        with open(output_path, "wb") as f:
            f.write(report_data)
    else:
        with open(output_path, "w") as f:
            f.write(report_data)
```

## Report Formats

### PDF Report

Professional-looking report with:
- Header with title and generation date
- Summary table with statistics
- Detailed file table with color-coded status
- Optional certificate details per file

**Best for:** Formal reports, audits, presentations

### CSV Report

Excel-compatible spreadsheet with columns:
- Filename
- Status (VALID, INVALID, UNSIGNED, ERROR)
- Signed (Yes/No)
- Signature Count
- All Valid (Yes/No)
- Signer Name
- Signer Email
- Signing Time
- Certificate Valid Until
- Error

**Best for:** Data analysis, spreadsheet manipulation, filtering

### JSON Report

Complete structured data with:
- Metadata (title, generation time, file count)
- Summary statistics
- Full file details with all signature information
- Certificate details

**Best for:** API integration, automated processing, archival

## Report Options

```python
ReportOptions(
    include_summary=True,           # Include summary statistics
    include_details=True,           # Include per-file details
    include_certificate_info=True,  # Include certificate details (PDF only)
    title="PDF Validation Report",  # Report title
)
```

## Status Color Coding (PDF Reports)

- **Green**: All signatures valid
- **Yellow**: Signed but has issues
- **Gray**: Unsigned PDF
- **Red**: Error during validation

## Integration Example

```python
from pathlib import Path
from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.core.reports import ValidationReportGenerator, ReportFormat

def validate_and_export(pdf_files: list[Path], output_file: Path):
    """Validate PDFs and generate report."""
    # Validate all files
    validator = PDFValidator()
    results = [validator.validate(pdf) for pdf in pdf_files]

    # Generate report
    generator = ValidationReportGenerator()

    # Choose format based on file extension
    if output_file.suffix == ".pdf":
        report = generator.generate(results, ReportFormat.PDF)
        mode = "wb"
    elif output_file.suffix == ".csv":
        report = generator.generate(results, ReportFormat.CSV)
        mode = "w"
    else:
        report = generator.generate(results, ReportFormat.JSON)
        mode = "w"

    # Save report
    with open(output_file, mode) as f:
        f.write(report)

    print(f"Report saved to: {output_file}")

    # Print summary
    total = len(results)
    valid = sum(1 for r in results if r.all_valid and r.is_signed)
    print(f"Validated {total} files, {valid} fully valid")

# Usage
pdf_files = [Path("doc1.pdf"), Path("doc2.pdf"), Path("doc3.pdf")]
validate_and_export(pdf_files, Path("validation_report.pdf"))
```
