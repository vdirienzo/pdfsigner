# Test Fixtures

This directory contains PDF fixtures used for E2E and integration tests.

## Available Fixtures

| Fixture | Description | Size | Usage |
|---------|-------------|------|-------|
| `sample.pdf` | Simple unsigned PDF | ~1KB | Unsigned PDF for signing tests |
| `sample_signed.pdf` | Signed PDF with QR (dry-run) | ~56KB | Validation tests, stamp verification |
| `sample_signed_no_qr.pdf` | Signed PDF without QR (dry-run) | ~39KB | Template variation tests |
| `sample_hd.pdf` | High-resolution unsigned PDF | ~234KB | Performance tests |
| `multipage.pdf` | Multi-page unsigned PDF | ~3KB | Batch signing tests |
| `test_qr_sin_url.pdf` | QR without URL validation test | ~56KB | QR generation edge cases |

## Stamp Previews

PNG images showing expected stamp appearance:
- `stamp_preview.png` - Default stamp with QR
- `stamp_preview_no_qr.png` - Stamp without QR
- `stamp_hd.png` - High-resolution stamp
- `test_sin_url.png` - QR without URL

## Creating/Regenerating Fixtures

Use the `create_test_pdfs.py` script to regenerate fixtures:

```bash
# Create all fixtures
uv run python tests/fixtures/create_test_pdfs.py

# Create only unsigned PDFs
uv run python tests/fixtures/create_test_pdfs.py --unsigned

# Create only signed PDFs (dry-run mode)
uv run python tests/fixtures/create_test_pdfs.py --signed

# Create multi-page PDF
uv run python tests/fixtures/create_test_pdfs.py --multipage
```

## Notes

- **Signed fixtures** are created using **dry-run mode** (no real PKCS#11 token)
- Dry-run PDFs have visual stamps but NO cryptographic signatures
- All fixtures use Letter size (612x792 points)
- Fixtures are committed to git for test reproducibility

## Usage in Tests

### Using `sample_pdf` fixture (dynamic creation)

The `sample_pdf` fixture is defined in `conftest.py` and creates a temporary PDF for each test:

```python
def test_signing(sample_pdf):
    """sample_pdf is created in temp_dir for this test."""
    result = sign_pdf(sample_pdf)
    assert result.success
```

### Using static fixtures

For validation tests that need pre-signed PDFs:

```python
@pytest.fixture
def unsigned_pdf(self):
    """Path to static unsigned PDF fixture."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "sample.pdf"
    if fixture_path.exists():
        return fixture_path
    pytest.skip("Unsigned PDF fixture not available")

def test_validation(unsigned_pdf):
    """Uses static sample.pdf from fixtures/."""
    result = validate_pdf(unsigned_pdf)
    assert not result.is_signed
```

## Maintenance

- Run `create_test_pdfs.py --all` after major signing logic changes
- Verify fixtures after template system updates
- Keep fixtures small (<100KB) except performance tests
- Document new fixtures in this README

## Related Files

- `tests/conftest.py` - Defines `sample_pdf`, `temp_dir`, and other fixtures
- `tests/integration/test_e2e_signing_flow.py` - E2E tests using these fixtures
- `tests/unit/test_validator.py` - Validation tests using signed fixtures
