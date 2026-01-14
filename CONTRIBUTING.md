# Contributing to PDFSigner

Thank you for your interest in contributing to PDFSigner! This document provides guidelines and instructions for contributing.

## Author

**Homero Thompson del Lago del Terror**

---

## Development Setup

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- GTK4 and libadwaita development libraries (for GUI)
- NSS tools (for token testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/vdirienzo/pdfsigner.git
cd pdfsigner

# Install dependencies
uv sync --all-extras

# Install pre-commit hooks
uv run pre-commit install
```

---

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
```

### 2. Make Changes

- Follow the existing code style
- Add tests for new functionality
- Update documentation if needed

### 3. Run Quality Checks

```bash
# Format and lint
uv run ruff check --fix .
uv run ruff format .

# Type checking
uv run mypy src/

# Security scan
uv run bandit -r src/

# Run tests
uv run pytest -v --cov=src
```

### 4. Commit Your Changes

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```bash
git commit -m "feat(gui): add drag and drop support"
git commit -m "fix(signer): handle empty PDF files"
git commit -m "docs: update installation instructions"
```

**Commit Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Formatting (no code change)
- `refactor` - Code refactoring
- `test` - Adding tests
- `chore` - Maintenance

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Then create a Pull Request on GitHub.

---

## Code Style

### Python

- Use type hints for public functions
- Keep files under 300 lines
- Follow PEP 8 (enforced by Ruff)
- Use descriptive variable names

### Docstrings

```python
def sign_pdf(pdf_path: Path, output_path: Path) -> bool:
    """Sign a PDF file with the configured certificate.

    Args:
        pdf_path: Path to the input PDF file.
        output_path: Path for the signed output file.

    Returns:
        True if signing was successful, False otherwise.

    Raises:
        SigningError: If the signing process fails.
    """
```

---

## Testing

### Running Tests

```bash
# All tests
uv run pytest -v

# With coverage
uv run pytest --cov=src --cov-report=html

# Specific test file
uv run pytest tests/unit/test_pdf_signer.py -v

# Only failed tests from last run
uv run pytest --lf
```

### Writing Tests

- Use the AAA pattern (Arrange, Act, Assert)
- Name tests descriptively: `test_sign_pdf_with_invalid_path_raises_error`
- Use fixtures from `conftest.py`

---

## Project Structure

```
pdfsigner/
├── src/pdfsigner/
│   ├── cli/           # CLI commands
│   ├── config/        # Settings
│   ├── core/          # Core logic (signing, validation, token)
│   ├── gui/           # GTK4 GUI
│   └── ui/dialogs/    # Reusable dialogs
├── tests/
│   ├── unit/          # Unit tests
│   └── integration/   # Integration tests
└── scripts/           # Installation scripts
```

---

## Reporting Issues

When reporting bugs, please include:

1. Operating system and version
2. Python version (`python --version`)
3. PDFSigner version
4. Steps to reproduce
5. Expected vs actual behavior
6. Error messages/logs if any

---

## Questions?

If you have questions, feel free to:

1. Open a [GitHub Issue](https://github.com/vdirienzo/pdfsigner/issues)
2. Check existing issues for similar questions

---

## License

By contributing to PDFSigner, you agree that your contributions will be licensed under the MIT License.
