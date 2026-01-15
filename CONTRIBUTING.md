# Contributing to Cedar Python

Thank you for your interest in contributing to Cedar Python!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/cedar-python.git`
3. Create a virtual environment: `uv venv && source .venv/bin/activate`
4. Install dependencies: `uv sync --group dev`
5. Build the Rust extension: `uv run maturin develop`

## Development Workflow

### Running Tests

```bash
uv run pytest
```

### Formatting and Linting

```bash
# Python
uv run ruff format .
uv run ruff check --fix .

# Rust
cargo fmt
cargo clippy
```

### Building

```bash
uv run maturin develop  # Development build
uv run maturin build    # Release build
```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Ensure tests pass and code is formatted
4. Submit a pull request with a clear description of changes

## Code Style

- Follow existing code patterns
- Add tests for new functionality
- Keep commits focused and atomic

## Reporting Issues

Please use GitHub Issues to report bugs or request features. Include:
- Clear description of the issue
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
