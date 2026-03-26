# ipanon — Development Guide

For project overview, installation, and usage, see [README.md](README.md).

## Architecture

- `src/ipanon/ranges.py` — IP classification (Cat A/B/C), first-octet sets
- `src/ipanon/permutation.py` — Fisher-Yates + HMAC prefix-preserving permute
- `src/ipanon/anonymizer.py` — Core engine with dispatch, remap, caching
- `src/ipanon/networks.py` — NetworkRegistry for subnet-aware host-bit locking
- `src/ipanon/scanner.py` — Regex IP detection and text replacement
- `src/ipanon/cli.py` — argparse CLI interface

## Commands

```bash
ruff format src/ tests/       # format
ruff check src/ tests/        # lint
pytest tests/                 # test (224 tests)
pre-commit run --all-files    # run all pre-commit hooks
```

## Pre-commit Checks (in order)

**CRITICAL: Always run these checks before any commit:**

1. **Formatting** — `ruff format src/ tests/`
2. **Linting** — `ruff check src/ tests/`
3. **Type checking** — `mypy src/` (configured in pyproject.toml, strict mode)
4. **Tests** — `pytest tests/` (270 tests across 6 test files)
5. **Test coverage verification** — Confirm all 6 test files are running: test_ranges (51), test_permutation (16), test_anonymizer (100), test_scanner (36), test_cli (41), test_networks (26)
6. **All tests must pass** — **CRITICAL**: Fix any failing tests immediately, do not commit/push with failing tests
7. **Final review** — Check `git diff --staged` to review what will be committed
8. **Security check** — Verify no sensitive information (keys, tokens, passwords) is included
9. **Documentation check** — Before committing, verify that all code changes are reflected in the documentation. If new features, options, or behavioral changes are not documented, update the docs in the same commit. Documentation lives in four places:
   - `README.md` — User-facing features, CLI reference table, examples
   - `API.md` — Python API reference
   - `SPEC.md` — Full implementation specification
   - `src/ipanon/cli.py` — `--help` text (argparse help strings)

Note: Steps 1-2 are also enforced by pre-commit hooks (`.pre-commit-config.yaml`), but run them manually to catch issues early.

## Version Management

Version is defined in TWO places that must BOTH be updated together:

1. `pyproject.toml` (`version = "x.y.z"`)
2. `src/ipanon/__init__.py` (`__version__ = "x.y.z"`)

Use **patch** bump for all changes. Include the version bump in the same commit as the code changes. After committing, create a git tag `v{version}`.

## Dependencies

- Python >= 3.9
- No third-party runtime dependencies (stdlib only)
- Dev: `pytest`, `ruff`, `pre-commit`

## PyPI Publishing

Publishing is automated via GitHub Actions (`.github/workflows/publish.yml`). Creating a GitHub Release tagged `v{version}` triggers the workflow, which builds and uploads to PyPI using trusted publishers (OIDC, no tokens needed).
