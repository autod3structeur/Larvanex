# Contributing to Larvanex

Thanks for your interest! Larvanex is meant to stay small, readable and
beginner-friendly, so contributions that add a focused check or improve
clarity are very welcome.

## Getting started

```bash
git clone https://github.com/autod3structeur/Larvanex.git
cd Larvanex
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[pdf,dev]"
```

## Running the checks

```bash
pytest -q          # unit tests
make lint          # byte-compile every module
make demo          # generate samples and scan the suspicious ones
```

Please make sure `pytest` passes before opening a pull request. CI runs the
suite on Python 3.9 through 3.13.

## Adding a new analyzer

1. Create `larvanex/analyzers/my_check.py` subclassing `Analyzer`.
2. Return a list of `Finding` objects (see `larvanex/analyzers/base.py`).
3. Register it in `larvanex/scanner.py` → `build_analyzers()`.
4. Add at least one test in `tests/test_larvanex.py`.

```python
from .base import Analyzer, Finding, FileContext

class MyAnalyzer(Analyzer):
    name = "my-check"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        ...
```

## Guidelines

- Keep analyzers side-effect free and fast; never execute scanned content.
- Prefer the standard library. Optional dependencies go in `pyproject.toml`.
- Match the existing style: type hints, docstrings, no dead code.
- One logical change per pull request, with a clear description.

## Reporting bugs

Open an issue using the bug report template. For anything security-sensitive,
follow [SECURITY.md](SECURITY.md) instead.
