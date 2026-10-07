# Larvanex

[![CI](https://github.com/autod3structeur/Larvanex/actions/workflows/ci.yml/badge.svg)](https://github.com/autod3structeur/Larvanex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Dependencies: none](https://img.shields.io/badge/dependencies-none-success.svg)](#install)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> **Beginner-friendly static malware triage.** Point Larvanex at a suspicious file and it tells you whether it *looks* safe, suspicious, or malicious — and exactly why.

Larvanex was built around one very common attack: an attacker hides a malicious payload inside an innocent-looking file — a PDF, an Office document, an archive or an image. Larvanex digs it out.

It never executes what it scans. Everything is static analysis.

---

## Table of contents

- [Why this project exists](#why-this-project-exists)
- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [How the verdict is calculated](#how-the-verdict-is-calculated)
- [Project structure](#project-structure)
- [Writing your own analyzer](#writing-your-own-analyzer)
- [Development](#development)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Why this project exists

Attackers rarely send you `virus.exe`. They send you `Invoice_2026.pdf` that secretly contains:

- a **JavaScript** action that fires the moment you open it,
- an **embedded executable** hidden inside a compressed stream,
- a **macro** that downloads the real payload, or
- an **executable renamed** to look like a document (`invoice.pdf.exe`).

Larvanex checks for all of these in a single pass, using readable rules — which makes it a good way to learn how malware triage actually works.

---

## Features

| Check | What it does |
| --- | --- |
| **File type / magic bytes** | Reveals the *real* type of a file and flags extension mismatches (`.pdf` that is actually a Windows executable) and double extensions (`invoice.pdf.exe`). |
| **Embedded file scanner** | Carves out files hidden inside other files: executables inside PDF streams, dangerous members inside ZIP/Office files, VBA macros, and zip bombs. |
| **Entropy analysis** | Measures randomness to find encrypted or packed payloads hiding inside a file. |
| **Suspicious strings** | Greps for `powershell`, `cmd.exe`, `certutil`, `/JavaScript`, `/Launch`, Base64 blobs, and download URLs. |
| **PDF structure checks** | Inspects `/OpenAction`, `/Launch`, `/EmbeddedFile`, hex-obfuscated names, and incremental updates. |
| **SHA-256 + lookup** | Computes MD5/SHA-1/SHA-256, checks an optional local blocklist, and queries the [MalwareBazaar](https://bazaar.abuse.ch/) database. |

Output is available as a **colourful terminal report** or **machine-readable JSON**, and the process exit code is CI-friendly.

---

## Install

Larvanex runs on **Python 3.9+** with **no required dependencies**.

```bash
git clone https://github.com/autod3structeur/Larvanex.git
cd Larvanex

# Optional but recommended: a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install the CLI (pypdf enables deeper PDF parsing)
pip install -e ".[pdf]"
```

Prefer not to install anything? Run it in place:

```bash
python -m larvanex --help
```

---

## Quick start

Generate a set of safe, synthetic sample files to play with:

```bash
python samples/generate_samples.py
```

Scan a single file:

```bash
larvanex samples/suspicious/hidden_payload.pdf
```

Scan a whole folder (recursively):

```bash
larvanex -r samples/suspicious
```

Emit a JSON report for scripting or CI:

```bash
larvanex --json samples/suspicious/invoice.pdf.exe
```

Stay fully offline (skip the MalwareBazaar lookup):

```bash
larvanex --no-network samples/suspicious/dropper.zip
```

Check a hash against your own list of known-bad hashes:

```bash
larvanex --blocklist blocklist.txt suspicious.bin
```

### Example output

```text
================================================================
 Larvanex report: hidden_payload.pdf
================================================================
 Path : samples/suspicious/hidden_payload.pdf
 Size : 106 B
 Risk :  MALICIOUS   (score 60/100)

[CRITICAL] embedded: Embedded Windows PE executable recovered from a PDF stream
           Hidden payload decompressed from inside the PDF.
[INFO    ] file-type: Detected type: PDF document
           Consistent with the .pdf extension.
[INFO    ] hashes: SHA-256: c23ebdef91285b5056781a27774467daa87e519e28098dfc1283c407089328cd

Disclaimer: static analysis only. A 'LIKELY SAFE' verdict is not a guarantee.
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Likely safe |
| `1` | Suspicious |
| `2` | Malicious, or an error occurred |

Use the exit code in scripts, hooks or CI pipelines to block suspicious files.

---

## How the verdict is calculated

Every finding carries a severity, and each severity has a weight:

| Severity | Weight |
| --- | --- |
| critical | 60 |
| high | 30 |
| medium | 15 |
| low | 5 |
| info | 0 |

Weights are summed and capped at 100. Any `critical` finding, or a total ≥ 60, is **MALICIOUS**; a total ≥ 25 is **SUSPICIOUS**; otherwise **LIKELY SAFE**. Thresholds live in `larvanex/scanner.py`.

Analyzers run in order, each reading the same immutable `FileContext` and adding `Finding`s:

```
file → FileTypeAnalyzer → EntropyAnalyzer → StringsAnalyzer
     → PdfAnalyzer → EmbeddedFileAnalyzer → HashAnalyzer → score → verdict
```

---

## Project structure

```text
Larvanex/
├── larvanex/
│   ├── analyzers/
│   │   ├── base.py        # Finding, FileContext, Analyzer base class
│   │   ├── filetype.py    # magic bytes + extension mismatch
│   │   ├── entropy.py     # randomness detection
│   │   ├── strings.py     # suspicious keywords / URLs / base64
│   │   ├── pdf.py         # PDF structure analysis
│   │   ├── embedded.py    # hidden files, macros, zip bombs
│   │   └── hashes.py      # hashes + MalwareBazaar lookup
│   ├── scanner.py         # runs analyzers, scores, verdict
│   ├── report.py          # text / JSON output
│   ├── utils.py           # entropy, string extraction helpers
│   └── cli.py             # command line interface
├── samples/generate_samples.py
├── tests/test_larvanex.py
├── .github/workflows/ci.yml
└── pyproject.toml
```

---

## Writing your own analyzer

Adding a check takes about 20 lines. Each analyzer returns a list of `Finding`s:

```python
from .base import Analyzer, Finding, FileContext

class MyAnalyzer(Analyzer):
    name = "my-check"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        if b"definitely_bad" in ctx.data:
            return [Finding(
                category=self.name,
                severity="high",
                message="Found definitely_bad marker",
            )]
        return []
```

Then register it in `larvanex/scanner.py` → `build_analyzers()`, and add a test.

---

## Development

```bash
pip install -e ".[pdf,dev]"

make test     # run the test suite
make lint     # byte-compile every module
make demo     # generate samples and scan the suspicious ones
make help     # list all targets
```

The tests build synthetic files in memory, so they need no network and no real malware. CI runs them on Python 3.9–3.13.

---

## Roadmap

- [ ] VirusTotal / Hybrid Analysis integration
- [ ] YARA rule support
- [ ] Recursive scan of files extracted from containers
- [ ] HTML report with extracted-payload previews
- [ ] Office macro (OLE/VBA) deobfuscation

---

## Disclaimer

Larvanex performs **static** analysis only and relies on heuristic rules. A "LIKELY SAFE" result does **not** guarantee a file is harmless, and a "SUSPICIOUS" result is not proof of malware. Always combine it with antivirus, sandboxing, and common sense.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Security Policy](SECURITY.md) first. For security-sensitive reports, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

[MIT](LICENSE)
