# Larvanex

**Beginner-friendly static malware triage.** Drop a suspicious file into Larvanex and it tells you whether it *looks* safe, suspicious, or malicious — and exactly why.

Larvanex was built around one common attack: an attacker hides a malicious payload inside an innocent-looking file (a PDF, an Office document, an archive, an image). Larvanex digs it out.

> This is a defensive security tool. It never executes the file it scans. Everything is static analysis.

---

## Why this project exists

Attackers rarely send you `virus.exe`. They send you `Invoice_2026.pdf` that secretly contains:

- a **JavaScript** action that runs the moment you open it,
- an **embedded executable** hidden inside a compressed stream,
- a **macro** that downloads the real payload,
- or an **executable renamed** to look like a document (`.pdf.exe`).

Larvanex checks for all of these in one pass.

---

## Features

| Check | What it does |
| --- | --- |
| **File type / magic bytes** | Reveals the *real* type of a file and flags extension mismatches (`.pdf` that is actually a Windows executable) and double extensions (`invoice.pdf.exe`). |
| **Embedded file scanner** | Carves out files hidden inside other files: executables inside PDF streams, dangerous members inside ZIP/Office files, VBA macros, and zip bombs. |
| **Entropy analysis** | Measures randomness to find encrypted or packed payloads hiding inside a file. |
| **Suspicious strings** | Greps for `powershell`, `cmd.exe`, `certutil`, `/JavaScript`, `/Launch`, Base64 blobs, download URLs and more. |
| **PDF structure checks** | Inspects `/OpenAction`, `/Launch`, `/EmbeddedFile`, hex-obfuscated names and incremental updates. |
| **SHA-256 + lookup** | Computes MD5/SHA-1/SHA-256, checks an optional local blocklist, and queries the [MalwareBazaar](https://bazaar.abuse.ch/) database. |

All checks are rule-based and readable — perfect for learning how malware triage actually works.

---

## Install

Larvanex works on Python 3.9+ with **no required dependencies**.

```bash
git clone https://github.com/your-username/Larvanex.git
cd Larvanex

# Optional but recommended: a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Core tool (pypdf adds deeper PDF parsing)
pip install -e ".[pdf]"
```

Or just run it in place with no install:

```bash
python -m larvanex --help
```

---

## Quick start

Generate a set of safe sample files to try it on:

```bash
python samples/generate_samples.py
```

Scan one file:

```bash
larvanex samples/suspicious/hidden_payload.pdf
```

Scan everything in a folder:

```bash
larvanex -r samples/suspicious
```

Machine-readable output (handy for scripting / CI):

```bash
larvanex --json samples/suspicious/invoice.pdf.exe
```

Skip the online lookup (fully offline):

```bash
larvanex --no-network samples/suspicious/dropper.zip
```

### Example output

```
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
[INFO    ] hashes: SHA-256: c23e...

Disclaimer: static analysis only. A 'LIKELY SAFE' verdict is not a guarantee.
```

### Exit codes (for CI)

| Code | Meaning |
| --- | --- |
| `0` | Likely safe |
| `1` | Suspicious |
| `2` | Malicious / error |

---

## How the verdict is calculated

Every finding has a severity with a weight:

| Severity | Weight |
| --- | --- |
| critical | 60 |
| high | 30 |
| medium | 15 |
| low | 5 |
| info | 0 |

The weights are summed and capped at 100. Any `critical` finding, or a total ≥ 60, means **MALICIOUS**; ≥ 25 means **SUSPICIOUS**; otherwise **LIKELY SAFE**. Tune the thresholds in `larvanex/scanner.py`.

---

## Project structure

```
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

Then register it in `larvanex/scanner.py` → `build_analyzers()`.

---

## Running the tests

```bash
pip install pytest
pytest -q
```

The tests build synthetic files in memory, so they need no network and no real malware.

---

## Roadmap / ideas

- [ ] VirusTotal / hybrid-analysis integration
- [ ] YARA rule support
- [ ] Recursive scan of files extracted from containers
- [ ] HTML report with extracted-payload previews
- [ ] Office macro (OLE/VBA) deobfuscation

---

## Disclaimer

Larvanex performs **static** analysis only and uses heuristic rules. A "LIKELY SAFE" result does **not** guarantee a file is harmless, and a "SUSPICIOUS" result is not proof of malware. Always combine it with antivirus, sandboxing, and common sense.

## License

[MIT](LICENSE)
