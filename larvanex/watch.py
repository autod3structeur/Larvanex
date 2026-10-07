"""Watch folders and scan files as they appear or change."""

from __future__ import annotations

import os
import time

from rich.console import Console
from rich.text import Text

from .analyzers.base import Analyzer
from .scanner import ScanResult, scan_bytes
from .tui import SEVERITY_STYLE, VERDICT_STYLE
from .utils import format_size

VERDICT_RANK = {"MALICIOUS": 2, "SUSPICIOUS": 1, "LIKELY SAFE": 0}


def _iter_files(targets: list[str]) -> list[str]:
    files: list[str] = []
    for target in targets:
        if os.path.isdir(target):
            for root, _dirs, names in os.walk(target):
                files.extend(os.path.join(root, name) for name in names)
        elif os.path.isfile(target):
            files.append(target)
    return files


def _snapshot(targets: list[str]) -> dict[str, tuple[int, int]]:
    state: dict[str, tuple[int, int]] = {}
    for path in _iter_files(targets):
        try:
            stat = os.stat(path)
        except OSError:
            continue
        state[path] = (int(stat.st_mtime), stat.st_size)
    return state


def _print_alert(console: Console, result: ScanResult) -> None:
    header = Text()
    header.append(" NEW ", style=VERDICT_STYLE.get(result.verdict, "bold"))
    header.append(f"  {result.filename}  ", style="bold")
    header.append(f"{format_size(result.size)}  ", style="dim")
    header.append(f"score {result.score}/100\n", style="dim")
    console.print(header)

    interesting = [
        f for f in result.findings if f.severity not in ("info", "low")
    ]
    for finding in interesting[:6]:
        line = Text("   ")
        line.append(f"[{finding.severity}]", style=SEVERITY_STYLE.get(finding.severity, ""))
        line.append(f" {finding.message}")
        console.print(line)
    if not interesting:
        console.print(Text("   no notable findings", style="dim"))


def watch(
    console: Console,
    targets: list[str],
    analyzers: list[Analyzer],
    interval: float = 2.0,
    decompose: bool = False,
    quarantine_dir: str | None = None,
    max_depth: int = 3,
) -> None:
    console.print(
        Text.assemble(
            ("Larvanex watch\n", "bold"),
            ("Monitoring ", "dim"),
            (", ".join(targets), "cyan"),
            (f"  (every {interval:g}s, Ctrl+C to stop)\n", "dim"),
        )
    )

    state = _snapshot(targets)
    console.print(Text(f"Baseline: {len(state)} file(s) known. Waiting for new activity...\n", style="dim"))

    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "LIKELY SAFE": 0}
    try:
        while True:
            time.sleep(interval)
            current = _snapshot(targets)
            for path, signature in current.items():
                if state.get(path) == signature:
                    continue
                state[path] = signature
                try:
                    with open(path, "rb") as handle:
                        data = handle.read()
                except OSError:
                    continue
                result = scan_bytes(
                    path,
                    data,
                    analyzers,
                    decompose=decompose,
                    quarantine_dir=quarantine_dir,
                    max_depth=max_depth,
                )
                counts[result.verdict] = counts.get(result.verdict, 0) + 1
                _print_alert(console, result)
            state = current
    except KeyboardInterrupt:
        console.print(
            Text(
                f"\nStopped. {counts['MALICIOUS']} malicious, "
                f"{counts['SUSPICIOUS']} suspicious, {counts['LIKELY SAFE']} safe.",
                style="bold",
            )
        )
