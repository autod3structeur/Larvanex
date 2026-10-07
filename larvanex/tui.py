"""Command-centre rendering with `rich`: panels, tables, gauges and a tree."""

from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .analyzers.base import Analyzer
from .attack import label as attack_label
from .attack import matrix
from .scanner import ScanResult, scan_bytes
from .utils import format_size

VERDICT_STYLE = {
    "MALICIOUS": "bold white on red",
    "SUSPICIOUS": "bold black on yellow",
    "LIKELY SAFE": "bold black on green",
}

SEVERITY_STYLE = {
    "critical": "bold magenta",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def make_console(no_color: bool = False) -> Console:
    return Console(no_color=no_color, highlight=False)


def _risk_bar(score: int, width: int = 24) -> Text:
    filled = round(width * score / 100)
    color = "green" if score < 25 else "yellow" if score < 60 else "red"
    bar = Text()
    bar.append("\u2588" * filled, style=color)
    bar.append("\u2591" * (width - filled), style="grey37")
    bar.append(f"  {score}/100", style="bold")
    return bar


def render_result(console: Console, result: ScanResult, show_artifacts: bool = True) -> None:
    header = Text()
    header.append(f"{result.filename}\n", style="bold")
    header.append(f"{result.path}\n", style="dim")
    header.append(f"{format_size(result.size)}   ")
    header.append(f"{result.verdict}", style=VERDICT_STYLE.get(result.verdict, "bold"))
    header.append("\n")
    header.append_text(_risk_bar(result.score))
    header.append(f"\nSHA-256 {result.sha256}", style="dim")

    console.print(Panel(header, title="[bold]Larvanex[/bold]", border_style="grey37"))

    findings_table = Table(show_header=True, header_style="bold", expand=True, pad_edge=False)
    findings_table.add_column("Severity", width=9)
    findings_table.add_column("Check", width=16, style="dim")
    findings_table.add_column("Finding", overflow="fold")
    findings_table.add_column("ATT&CK", width=26, style="dim")
    for finding in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
        attack = ", ".join(tid for tid in finding.attack)
        findings_table.add_row(
            Text(finding.severity, style=SEVERITY_STYLE.get(finding.severity, "")),
            finding.category,
            finding.message,
            attack,
        )
    console.print(findings_table)

    if result.attack:
        attack_table = Table(show_header=True, header_style="bold", expand=True, box=None)
        attack_table.add_column("Tactic", width=22)
        attack_table.add_column("Techniques")
        for _tactic_id, tactic_name, ids in matrix(result.attack):
            if not ids:
                continue
            attack_table.add_row(
                Text(tactic_name, style="bold #a5b4fc"),
                Text("\n".join(attack_label(tid) for tid in ids)),
            )
        console.print(Panel(attack_table, title="[bold]MITRE ATT&CK[/bold]", border_style="grey37"))

    if show_artifacts and result.artifacts:
        console.print(Panel(_artifact_tree(result), title="[bold]Embedded artifacts[/bold]", border_style="grey37"))


def _artifact_tree(result: ScanResult) -> Tree:
    tree = Tree(f"[bold]{result.filename}[/bold] ({result.verdict})")

    def add(node, artifacts):
        for artifact in artifacts:
            verdict = None
            if artifact.ctx is not None:
                from .scanner import score, verdict as verdict_of

                verdict = verdict_of(artifact.ctx.findings, score(artifact.ctx.findings))
            style = "red" if verdict == "MALICIOUS" else "yellow" if verdict == "SUSPICIOUS" else "green"
            label = Text()
            label.append(f"{artifact.name}", style="bold")
            label.append(f"  {artifact.origin}  {format_size(artifact.size)}", style="dim")
            label.append(f"  {verdict}", style=style)
            child = node.add(label)
            add(child, artifact.children)

    add(tree, result.artifacts)
    return tree


def render_summary(console: Console, results: list[ScanResult]) -> None:
    table = Table(title="Scan summary", header_style="bold", expand=True)
    table.add_column("#", width=4, style="dim")
    table.add_column("File", overflow="fold")
    table.add_column("Size", width=9, style="dim")
    table.add_column("Score", width=7, justify="right")
    table.add_column("Verdict", width=14)
    table.add_column("Top finding", overflow="fold", style="dim")
    for index, result in enumerate(sorted(results, key=lambda r: r.score, reverse=True), 1):
        worst = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        top = next((f.message for f in worst if f.severity != "info"), "-")
        table.add_row(
            str(index),
            result.filename,
            format_size(result.size),
            str(result.score),
            Text(result.verdict, style=VERDICT_STYLE.get(result.verdict, "")),
            top,
        )
    console.print(table)

    malicious = sum(1 for r in results if r.verdict == "MALICIOUS")
    suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    safe = sum(1 for r in results if r.verdict == "LIKELY SAFE")
    summary = Text()
    summary.append(f"{len(results)} files   ", style="bold")
    summary.append(f"{malicious} malicious   ", style="bold red")
    summary.append(f"{suspicious} suspicious   ", style="bold yellow")
    summary.append(f"{safe} safe", style="bold green")
    console.print(summary)


def scan_paths(
    console: Console,
    paths: list[str],
    analyzers: list[Analyzer],
    decompose: bool = False,
    quarantine_dir: str | None = None,
    max_depth: int = 3,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning", total=len(paths))
        for path in paths:
            progress.update(task, description=f"Scanning {os.path.basename(path)}")
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError as exc:
                console.print(f"[red]cannot read {path}: {exc}[/red]")
                progress.advance(task)
                continue
            results.append(
                scan_bytes(
                    path,
                    data,
                    analyzers,
                    decompose=decompose,
                    quarantine_dir=quarantine_dir,
                    max_depth=max_depth,
                )
            )
            progress.advance(task)
    return results
