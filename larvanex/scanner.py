"""Wire the analyzers together and turn their findings into a verdict."""

from __future__ import annotations

from .analyzers import (
    Analyzer,
    EmbeddedFileAnalyzer,
    EntropyAnalyzer,
    FileTypeAnalyzer,
    FileContext,
    Finding,
    HashAnalyzer,
    PdfAnalyzer,
    StringsAnalyzer,
    SEVERITY_WEIGHT,
)

MALICIOUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25


def build_analyzers(network: bool = True, blocklist_path: str | None = None) -> list[Analyzer]:
    return [
        FileTypeAnalyzer(),
        EntropyAnalyzer(),
        StringsAnalyzer(),
        PdfAnalyzer(),
        EmbeddedFileAnalyzer(),
        HashAnalyzer(network=network, blocklist_path=blocklist_path),
    ]


def score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[finding.severity] for finding in findings))


def verdict(findings: list[Finding], total: int) -> str:
    if any(finding.severity == "critical" for finding in findings):
        return "MALICIOUS"
    if total >= MALICIOUS_THRESHOLD:
        return "MALICIOUS"
    if total >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LIKELY SAFE"


def scan_bytes(path: str, data: bytes, analyzers: list[Analyzer]) -> FileContext:
    ctx = FileContext(path=path, data=data)
    for analyzer in analyzers:
        for finding in analyzer.analyze(ctx):
            ctx.add(finding)
    return ctx
