"""Wire the analyzers together and turn their findings into a verdict."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

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
    YaraAnalyzer,
)
from .intel import IntelMesh, LocalBlocklist, MalwareBazaar, VirusTotal

MALICIOUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25


@dataclass
class ScanResult:
    """Everything Larvanex learned about one file."""

    path: str
    ctx: FileContext
    artifacts: list = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return self.ctx.findings

    @property
    def data(self) -> bytes:
        return self.ctx.data

    @property
    def filename(self) -> str:
        return self.ctx.filename

    @property
    def size(self) -> int:
        return self.ctx.size

    @property
    def score(self) -> int:
        return score(self.ctx.findings)

    @property
    def verdict(self) -> str:
        return verdict(self.ctx.findings, self.score)

    @property
    def attack(self) -> set[str]:
        techniques: set[str] = set()
        for finding in self.ctx.findings:
            techniques.update(finding.attack)
        return techniques

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.ctx.data).hexdigest()

    @property
    def max_severity(self) -> str:
        from .analyzers.base import SEVERITIES

        for name in reversed(SEVERITIES):
            if any(finding.severity == name for finding in self.ctx.findings):
                return name
        return "info"


def build_analyzers(
    network: bool = True,
    blocklist_path: str | None = None,
    yara_paths: list[str] | None = None,
) -> list[Analyzer]:
    providers = []
    if blocklist_path:
        providers.append(LocalBlocklist(blocklist_path))
    if network:
        providers.append(MalwareBazaar())
        providers.append(VirusTotal())
    mesh = IntelMesh(providers, network=network)

    return [
        FileTypeAnalyzer(),
        EntropyAnalyzer(),
        StringsAnalyzer(),
        PdfAnalyzer(),
        EmbeddedFileAnalyzer(),
        YaraAnalyzer(extra_paths=yara_paths),
        HashAnalyzer(mesh=mesh),
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


def scan_bytes(
    path: str,
    data: bytes,
    analyzers: list[Analyzer],
    decompose: bool = False,
    quarantine_dir: str | None = None,
    max_depth: int = 3,
) -> ScanResult:
    ctx = FileContext(path=path, data=data)
    for analyzer in analyzers:
        for finding in analyzer.analyze(ctx):
            ctx.add(finding)

    result = ScanResult(path=path, ctx=ctx)
    if decompose:
        from .decompose import build_tree

        result.artifacts = build_tree(
            ctx, analyzers, max_depth=max_depth, quarantine_dir=quarantine_dir
        )
    return result
