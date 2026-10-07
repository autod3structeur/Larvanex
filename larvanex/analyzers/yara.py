"""Run YARA rules against the file. YARA is optional; install the `yara` extra."""

from __future__ import annotations

import os

from .base import Analyzer, Finding, FileContext

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def collect_rule_files(paths: list[str]) -> list[str]:
    collected: list[str] = []
    for path in paths:
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if name.endswith((".yar", ".yara")):
                    collected.append(os.path.join(path, name))
        elif os.path.isfile(path):
            collected.append(path)
    return collected


class YaraAnalyzer(Analyzer):
    name = "yara"

    def __init__(self, extra_paths: list[str] | None = None):
        self.rules = None
        self.error: str | None = None
        self.rule_count = 0
        self._load(extra_paths or [])

    def _load(self, extra_paths: list[str]) -> None:
        try:
            import yara  # type: ignore
        except ImportError:
            self.error = "yara-python not installed (pip install 'larvanex[yara]')"
            return

        files = collect_rule_files([RULES_DIR, *extra_paths])
        if not files:
            self.error = "no YARA rules found"
            return
        try:
            self.rules = yara.compile(filepaths={f"ns{index}": path for index, path in enumerate(files)})
            self.rule_count = len(files)
        except Exception as exc:  # noqa: BLE001 - malformed rule files
            self.error = f"could not compile YARA rules: {exc}"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        if self.rules is None:
            return [
                Finding(
                    category=self.name,
                    severity="info",
                    message="YARA scanning skipped",
                    detail=self.error or "rules unavailable",
                )
            ]

        try:
            matches = self.rules.match(data=ctx.data, timeout=10)
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    category=self.name,
                    severity="info",
                    message="YARA scan failed",
                    detail=str(exc),
                )
            ]

        findings: list[Finding] = []
        for match in matches:
            meta = match.meta or {}
            severity = str(meta.get("severity", "medium")).lower()
            description = meta.get("description", match.rule)
            attack = [tag.strip() for tag in str(meta.get("attack", "")).split(",") if tag.strip()]
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"YARA match: {match.rule}",
                    detail=description,
                    attack=attack,
                )
            )
        if not findings:
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message="No YARA rules matched",
                )
            )
        return findings
