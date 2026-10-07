"""Render scan results as a colourful terminal report or JSON."""

from __future__ import annotations

import json
import sys

from .analyzers import FileContext
from .utils import format_size

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

COLORS = {
    "critical": "\033[1;35m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[36m",
    "info": "\033[2;37m",
}

VERDICT_COLORS = {
    "MALICIOUS": "\033[1;41;97m",
    "SUSPICIOUS": "\033[1;43;30m",
    "LIKELY SAFE": "\033[1;42;30m",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _supports_color() -> bool:
    return sys.stdout.isatty()


class Reporter:
    def __init__(self, color: bool | None = None):
        self.color = _supports_color() if color is None else color

    def _c(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return f"{code}{text}{RESET}"

    def render_text(self, ctx: FileContext, total: int, verdict: str) -> str:
        lines: list[str] = []
        rule = "=" * 64
        lines.append(self._c(rule, BOLD))
        lines.append(self._c(f" Larvanex report: {ctx.filename}", BOLD))
        lines.append(self._c(rule, BOLD))
        lines.append(f" Path : {ctx.path}")
        lines.append(f" Size : {format_size(ctx.size)}")
        verdict_text = self._c(f" {verdict} ", VERDICT_COLORS.get(verdict, BOLD))
        lines.append(f" Risk : {verdict_text}  (score {total}/100)")
        lines.append("")

        ordered = sorted(ctx.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        for finding in ordered:
            tag = self._c(f"[{finding.severity.upper():8}]", COLORS.get(finding.severity, ""))
            lines.append(f"{tag} {self._c(finding.category, BOLD)}: {finding.message}")
            if finding.detail:
                lines.append(f"           {self._c(finding.detail, DIM)}")
        lines.append("")
        lines.append(self._c("Disclaimer: static analysis only. A 'LIKELY SAFE' verdict is not a guarantee.", DIM))
        return "\n".join(lines)

    def render_json(self, ctx: FileContext, total: int, verdict: str) -> str:
        payload = {
            "file": ctx.path,
            "size": ctx.size,
            "score": total,
            "verdict": verdict,
            "findings": [finding.to_dict() for finding in ctx.findings],
        }
        return json.dumps(payload, indent=2)
