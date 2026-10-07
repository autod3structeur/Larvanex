"""Plain-text (colour-free) and JSON renderers."""

from __future__ import annotations

import json

from .attack import label as attack_label
from .scanner import ScanResult
from .utils import format_size

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _artifact_dict(artifact) -> dict:
    data = {
        "name": artifact.name,
        "origin": artifact.origin,
        "size": artifact.size,
        "sha256": artifact.sha256,
    }
    if artifact.offset is not None:
        data["offset"] = artifact.offset
    if artifact.saved_path:
        data["saved_path"] = artifact.saved_path
    if artifact.ctx is not None:
        data["verdict"] = _artifact_verdict(artifact)
    data["children"] = [_artifact_dict(child) for child in artifact.children]
    return data


def _artifact_verdict(artifact) -> str:
    from .scanner import score, verdict

    return verdict(artifact.ctx.findings, score(artifact.ctx.findings))


def result_to_dict(result: ScanResult) -> dict:
    from .scanner import score, verdict

    payload = {
        "file": result.path,
        "size": result.size,
        "score": result.score,
        "verdict": result.verdict,
        "sha256": result.sha256,
        "attack": sorted(result.attack),
        "findings": [finding.to_dict() for finding in result.findings],
    }
    if result.artifacts:
        payload["artifacts"] = [_artifact_dict(artifact) for artifact in result.artifacts]
    return payload


def render_json(results: list[ScanResult]) -> str:
    return json.dumps([result_to_dict(result) for result in results], indent=2)


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    rule = "=" * 64
    lines.append(rule)
    lines.append(f" Larvanex report: {result.filename}")
    lines.append(rule)
    lines.append(f" Path : {result.path}")
    lines.append(f" Size : {format_size(result.size)}")
    lines.append(f" Risk : {result.verdict}  (score {result.score}/100)")
    lines.append(f" Hash : {result.sha256}")
    lines.append("")

    ordered = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for finding in ordered:
        lines.append(f"[{finding.severity.upper():8}] {finding.category}: {finding.message}")
        if finding.detail:
            lines.append(f"           {finding.detail}")
        for technique in finding.attack:
            lines.append(f"           ATT&CK: {attack_label(technique)}")

    if result.attack:
        lines.append("")
        lines.append(" MITRE ATT&CK techniques: " + ", ".join(sorted(result.attack)))

    if result.artifacts:
        lines.append("")
        lines.append(" Embedded artifacts:")
        _append_artifacts(lines, result.artifacts, indent=2)

    lines.append("")
    lines.append("Disclaimer: static analysis only. A 'LIKELY SAFE' verdict is not a guarantee.")
    return "\n".join(lines)


def _append_artifacts(lines: list[str], artifacts: list, indent: int) -> None:
    pad = " " * indent
    for artifact in artifacts:
        suffix = f" -> {artifact.saved_path}" if artifact.saved_path else ""
        lines.append(f"{pad}- {artifact.name} ({artifact.origin}, {format_size(artifact.size)}){suffix}")
        _append_artifacts(lines, artifact.children, indent + 2)


class Reporter:
    def __init__(self, color: bool | None = None):
        self.color = color

    def render_text(self, result: ScanResult) -> str:
        return render_text(result)

    def render_json(self, results: list[ScanResult]) -> str:
        return render_json(results)
