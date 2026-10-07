"""Compute file hashes and run them through the threat-intel mesh."""

from __future__ import annotations

import hashlib

from .base import Analyzer, Finding, FileContext
from ..intel import IntelMesh

SEVERITY_BY_STATUS = {
    "malicious": "critical",
    "suspicious": "medium",
}


def hash_file(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class HashAnalyzer(Analyzer):
    name = "hashes"

    def __init__(self, mesh: IntelMesh | None = None):
        self.mesh = mesh

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        digests = hash_file(ctx.data)

        findings.append(
            Finding(
                category=self.name,
                severity="info",
                message=f"SHA-256: {digests['sha256']}",
                detail=f"MD5: {digests['md5']} | SHA-1: {digests['sha1']}",
            )
        )

        if self.mesh is None:
            return findings

        results = self.mesh.query(digests)
        for result in results:
            severity = SEVERITY_BY_STATUS.get(result.status)
            if severity:
                findings.append(
                    Finding(
                        category=f"intel:{result.provider}",
                        severity=severity,
                        message=f"{result.provider}: {result.status.upper()} - {result.detail}",
                        detail="; ".join(result.references),
                        attack=["T1204.002"] if result.is_malicious else [],
                    )
                )
            elif result.status == "error":
                findings.append(
                    Finding(
                        category=f"intel:{result.provider}",
                        severity="info",
                        message=f"{result.provider}: lookup unavailable",
                        detail=result.error or result.detail,
                    )
                )

        status, _score, summary = IntelMesh.consensus(results)
        if status == "clean":
            findings.append(
                Finding(
                    category="intel:consensus",
                    severity="info",
                    message="Threat intelligence: no known detections",
                    detail=summary,
                )
            )
        return findings
