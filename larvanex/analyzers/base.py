"""Core types shared by every Larvanex analyzer."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")

SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 60,
}


@dataclass
class Finding:
    """A single observation reported by an analyzer."""

    category: str
    severity: str
    message: str
    detail: str = ""
    offset: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")

    def to_dict(self) -> dict:
        data = {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
        }
        if self.detail:
            data["detail"] = self.detail
        if self.offset is not None:
            data["offset"] = self.offset
        return data


@dataclass
class FileContext:
    """Immutable view of the file handed to every analyzer."""

    path: str
    data: bytes
    findings: list[Finding] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def filename(self) -> str:
        return os.path.basename(self.path)

    @property
    def extension(self) -> str:
        return os.path.splitext(self.path)[1].lower().lstrip(".")

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


class Analyzer:
    """Base class every analyzer must implement."""

    name = "base"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        raise NotImplementedError
