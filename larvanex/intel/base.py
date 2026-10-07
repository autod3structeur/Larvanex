"""Threat-intelligence providers and the mesh that aggregates them."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IntelResult:
    """The outcome of one provider querying one file's hashes."""

    provider: str
    status: str  # malicious | suspicious | clean | unknown | error
    score: int  # 0-100 confidence that the file is bad
    detail: str = ""
    references: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_malicious(self) -> bool:
        return self.status == "malicious"

    @property
    def is_suspicious(self) -> bool:
        return self.status == "suspicious"

    def to_dict(self) -> dict:
        data = {
            "provider": self.provider,
            "status": self.status,
            "score": self.score,
            "detail": self.detail,
        }
        if self.references:
            data["references"] = self.references
        if self.error:
            data["error"] = self.error
        return data


class IntelProvider:
    """Base class for every threat-intel source."""

    name = "provider"
    requires_network = True

    def available(self) -> bool:
        return True

    def query(self, digests: dict[str, str]) -> IntelResult:
        raise NotImplementedError
