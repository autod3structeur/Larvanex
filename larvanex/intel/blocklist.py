"""Check file hashes against a local, user-supplied blocklist."""

from __future__ import annotations

import os

from .base import IntelProvider, IntelResult


class LocalBlocklist(IntelProvider):
    name = "blocklist"
    requires_network = False

    def __init__(self, path: str):
        self.path = path
        self._known: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self.path or not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                self._known = {
                    line.strip().lower()
                    for line in handle
                    if line.strip() and not line.lstrip().startswith("#")
                }
        except OSError:
            self._known = set()

    def available(self) -> bool:
        return bool(self._known)

    def query(self, digests: dict[str, str]) -> IntelResult:
        for kind, value in digests.items():
            if value in self._known:
                return IntelResult(
                    provider=self.name,
                    status="malicious",
                    score=100,
                    detail=f"{kind.upper()} match in {self.path}",
                )
        return IntelResult(
            provider=self.name,
            status="clean",
            score=0,
            detail="Not present in the local blocklist",
        )
