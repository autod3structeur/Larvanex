"""Aggregate several threat-intel providers into one consensus lookup."""

from __future__ import annotations

from .base import IntelProvider, IntelResult


class IntelMesh:
    """Runs every available provider and merges their verdicts."""

    def __init__(self, providers: list[IntelProvider], network: bool = True):
        self.providers = providers
        self.network = network

    def query(self, digests: dict[str, str]) -> list[IntelResult]:
        results: list[IntelResult] = []
        for provider in self.providers:
            if provider.requires_network and not self.network:
                continue
            if not provider.available():
                continue
            results.append(provider.query(digests))
        return results

    @staticmethod
    def consensus(results: list[IntelResult]) -> tuple[str, int, str]:
        """Return (status, score, summary) across all results."""
        if not results:
            return "unknown", 0, "No threat-intelligence providers available"

        malicious = [r for r in results if r.is_malicious]
        suspicious = [r for r in results if r.is_suspicious]
        if malicious:
            sources = ", ".join(r.provider for r in malicious)
            top = max(malicious, key=lambda r: r.score)
            return "malicious", 100, f"Flagged malicious by {sources} - {top.detail}"
        if suspicious:
            sources = ", ".join(r.provider for r in suspicious)
            top = max(suspicious, key=lambda r: r.score)
            return "suspicious", top.score, f"Flagged suspicious by {sources} - {top.detail}"

        clean = [r for r in results if r.status == "clean"]
        if clean:
            return "clean", 0, f"Clean across {len(clean)} provider(s)"
        return "unknown", 0, "No provider returned a verdict"
