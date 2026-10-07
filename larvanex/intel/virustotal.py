"""VirusTotal file hash lookup.

Docs: https://docs.virustotal.com/reference/file-info
Needs a free API key in VT_API_KEY.
"""

from __future__ import annotations

import os

from .base import IntelProvider, IntelResult
from .http import describe_error, request_json

API_URL = "https://www.virustotal.com/api/v3/files/"


class VirusTotal(IntelProvider):
    name = "virustotal"

    def __init__(self, api_key: str | None = None, timeout: int = 10):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.api_key)

    def query(self, digests: dict[str, str]) -> IntelResult:
        if not self.api_key:
            return IntelResult(
                provider=self.name,
                status="unknown",
                score=0,
                detail="No API key configured",
                error="set VT_API_KEY to enable VirusTotal",
            )
        sha256 = digests["sha256"]
        try:
            result = request_json(
                API_URL + sha256,
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )
        except Exception as exc:  # noqa: BLE001
            return IntelResult(
                provider=self.name,
                status="error",
                score=0,
                detail="Lookup unavailable",
                error=describe_error(exc),
            )

        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        engines = malicious + suspicious + harmless + undetected
        reference = f"https://www.virustotal.com/gui/file/{sha256}"

        if malicious or suspicious:
            score = min(100, round(100 * (malicious + 0.5 * suspicious) / max(engines, 1)))
            status = "malicious" if malicious >= 3 else "suspicious"
            return IntelResult(
                provider=self.name,
                status=status,
                score=max(score, 60 if status == "malicious" else 30),
                detail=f"{malicious} malicious / {suspicious} suspicious out of {engines} engines",
                references=[reference],
            )
        return IntelResult(
            provider=self.name,
            status="clean",
            score=0,
            detail=f"0 detections out of {engines} engines",
            references=[reference],
        )
