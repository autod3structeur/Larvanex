"""Compute file hashes, check an optional local blocklist, and look the
SHA-256 up in the MalwareBazaar malware database."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .base import Analyzer, Finding, FileContext

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"


def hash_file(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class HashAnalyzer(Analyzer):
    name = "hashes"

    def __init__(self, network: bool = True, blocklist_path: str | None = None, timeout: int = 10):
        self.network = network
        self.blocklist_path = blocklist_path
        self.timeout = timeout

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

        if self.blocklist_path and os.path.isfile(self.blocklist_path):
            if self._in_blocklist(digests):
                findings.append(
                    Finding(
                        category=self.name,
                        severity="critical",
                        message="Hash matches the local malware blocklist",
                        detail=f"Found in {self.blocklist_path}",
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=self.name,
                        severity="info",
                        message="Hash not present in local blocklist",
                    )
                )

        if self.network:
            findings.append(self._query_malwarebazaar(digests["sha256"]))

        return findings

    def _in_blocklist(self, digests: dict[str, str]) -> bool:
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as handle:
                known = {line.strip().lower() for line in handle if line.strip() and not line.startswith("#")}
        except OSError:
            return False
        return any(value in known for value in digests.values())

    def _query_malwarebazaar(self, sha256: str) -> Finding:
        payload = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        headers = {"User-Agent": "Larvanex/1.0", "Content-Type": "application/x-www-form-urlencoded"}
        api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
        if api_key:
            headers["Auth-Key"] = api_key

        request = urllib.request.Request(MALWAREBAZAAR_URL, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8", "ignore"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return Finding(
                category=self.name,
                severity="info",
                message="MalwareBazaar lookup unavailable (offline?)",
                detail=str(exc),
            )

        status = result.get("query_status")
        if status == "ok" and result.get("data"):
            info = result["data"][0]
            signature = info.get("signature") or "unknown family"
            file_type = info.get("file_type") or "unknown type"
            return Finding(
                category=self.name,
                severity="critical",
                message=f"Known malware in MalwareBazaar: {signature} ({file_type})",
                detail=f"First seen: {info.get('first_seen', 'n/a')}",
            )
        if status == "hash_not_found":
            return Finding(
                category=self.name,
                severity="info",
                message="SHA-256 not found in MalwareBazaar",
                detail="Not conclusive - new/unique malware will not be listed.",
            )
        return Finding(
            category=self.name,
            severity="info",
            message=f"MalwareBazaar returned: {status or 'unknown response'}",
            detail="Set MALWAREBAZAAR_API_KEY for reliable results.",
        )
