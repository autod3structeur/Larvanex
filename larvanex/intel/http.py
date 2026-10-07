"""Tiny HTTP helper shared by the network-backed intel providers."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "Larvanex/2.0 (+https://github.com/autod3structeur/Larvanex)"


def request_json(
    url: str,
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict:
    """Perform a GET (or POST when ``data`` is set) and parse a JSON response."""
    merged = {"User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)

    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        merged.setdefault("Content-Type", "application/x-www-form-urlencoded")

    request = urllib.request.Request(url, data=body, headers=merged)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "ignore"))


def describe_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code} from server"
    if isinstance(exc, urllib.error.URLError):
        return f"network error: {exc.reason}"
    return str(exc)
