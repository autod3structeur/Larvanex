"""Small helpers shared across analyzers."""

from __future__ import annotations

import math
import re

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0-8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def sliding_entropy(data: bytes, window: int = 256, step: int = 256) -> list[tuple[int, float]]:
    """Return (offset, entropy) pairs for every ``window`` chunk of ``data``."""
    results: list[tuple[int, float]] = []
    for offset in range(0, max(len(data) - window + 1, 1), step):
        chunk = data[offset : offset + window]
        if len(chunk) < window:
            break
        results.append((offset, shannon_entropy(chunk)))
    return results


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings and snippets of UTF-16 text."""
    strings: list[str] = []
    for match in PRINTABLE_RE.finditer(data):
        if len(match.group()) >= min_length:
            strings.append(match.group().decode("ascii", "ignore"))
    for match in UTF16_RE.finditer(data):
        decoded = match.group().decode("utf-16-le", "ignore")
        if len(decoded) >= min_length:
            strings.append(decoded)
    return strings


def find_signatures(data: bytes, signatures: dict[bytes, str]) -> list[tuple[int, str]]:
    """Return every (offset, name) where a magic-byte signature appears."""
    hits: list[tuple[int, str]] = []
    for signature, name in signatures.items():
        start = 0
        while True:
            index = data.find(signature, start)
            if index == -1:
                break
            hits.append((index, name))
            start = index + 1
    hits.sort()
    return hits


def format_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024
    return f"{num_bytes} B"
