"""Recursively unpack a file: extract every embedded object, scan it too,
and (optionally) quarantine the payloads it finds.

This turns a single detection into a full investigation tree:

    invoice.pdf
    └── stream (deflate)
        └── Windows PE executable
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from dataclasses import dataclass, field

from .analyzers.base import Analyzer, FileContext
from .analyzers.embedded import carve, _decompress_streams
from .scanner import scan_bytes

MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_ARTIFACTS_PER_LEVEL = 64
MAX_DEPTH = 3

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class Artifact:
    """A file extracted from inside another file."""

    name: str
    data: bytes
    origin: str
    offset: int | None = None
    sha256: str = ""
    ctx: FileContext | None = None
    saved_path: str | None = None
    children: list["Artifact"] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slice_hits(data: bytes, hits: list[tuple[int, str, str]]) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for index, (offset, name, _severity) in enumerate(hits):
        if len(artifacts) >= MAX_ARTIFACTS_PER_LEVEL:
            break
        end = hits[index + 1][0] if index + 1 < len(hits) else len(data)
        end = min(end, offset + MAX_ARTIFACT_BYTES)
        payload = data[offset:end]
        if len(payload) < 16:
            continue
        artifacts.append(
            Artifact(name=f"{name} @0x{offset:x}", data=payload, origin="carved", offset=offset)
        )
    return artifacts


def extract_children(data: bytes, filename: str) -> list[Artifact]:
    """Find every extractable object inside ``data`` (non-recursive)."""
    artifacts: list[Artifact] = []

    skip = set()
    if data.startswith(b"PK\x03\x04"):
        skip.add("ZIP / Office archive")
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        skip.add("OLE / legacy Office document")
    artifacts.extend(_slice_hits(data, carve(data, skip_names=skip)))

    if data.startswith(b"%PDF"):
        decompressed = _decompress_streams(data)
        if decompressed:
            for artifact in _slice_hits(decompressed, carve(decompressed, skip_offset_zero=False)):
                artifact.origin = "pdf-stream"
                artifact.name = f"pdf-stream: {artifact.name}"
                artifacts.append(artifact)

    if data.startswith(b"PK\x03\x04"):
        artifacts.extend(_zip_members(data))

    return artifacts


def _zip_members(data: bytes) -> list[Artifact]:
    artifacts: list[Artifact] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return artifacts
    for member in archive.infolist():
        if member.is_dir() or member.file_size > MAX_ARTIFACT_BYTES:
            continue
        try:
            payload = archive.read(member)
        except (RuntimeError, zipfile.BadZipFile):
            continue
        if not payload:
            continue
        artifacts.append(
            Artifact(name=f"zip-member: {member.filename}", data=payload, origin="zip-member")
        )
        if len(artifacts) >= MAX_ARTIFACTS_PER_LEVEL:
            break
    return artifacts


def _quarantine(artifact: Artifact, quarantine_dir: str) -> None:
    os.makedirs(quarantine_dir, exist_ok=True)
    base = _SAFE_NAME.sub("_", artifact.name)[:60] or "artifact"
    path = os.path.join(quarantine_dir, f"{artifact.sha256[:16]}_{base}.quarantined")
    with open(path, "wb") as handle:
        handle.write(artifact.data)
    artifact.saved_path = path


def build_tree(
    ctx: FileContext,
    analyzers: list[Analyzer],
    max_depth: int = MAX_DEPTH,
    quarantine_dir: str | None = None,
    _depth: int = 1,
    _seen: set[str] | None = None,
) -> list[Artifact]:
    """Recursively extract and scan everything embedded in ``ctx``."""
    if _depth > max_depth:
        return []
    seen = _seen if _seen is not None else set()

    children = extract_children(ctx.data, ctx.filename)
    results: list[Artifact] = []
    for artifact in children:
        artifact.sha256 = _digest(artifact.data)
        if artifact.sha256 in seen:
            continue
        seen.add(artifact.sha256)

        artifact.ctx = scan_bytes(artifact.name, artifact.data, analyzers).ctx
        if quarantine_dir:
            _quarantine(artifact, quarantine_dir)

        if _depth < max_depth:
            artifact.children = build_tree(
                artifact.ctx,
                analyzers,
                max_depth=max_depth,
                quarantine_dir=quarantine_dir,
                _depth=_depth + 1,
                _seen=seen,
            )
        results.append(artifact)
    return results


def count_artifacts(artifacts: list[Artifact]) -> int:
    return sum(1 + count_artifacts(artifact.children) for artifact in artifacts)
