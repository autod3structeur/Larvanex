"""The heart of Larvanex: find files hidden inside other files.

This covers the classic "malicious file inside a PDF" case, macro-laden
Office documents, archives containing executables, and zip bombs."""

from __future__ import annotations

import io
import re
import zipfile

from .base import Analyzer, Finding, FileContext

EMBEDDED_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "Windows PE executable", "critical"),
    (b"PK\x03\x04", "ZIP / Office archive", "high"),
    (b"%PDF", "PDF document", "medium"),
    (b"\x7fELF", "Linux ELF executable", "critical"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE / legacy Office document", "high"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "info"),
    (b"\xff\xd8\xff", "JPEG image", "info"),
    (b"Rar!\x1a\x07", "RAR archive", "high"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "high"),
    (b"\x1f\x8b\x08", "GZIP archive", "medium"),
]

DANGEROUS_MEMBER_EXT = {
    "exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "lnk", "reg", "jar", "apk", "msi",
    "so", "elf",
}

STREAM_RE = re.compile(rb"stream\r?\n")
WHITESPACE = b"\x00\t\n\r\x0c "


def _find_pe(data: bytes, start: int) -> bool:
    header = data[start : start + 0x400]
    return b"PE\x00\x00" in header


def carve(
    data: bytes,
    skip_offset_zero: bool = True,
    skip_names: set[str] | None = None,
) -> list[tuple[int, str, str]]:
    """Locate embedded file signatures inside ``data``."""
    hits: list[tuple[int, str, str]] = []
    seen: set[tuple[str, int]] = set()
    skip_names = skip_names or set()
    for signature, name, severity in EMBEDDED_SIGNATURES:
        if name in skip_names:
            continue
        start = 0
        while True:
            index = data.find(signature, start)
            if index == -1:
                break
            start = index + 1
            if skip_offset_zero and index == 0:
                continue
            if signature == b"MZ" and not _find_pe(data, index):
                continue
            key = (name, index)
            if key in seen:
                continue
            seen.add(key)
            hits.append((index, name, severity))
    hits.sort()
    return hits


def _decompress_streams(data: bytes) -> bytes:
    """Return the concatenation of all FlateDecode streams found in a PDF."""
    import zlib

    output = bytearray()
    for match in STREAM_RE.finditer(data):
        body_start = match.end()
        body_end = data.find(b"endstream", body_start)
        if body_end == -1:
            continue
        raw = data[body_start:body_end].rstrip(WHITESPACE)
        try:
            output.extend(zlib.decompress(raw))
        except zlib.error:
            try:
                output.extend(zlib.decompressobj().decompress(raw))
            except zlib.error:
                continue
    return bytes(output)


class EmbeddedFileAnalyzer(Analyzer):
    name = "embedded"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        if ctx.extension in {"zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "ods", "odp", "epub"} or ctx.data.startswith(b"PK\x03\x04"):
            self._scan_zip(ctx, findings)

        self._scan_carved(ctx, findings)

        if ctx.data.startswith(b"%PDF"):
            self._scan_pdf_streams(ctx, findings)

        return findings

    def _scan_carved(self, ctx: FileContext, findings: list[Finding]) -> None:
        limit = 4 * 1024 * 1024
        region = ctx.data[:limit]
        skip_names: set[str] = set()
        if ctx.data.startswith(b"PK\x03\x04"):
            skip_names.add("ZIP / Office archive")
        if ctx.data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            skip_names.add("OLE / legacy Office document")
        for offset, name, severity in carve(region, skip_names=skip_names):
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"Embedded {name} found at offset 0x{offset:x}",
                    detail="A file hidden inside another file. Extract and inspect it.",
                    offset=offset,
                )
            )
        if len(ctx.data) > limit:
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message=f"Embedded scan limited to first {limit // (1024 * 1024)} MB",
                    detail="Large file: later regions were skipped.",
                )
            )

    def _scan_zip(self, ctx: FileContext, findings: list[Finding]) -> None:
        try:
            archive = zipfile.ZipFile(io.BytesIO(ctx.data))
        except zipfile.BadZipFile:
            return

        members = archive.infolist()
        total_compressed = sum(m.compress_size for m in members) or 1
        total_uncompressed = sum(m.file_size for m in members)

        for member in members:
            extension = member.filename.rsplit(".", 1)[-1].lower() if "." in member.filename else ""
            if extension in DANGEROUS_MEMBER_EXT:
                findings.append(
                    Finding(
                        category=self.name,
                        severity="high",
                        message=f"Archive contains executable member: {member.filename}",
                        detail="Executables/scripts inside a document or archive are a red flag.",
                    )
                )
            if member.filename.lower().endswith("vbaproject.bin"):
                findings.append(
                    Finding(
                        category=self.name,
                        severity="high",
                        message="VBA macro project found in Office document",
                        detail="Macros can run automatically and download malware.",
                    )
                )

        if total_uncompressed > 0 and total_uncompressed / total_compressed > 100:
            findings.append(
                Finding(
                    category=self.name,
                    severity="high",
                    message=f"Possible zip bomb (ratio {total_uncompressed / total_compressed:.0f}:1)",
                    detail="Extremely high compression ratio, often used to exhaust resources.",
                )
            )

        if not any(f.category == self.name for f in findings):
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message=f"Archive inspected: {len(members)} member(s), no dangerous content",
                )
            )

    def _scan_pdf_streams(self, ctx: FileContext, findings: list[Finding]) -> None:
        decompressed = _decompress_streams(ctx.data)
        if not decompressed:
            return
        for offset, name, severity in carve(decompressed, skip_offset_zero=False):
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"Embedded {name} recovered from a PDF stream",
                    detail="Hidden payload decompressed from inside the PDF.",
                    offset=offset,
                )
            )
