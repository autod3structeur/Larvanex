"""Detect the real type of a file from its magic bytes and compare it
against the extension the file claims to have."""

from __future__ import annotations

from .base import Analyzer, Finding, FileContext

SIGNATURES: list[tuple[bytes, str, set[str]]] = [
    (b"MZ", "Windows PE executable", {"exe", "dll", "sys", "scr", "com", "cpl", "ocx", "efi"}),
    (b"\x7fELF", "Linux ELF executable", {"so", "elf", "bin", "o"}),
    (b"%PDF", "PDF document", {"pdf"}),
    (b"PK\x03\x04", "ZIP archive", {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "epub", "whl"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE / legacy Office document", {"doc", "xls", "ppt", "msi", "msg"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {"png"}),
    (b"\xff\xd8\xff", "JPEG image", {"jpg", "jpeg"}),
    (b"GIF87a", "GIF image", {"gif"}),
    (b"GIF89a", "GIF image", {"gif"}),
    (b"BM", "BMP image", {"bmp"}),
    (b"II*\x00", "TIFF image", {"tif", "tiff"}),
    (b"MM\x00*", "TIFF image", {"tif", "tiff"}),
    (b"Rar!\x1a\x07", "RAR archive", {"rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {"7z"}),
    (b"\x1f\x8b", "GZIP archive", {"gz", "tgz"}),
    (b"BZh", "BZIP2 archive", {"bz2"}),
    (b"\xfd7zXZ\x00", "XZ archive", {"xz"}),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O binary", {"class", "jar"}),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable", {"macho", "dylib"}),
    (b"\xfe\xed\xfa\xce", "Mach-O executable", {"macho", "dylib"}),
    (b"!<arch>", "Unix ar archive", {"a", "deb"}),
    (b"OggS", "Ogg media", {"ogg", "oga", "ogv"}),
    (b"ID3", "MP3 audio", {"mp3"}),
    (b"RIFF", "RIFF container (WAV/AVI/WEBP)", {"wav", "avi", "webp"}),
    (b"\x00\x00\x01\x00", "Windows icon", {"ico"}),
    (b"SQLite format 3\x00", "SQLite database", {"sqlite", "db"}),
]

SCRIPT_PREFIXES = (
    (b"#!/", "shell script"),
    (b"<?php", "PHP script"),
    (b"<script", "HTML/JS script"),
)

DANGEROUS_EXTENSIONS = {
    "exe": "an executable",
    "scr": "a screensaver executable",
    "com": "a DOS executable",
    "pif": "a program information file",
    "bat": "a batch script",
    "cmd": "a command script",
    "ps1": "a PowerShell script",
    "vbs": "a VBScript",
    "vbe": "an encoded VBScript",
    "js": "a JavaScript file",
    "jse": "an encoded JavaScript file",
    "wsf": "a Windows script",
    "wsh": "a Windows script",
    "hta": "an HTML application",
    "lnk": "a Windows shortcut",
    "reg": "a registry script",
    "jar": "a Java archive",
    "apk": "an Android package",
    "dll": "a dynamic library",
    "msi": "a Windows installer",
}

EXECUTABLE_TYPES = {
    "Windows PE executable",
    "Linux ELF executable",
    "Mach-O executable",
    "Java class / Mach-O binary",
}

DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "jpg", "jpeg", "png", "gif", "txt", "csv", "rtf",
}


def detect_type(data: bytes) -> tuple[str | None, set[str]]:
    for signature, name, extensions in SIGNATURES:
        if data.startswith(signature):
            return name, extensions
    for prefix, name in SCRIPT_PREFIXES:
        if data.startswith(prefix):
            return name, set()
    return None, set()


def _double_extension(filename: str) -> str | None:
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return None
    if parts[-1] in DANGEROUS_EXTENSIONS and parts[-2] in DOCUMENT_EXTENSIONS:
        return f"{parts[-2]}.{parts[-1]}"
    return None


class FileTypeAnalyzer(Analyzer):
    name = "file-type"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        detected, expected = detect_type(ctx.data)
        extension = ctx.extension

        double = _double_extension(ctx.filename)
        if double:
            findings.append(
                Finding(
                    category=self.name,
                    severity="high",
                    message=f"Double extension detected: {double}",
                    detail="A document-looking name ending in an executable extension is a classic disguise.",
                )
            )

        if extension in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category=self.name,
                    severity="medium",
                    message=f"Executable/script extension: .{extension}",
                    detail=f"Files ending in .{extension} are {DANGEROUS_EXTENSIONS[extension]}.",
                )
            )

        if detected is None:
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message="File type not recognised from magic bytes",
                    detail="Could be plain text, an unknown format, or an obfuscated payload.",
                )
            )
            return findings

        if extension and expected and extension not in expected:
            severity = "high" if detected in EXECUTABLE_TYPES else "medium"
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"Extension mismatch: name says .{extension} but content is {detected}",
                    detail="The file is masquerading as another type. Treat it as untrusted.",
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message=f"Detected type: {detected}",
                    detail=f"Consistent with the .{extension} extension." if extension else "",
                )
            )
        return findings
