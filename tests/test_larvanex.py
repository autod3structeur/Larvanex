"""Tests for Larvanex. Run with: pytest -q"""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from larvanex.analyzers.entropy import EntropyAnalyzer
from larvanex.analyzers.filetype import FileTypeAnalyzer, detect_type
from larvanex.analyzers.pdf import PdfAnalyzer
from larvanex.analyzers.strings import StringsAnalyzer
from larvanex.analyzers.embedded import EmbeddedFileAnalyzer
from larvanex.scanner import build_analyzers, scan_bytes, score, verdict


def categories(ctx):
    return {f.category for f in ctx.findings}


def severities(ctx):
    return {f.severity for f in ctx.findings}


def offline_analyzers():
    return build_analyzers(network=False)


def test_detect_type_pdf():
    name, extensions = detect_type(b"%PDF-1.7\n...")
    assert name == "PDF document"
    assert "pdf" in extensions


def test_extension_mismatch_executable_disguised_as_pdf():
    data = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 100
    ctx = scan_bytes("invoice.pdf", data, [FileTypeAnalyzer()])
    messages = " ".join(f.message for f in ctx.findings)
    assert "mismatch" in messages.lower()
    assert "high" in severities(ctx)


def test_double_extension_is_high():
    data = b"%PDF-1.4\n%%EOF"
    ctx = scan_bytes("invoice.pdf.exe", data, [FileTypeAnalyzer()])
    assert any("Double extension" in f.message for f in ctx.findings)


def test_high_entropy_random_data():
    data = os.urandom(4096)
    ctx = scan_bytes("blob.bin", data, [EntropyAnalyzer()])
    assert any(f.severity == "medium" for f in ctx.findings)


def test_low_entropy_text():
    data = b"hello world " * 500
    ctx = scan_bytes("note.txt", data, [EntropyAnalyzer()])
    assert not any(f.severity == "medium" for f in ctx.findings)


def test_suspicious_strings_powershell():
    data = b"powershell -enc SQBFAFgA"
    ctx = scan_bytes("run.txt", data, [StringsAnalyzer()])
    assert any("powershell" in f.message for f in ctx.findings)
    assert "critical" in severities(ctx)


def test_urls_are_reported():
    data = b"http://evil.example.com/payload.exe"
    ctx = scan_bytes("link.txt", data, [StringsAnalyzer()])
    assert any(f.category == "strings" and "URL" in f.message for f in ctx.findings)


def test_pdf_javascript_detected():
    data = b"%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF"
    ctx = scan_bytes("doc.pdf", data, [PdfAnalyzer()])
    messages = " ".join(f.message for f in ctx.findings)
    assert "JavaScript" in messages
    assert "/OpenAction" in messages


def test_embedded_pe_inside_pdf():
    pe = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 100
    data = b"%PDF-1.4\n" + b"A" * 64 + pe + b"\n%%EOF"
    ctx = scan_bytes("hidden.pdf", data, [EmbeddedFileAnalyzer()])
    assert any("Windows PE executable" in f.message for f in ctx.findings)
    assert "critical" in severities(ctx)


def test_zip_with_executable_member():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "hello")
        archive.writestr("payload.exe", b"MZ" + b"\x00" * 100)
    ctx = scan_bytes("archive.zip", buffer.getvalue(), [EmbeddedFileAnalyzer()])
    assert any("payload.exe" in f.message for f in ctx.findings)


def test_verdict_scoring():
    data = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + os.urandom(2000) + b"powershell cmd.exe"
    ctx = scan_bytes("totally_safe.pdf", data, offline_analyzers())
    total = score(ctx.findings)
    result = verdict(ctx.findings, total)
    assert result in {"SUSPICIOUS", "MALICIOUS"}
    assert total > 0
