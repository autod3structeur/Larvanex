"""Tests for the v2 features: ATT&CK, intel mesh, YARA, decomposition, reports."""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from larvanex.attack import label, matrix, name
from larvanex.intel import IntelMesh, IntelResult, LocalBlocklist
from larvanex.html_report import render_html
from larvanex.report import render_json, result_to_dict
from larvanex.scanner import build_analyzers, scan_bytes
from larvanex.analyzers.yara import YaraAnalyzer


def offline_analyzers():
    return build_analyzers(network=False)


def test_attack_lookup_and_matrix():
    assert name("T1059.001") == "PowerShell"
    assert "T1059.001" in label("T1059.001")
    grid = matrix({"T1059.001", "T1204.002"})
    tactics = {tid: ids for tid, _name, ids in grid}
    assert "T1059.001" in tactics["execution"]
    assert "T1204.002" in tactics["execution"]


def test_intel_mesh_consensus_malicious():
    results = [IntelResult("a", "malicious", 100, "known bad"), IntelResult("b", "clean", 0)]
    status, score, summary = IntelMesh.consensus(results)
    assert status == "malicious"
    assert score == 100
    assert "a" in summary


def test_intel_mesh_consensus_clean_and_empty():
    assert IntelMesh.consensus([IntelResult("a", "clean", 0)])[0] == "clean"
    assert IntelMesh.consensus([])[0] == "unknown"


def test_local_blocklist(tmp_path):
    sample = b"malicious bytes"
    import hashlib

    sha256 = hashlib.sha256(sample).hexdigest()
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text(f"# comment\n{sha256}\n")
    provider = LocalBlocklist(str(blocklist))
    assert provider.available()
    result = provider.query({"sha256": sha256})
    assert result.is_malicious
    assert provider.query({"sha256": "0" * 64}).status == "clean"


def test_yara_bundled_rule_matches():
    pytest.importorskip("yara")
    data = b"powershell -enc " + b"A" * 20
    findings = YaraAnalyzer().analyze(type("C", (), {"data": data, "path": "x.txt"})())
    assert any("YARA match" in f.message for f in findings)


def test_scan_result_attack_and_verdict():
    data = b"%PDF-1.4 /OpenAction /JavaScript /JS (app.alert(1)) %%EOF"
    result = scan_bytes("doc.pdf", data, offline_analyzers())
    assert result.verdict in {"SUSPICIOUS", "MALICIOUS"}
    assert "T1204.002" in result.attack
    assert result.max_severity == "high"


def test_decompose_tree_and_quarantine(tmp_path):
    import zlib

    pe = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x90" * 64
    compressed = zlib.compress(pe)
    data = (
        b"%PDF-1.4\n4 0 obj << /Length "
        + str(len(compressed)).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + compressed
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    qdir = tmp_path / "quarantine"
    result = scan_bytes(
        "hidden.pdf", data, offline_analyzers(), decompose=True, quarantine_dir=str(qdir)
    )
    assert result.verdict == "MALICIOUS"
    assert result.artifacts
    saved = list(qdir.glob("*.quarantined"))
    assert saved, "quarantine should contain the extracted payload"


def test_json_report_includes_attack_and_artifacts():
    import zlib

    pe = b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 40
    data = (
        b"%PDF-1.4\n1 0 obj << /Length "
        + str(len(zlib.compress(pe))).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + zlib.compress(pe)
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    result = scan_bytes("hidden.pdf", data, offline_analyzers(), decompose=True)
    payload = result_to_dict(result)
    assert payload["verdict"] == "MALICIOUS"
    assert payload["attack"]
    assert payload["artifacts"]


def test_html_report_contains_sections():
    data = b"%PDF-1.4 /OpenAction /JavaScript /JS (x) %%EOF"
    result = scan_bytes("doc.pdf", data, offline_analyzers())
    html = render_html([result])
    assert html.startswith("<!DOCTYPE html>")
    assert "Larvanex" in html
    assert "MITRE ATT&amp;CK coverage" in html
    assert result.sha256 in html


def test_zip_member_extraction():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("payload.exe", b"MZ" + b"\x00" * 100)
    result = scan_bytes("a.zip", buffer.getvalue(), offline_analyzers(), decompose=True)
    names = [a.name for a in result.artifacts]
    assert any("payload.exe" in n for n in names)
