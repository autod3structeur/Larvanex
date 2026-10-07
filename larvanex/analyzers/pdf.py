"""Structural inspection of PDF files: the format most abused for hiding
malicious payloads, JavaScript and automatic actions."""

from __future__ import annotations

import re

from .base import Analyzer, Finding, FileContext

PDF_KEYWORDS: dict[bytes, tuple[str, str, list[str]]] = {
    b"/JavaScript": ("high", "Embedded JavaScript", ["T1059.007", "T1204.002"]),
    b"/OpenAction": ("high", "Automatic action when the PDF is opened", ["T1204.002"]),
    b"/AA": ("medium", "Additional automatic action trigger", ["T1204.002"]),
    b"/Launch": ("critical", "Launch action - can start an external program", ["T1204.002"]),
    b"/EmbeddedFile": ("high", "Embedded file attachment", ["T1027.009"]),
    b"/RichMedia": ("medium", "Rich media / Flash content", ["T1203"]),
    b"/XFA": ("medium", "XFA form (can carry script)", ["T1059.007", "T1204.002"]),
    b"/Encrypt": ("medium", "The PDF is encrypted", ["T1027"]),
    b"/URI": ("low", "Embedded URI / link", ["T1071.001"]),
    b"/SubmitForm": ("medium", "Form submission action", ["T1567"]),
}

HEX_NAME_RE = re.compile(rb"/[0-9A-Fa-f]{2}(?:#[0-9A-Fa-f]{2}){3,}")


def _try_pypdf(path: str):
    try:
        from pypdf import PdfReader
    except ImportError:
        return None
    try:
        return PdfReader(path)
    except Exception:
        return None


class PdfAnalyzer(Analyzer):
    name = "pdf"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        if not ctx.data.startswith(b"%PDF"):
            return findings

        header_offset = ctx.data.find(b"%PDF")
        if header_offset > 0:
            findings.append(
                Finding(
                    category=self.name,
                    severity="medium",
                    message=f"PDF header is not at the start of the file (offset {header_offset})",
                    detail="Junk prepended before %PDF is a common trick to break scanners.",
                    offset=header_offset,
                    attack=["T1027"],
                )
            )

        eof_count = ctx.data.count(b"%%EOF")
        if eof_count > 1:
            findings.append(
                Finding(
                    category=self.name,
                    severity="low",
                    message=f"Multiple %%EOF markers ({eof_count})",
                    detail="Indicates incremental updates; hide-data-in-update is a known technique.",
                    attack=["T1027"],
                )
            )

        for keyword, (severity, description, attack) in PDF_KEYWORDS.items():
            count = ctx.data.count(keyword)
            if keyword == b"/JS" and count:
                continue
            if count:
                findings.append(
                    Finding(
                        category=self.name,
                        severity=severity,
                        message=f"{description}: {keyword.decode()} (x{count})",
                        attack=list(attack),
                    )
                )

        js_count = ctx.data.count(b"/JS") + ctx.data.count(b"/JavaScript")
        if js_count:
            findings.append(
                Finding(
                    category=self.name,
                    severity="high",
                    message=f"JavaScript present ({js_count} reference(s))",
                    detail="JavaScript in a PDF is a leading indicator of exploitation attempts.",
                    attack=["T1059.007", "T1204.002"],
                )
            )

        obfuscated = HEX_NAME_RE.findall(ctx.data)
        if obfuscated:
            findings.append(
                Finding(
                    category=self.name,
                    severity="high",
                    message=f"{len(obfuscated)} hex-obfuscated PDF name(s)",
                    detail="PDF names encoded as #xx sequences are used to evade string scanners.",
                    attack=["T1027", "T1140"],
                )
            )

        self._deep_scan(ctx, findings)
        return findings

    def _deep_scan(self, ctx: FileContext, findings: list[Finding]) -> None:
        reader = _try_pypdf(ctx.path)
        if reader is None:
            return
        try:
            if reader.is_encrypted:
                findings.append(
                    Finding(
                        category=self.name,
                        severity="medium",
                        message="PDF is encrypted",
                        detail="Encryption hides content from scanners (and sometimes from the user).",
                        attack=["T1027"],
                    )
                )
            attachments = getattr(reader, "attachments", {})
            if attachments:
                names = ", ".join(list(attachments.keys())[:5])
                findings.append(
                    Finding(
                        category=self.name,
                        severity="high",
                        message=f"{len(attachments)} embedded attachment(s)",
                        detail=f"Attachments: {names}",
                        attack=["T1027.009"],
                    )
                )
        except Exception as exc:  # pragma: no cover - defensive
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message="Deep PDF parsing failed",
                    detail=str(exc),
                )
            )
