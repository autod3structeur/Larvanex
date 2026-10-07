"""Hunt for suspicious keywords and command strings inside a file."""

from __future__ import annotations

import re

from .base import Analyzer, Finding, FileContext
from ..utils import extract_strings

KEYWORDS: list[tuple[str, str, str]] = [
    ("cmd.exe", "critical", "Windows command shell invocation"),
    ("powershell", "critical", "PowerShell invocation"),
    ("pwsh", "high", "PowerShell Core invocation"),
    ("wscript.shell", "high", "Windows Script Host shell"),
    ("shell.application", "high", "Shell.Application COM object"),
    ("createobject", "medium", "COM object creation"),
    ("shellexecute", "high", "Windows ShellExecute call"),
    ("invoke-expression", "high", "PowerShell Invoke-Expression (code execution)"),
    ("iex(", "high", "PowerShell IEX shorthand"),
    ("downloadstring", "high", "Remote payload download"),
    ("downloadfile", "high", "Remote payload download"),
    ("frombase64string", "high", "Base64 decoding of a payload"),
    ("base64_decode", "medium", "Base64 decoding"),
    ("certutil", "high", "Certutil (often abused to download/decode)"),
    ("bitsadmin", "high", "BITS transfer (often abused for download)"),
    ("mshta", "high", "MSHTA (HTML application execution)"),
    ("regsvr32", "high", "Regsvr32 used for UAC bypass / execution"),
    ("rundll32", "high", "Rundll32 execution"),
    ("schtasks", "medium", "Scheduled task creation"),
    ("/javascript", "high", "PDF embedded JavaScript"),
    ("/openaction", "high", "PDF automatic action on open"),
    ("/aa", "medium", "PDF additional action trigger"),
    ("/launch", "critical", "PDF launch action (runs external program)"),
    ("/embeddedfile", "high", "PDF embedded file attachment"),
    ("/submitform", "medium", "PDF form submission (data exfil)"),
    ("/richmedia", "medium", "PDF rich media (Flash/embedded content)"),
    ("autoopen", "high", "Macro auto-execute on open"),
    ("document_open", "high", "Macro auto-execute on document open"),
    ("auto_close", "medium", "Macro auto-execute on close"),
    ("workbook_open", "high", "Excel macro auto-execute"),
    ("meterpreter", "critical", "Meterpreter payload marker"),
    ("msfvenom", "critical", "Metasploit payload marker"),
    ("mimikatz", "critical", "Credential dumping tool marker"),
    ("xmrig", "high", "Cryptominer marker"),
]

KEYWORD_INFO = {keyword: (severity, description) for keyword, severity, description in KEYWORDS}

URL_RE = re.compile(rb"https?://[^\s\"'<>()\[\]]{4,}", re.IGNORECASE)
B64_RE = re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class StringsAnalyzer(Analyzer):
    name = "strings"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        strings = extract_strings(ctx.data)
        joined = "\n".join(strings).lower()

        hits: dict[str, tuple[str, int]] = {}
        for keyword, severity, _description in KEYWORDS:
            count = joined.count(keyword)
            if count:
                hits[keyword] = (severity, count)

        for keyword, (severity, count) in hits.items():
            description = KEYWORD_INFO[keyword][1]
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"Suspicious string: '{keyword}' (x{count})",
                    detail=description,
                )
            )

        urls = sorted({m.group().decode("ascii", "ignore") for m in URL_RE.finditer(ctx.data)})
        if urls:
            severity = "medium" if len(urls) > 1 else "low"
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"{len(urls)} URL(s) found",
                    detail=", ".join(urls[:5]) + (" ..." if len(urls) > 5 else ""),
                )
            )

        b64_blobs = B64_RE.findall(ctx.data)
        if b64_blobs:
            findings.append(
                Finding(
                    category=self.name,
                    severity="medium",
                    message=f"{len(b64_blobs)} long Base64-looking blob(s)",
                    detail="Base64 is often used to hide a second-stage payload.",
                )
            )

        if not hits and not urls and not b64_blobs:
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message="No suspicious strings found",
                )
            )
        return findings
