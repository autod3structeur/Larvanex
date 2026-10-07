"""Hunt for suspicious keywords and command strings inside a file."""

from __future__ import annotations

import re

from .base import Analyzer, Finding, FileContext
from ..utils import extract_strings

KEYWORDS: list[tuple[str, str, str, list[str]]] = [
    ("cmd.exe", "critical", "Windows command shell invocation", ["T1059.003"]),
    ("powershell", "critical", "PowerShell invocation", ["T1059.001"]),
    ("pwsh", "high", "PowerShell Core invocation", ["T1059.001"]),
    ("wscript.shell", "high", "Windows Script Host shell", ["T1059.005"]),
    ("shell.application", "high", "Shell.Application COM object", ["T1059.005"]),
    ("createobject", "medium", "COM object creation", ["T1059.005"]),
    ("shellexecute", "high", "Windows ShellExecute call", ["T1059.005"]),
    ("invoke-expression", "high", "PowerShell Invoke-Expression (code execution)", ["T1059.001"]),
    ("iex(", "high", "PowerShell IEX shorthand", ["T1059.001"]),
    ("downloadstring", "high", "Remote payload download", ["T1105"]),
    ("downloadfile", "high", "Remote payload download", ["T1105"]),
    ("frombase64string", "high", "Base64 decoding of a payload", ["T1140"]),
    ("base64_decode", "medium", "Base64 decoding", ["T1140"]),
    ("certutil", "high", "Certutil (often abused to download/decode)", ["T1105", "T1140"]),
    ("bitsadmin", "high", "BITS transfer (often abused for download)", ["T1105"]),
    ("mshta", "high", "MSHTA (HTML application execution)", ["T1218.005"]),
    ("regsvr32", "high", "Regsvr32 used for UAC bypass / execution", ["T1218.010"]),
    ("rundll32", "high", "Rundll32 execution", ["T1218.011"]),
    ("schtasks", "medium", "Scheduled task creation", ["T1053.005"]),
    ("/javascript", "high", "PDF embedded JavaScript", ["T1059.007", "T1204.002"]),
    ("/openaction", "high", "PDF automatic action on open", ["T1204.002"]),
    ("/aa", "medium", "PDF additional action trigger", ["T1204.002"]),
    ("/launch", "critical", "PDF launch action (runs external program)", ["T1204.002"]),
    ("/embeddedfile", "high", "PDF embedded file attachment", ["T1027.009"]),
    ("/submitform", "medium", "PDF form submission (data exfil)", ["T1567"]),
    ("/richmedia", "medium", "PDF rich media (Flash/embedded content)", ["T1203"]),
    ("autoopen", "high", "Macro auto-execute on open", ["T1204.002", "T1059.005"]),
    ("document_open", "high", "Macro auto-execute on document open", ["T1204.002", "T1059.005"]),
    ("auto_close", "medium", "Macro auto-execute on close", ["T1204.002"]),
    ("workbook_open", "high", "Excel macro auto-execute", ["T1204.002", "T1059.005"]),
    ("meterpreter", "critical", "Meterpreter payload marker", ["T1059.001", "T1105"]),
    ("msfvenom", "critical", "Metasploit payload marker", ["T1059.001"]),
    ("mimikatz", "critical", "Credential dumping tool marker", ["T1003"]),
    ("xmrig", "high", "Cryptominer marker", ["T1496"]),
]

KEYWORD_INFO = {keyword: (severity, description, attack) for keyword, severity, description, attack in KEYWORDS}

URL_RE = re.compile(rb"https?://[^\s\"'<>()\[\]]{4,}", re.IGNORECASE)
B64_RE = re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}")


class StringsAnalyzer(Analyzer):
    name = "strings"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        strings = extract_strings(ctx.data)
        joined = "\n".join(strings).lower()

        hits: dict[str, int] = {}
        for keyword, _severity, _description, _attack in KEYWORDS:
            count = joined.count(keyword)
            if count:
                hits[keyword] = count

        for keyword, count in hits.items():
            severity, description, attack = KEYWORD_INFO[keyword]
            findings.append(
                Finding(
                    category=self.name,
                    severity=severity,
                    message=f"Suspicious string: '{keyword}' (x{count})",
                    detail=description,
                    attack=list(attack),
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
                    attack=["T1071.001"],
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
                    attack=["T1140"],
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
