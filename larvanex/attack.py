"""A small, curated slice of the MITRE ATT&CK matrix.

Findings reference technique IDs (for example ``T1059.001``). This module turns
those IDs into human-readable names, groups them by tactic and builds a matrix
for the terminal and HTML reports.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

TACTICS = [
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.005": ("Visual Basic", "execution"),
    "T1059.007": ("JavaScript", "execution"),
    "T1204": ("User Execution", "execution"),
    "T1204.002": ("Malicious File", "execution"),
    "T1203": ("Exploitation for Client Execution", "execution"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1547": ("Boot or Logon Autostart Execution", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1566": ("Phishing", "initial-access"),
    "T1566.001": ("Spearphishing Attachment", "initial-access"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1027.002": ("Software Packing", "defense-evasion"),
    "T1027.006": ("HTML Smuggling", "defense-evasion"),
    "T1027.009": ("Embedded Payloads", "defense-evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "defense-evasion"),
    "T1218": ("System Binary Proxy Execution", "defense-evasion"),
    "T1218.005": ("Mshta", "defense-evasion"),
    "T1218.010": ("Regsvr32", "defense-evasion"),
    "T1218.011": ("Rundll32", "defense-evasion"),
    "T1221": ("Template Injection", "defense-evasion"),
    "T1497": ("Virtualization/Sandbox Evasion", "defense-evasion"),
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
    "T1567.002": ("Exfiltration to Cloud Storage", "exfiltration"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1496": ("Resource Hijacking", "impact"),
    "T1112": ("Modify Registry", "defense-evasion"),
    "T1036": ("Masquerading", "defense-evasion"),
    "T1036.007": ("Double File Extension", "defense-evasion"),
    "T1036.008": ("Masquerade File Type", "defense-evasion"),
}


def name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, (technique_id, "unknown"))[0]


def tactic(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, ("", ""))[1]


def label(technique_id: str) -> str:
    return f"{technique_id} - {name(technique_id)}"


def matrix(technique_ids: set[str]) -> list[tuple[str, str, list[str]]]:
    """Return (tactic_id, tactic_name, [technique_ids]) for every tactic,
    including empty ones, in canonical ATT&CK order."""
    grouped: dict[str, list[str]] = {}
    for technique_id in sorted(technique_ids):
        grouped.setdefault(tactic(technique_id), []).append(technique_id)
    return [(tid, tname, grouped.get(tid, [])) for tid, tname in TACTICS]
