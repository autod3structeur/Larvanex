"""Render scan results as a single, self-contained HTML file.

No external assets or CDNs: everything (CSS, JS, SVG) is inlined, so the
report can be attached to an email, opened offline, or committed as an
artefact.
"""

from __future__ import annotations

import datetime as _dt
import html

from .attack import TACTICS, matrix, name as attack_name
from .scanner import ScanResult
from .utils import format_size

SEVERITY_COLOR = {
    "critical": "#e11d48",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#38bdf8",
    "info": "#94a3b8",
}

VERDICT_COLOR = {
    "MALICIOUS": "#ef4444",
    "SUSPICIOUS": "#f59e0b",
    "LIKELY SAFE": "#22c55e",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(value: object) -> str:
    return html.escape(str(value))


def _gauge(score: int, verdict: str) -> str:
    color = VERDICT_COLOR.get(verdict, "#94a3b8")
    return (
        f'<div class="gauge" style="--pct:{score};--col:{color}">'
        f'<div class="gauge-hole"><span class="gauge-num">{score}</span>'
        f'<span class="gauge-max">/100</span></div></div>'
    )


def _severity_bars(result: ScanResult) -> str:
    counts = {sev: 0 for sev in SEVERITY_COLOR}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    total = max(len(result.findings), 1)
    rows = []
    for severity in ("critical", "high", "medium", "low", "info"):
        count = counts.get(severity, 0)
        if not count:
            continue
        pct = round(100 * count / total)
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{severity}</span>'
            f'<div class="bar-track"><div class="bar-fill" '
            f'style="width:{pct}%;background:{SEVERITY_COLOR[severity]}"></div></div>'
            f'<span class="bar-count">{count}</span></div>'
        )
    return "".join(rows)


def _findings_table(result: ScanResult) -> str:
    rows = []
    ordered = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for finding in ordered:
        color = SEVERITY_COLOR.get(finding.severity, "#94a3b8")
        attack = " ".join(
            f'<span class="chip mono">{_esc(tid)} {_esc(attack_name(tid))}</span>'
            for tid in finding.attack
        )
        detail = f'<div class="detail">{_esc(finding.detail)}</div>' if finding.detail else ""
        rows.append(
            f'<tr data-search="{_esc(finding.message.lower())} {_esc(finding.category.lower())}">'
            f'<td><span class="pill" style="background:{color}">{_esc(finding.severity)}</span></td>'
            f'<td class="mono dim">{_esc(finding.category)}</td>'
            f'<td><strong>{_esc(finding.message)}</strong>{detail}'
            f'{("<div class=chips>" + attack + "</div>") if attack else ""}</td>'
            f"</tr>"
        )
    return "".join(rows)


def _attack_matrix(result: ScanResult) -> str:
    techniques = result.attack
    if not techniques:
        return ""
    columns = []
    for tactic_id, tactic_name, ids in matrix(techniques):
        chips = "".join(
            f'<div class="tt-chip"><span class="mono">{_esc(tid)}</span> {_esc(attack_name(tid))}</div>'
            for tid in ids
        )
        active = "active" if ids else ""
        columns.append(
            f'<div class="tt-col {active}"><div class="tt-head">{_esc(tactic_name)}</div>{chips}</div>'
        )
    return f'<div class="tt-grid">{"".join(columns)}</div>'


def _artifact_tree(artifacts: list, depth: int = 0) -> str:
    if not artifacts:
        return ""
    items = []
    for artifact in artifacts:
        verdict = artifact.ctx and _artifact_verdict(artifact)
        badge = (
            f'<span class="pill" style="background:{VERDICT_COLOR.get(verdict, "#94a3b8")}">'
            f"{_esc(verdict)}</span>"
            if verdict
            else ""
        )
        saved = (
            f'<div class="detail mono">quarantined: {_esc(artifact.saved_path)}</div>'
            if artifact.saved_path
            else ""
        )
        children = _artifact_tree(artifact.children, depth + 1)
        items.append(
            f'<li><div class="artifact"><span class="mono">{_esc(artifact.name)}</span> '
            f'<span class="dim">{_esc(artifact.origin)} - {format_size(artifact.size)}</span> '
            f'{badge}<div class="detail mono">{_esc(artifact.sha256[:32])}</div>{saved}</div>'
            f'{children}</li>'
        )
    return f'<ul class="tree">{"".join(items)}</ul>'


def _artifact_verdict(artifact) -> str:
    from .scanner import score, verdict

    total = score(artifact.ctx.findings)
    return verdict(artifact.ctx.findings, total)


def _file_card(result: ScanResult) -> str:
    color = VERDICT_COLOR.get(result.verdict, "#94a3b8")
    yara_findings = [f for f in result.findings if f.category == "yara" and f.severity != "info"]
    meta_chips = [
        f'<span class="chip">size {format_size(result.size)}</span>',
        f'<span class="chip">{len(result.findings)} findings</span>',
    ]
    if yara_findings:
        meta_chips.append(f'<span class="chip warn">{len(yara_findings)} YARA</span>')
    if result.artifacts:
        from .decompose import count_artifacts

        meta_chips.append(f'<span class="chip warn">{count_artifacts(result.artifacts)} embedded</span>')

    artifact_section = (
        f'<h3>Embedded artifact tree</h3>{_artifact_tree(result.artifacts)}'
        if result.artifacts
        else ""
    )
    attack_section = f'<h3>MITRE ATT&amp;CK coverage</h3>{_attack_matrix(result)}' if result.attack else ""

    return f"""
    <section class="card">
      <div class="card-head">
        <div class="fileline">
          <span class="verdict" style="background:{color}">{_esc(result.verdict)}</span>
          <div>
            <div class="fname">{_esc(result.filename)}</div>
            <div class="fpath mono">{_esc(result.path)}</div>
            <div class="chips">{''.join(meta_chips)}</div>
          </div>
        </div>
        {_gauge(result.score, result.verdict)}
      </div>
      <div class="hash mono">{_esc(result.sha256)}</div>
      <div class="grid2">
        <div><h3>Severity breakdown</h3>{_severity_bars(result)}</div>
        <div><h3>Findings</h3>
          <table class="findings"><tbody>{_findings_table(result)}</tbody></table>
        </div>
      </div>
      {attack_section}
      {artifact_section}
    </section>
    """


def render_html(results: list[ScanResult], title: str = "Larvanex Report") -> str:
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    malicious = sum(1 for r in results if r.verdict == "MALICIOUS")
    suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    safe = sum(1 for r in results if r.verdict == "LIKELY SAFE")

    cards = "".join(_file_card(result) for result in results)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{
    --bg:#0b1020; --panel:#141a2e; --panel2:#1b2238; --text:#e2e8f0; --dim:#8b97b0;
    --border:#26304a; --accent:#6366f1;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:radial-gradient(1200px 600px at 20% -10%, #1e2a4a 0, var(--bg) 55%);
    color:var(--text); font-family:"Segoe UI",system-ui,-apple-system,sans-serif; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:32px 20px 80px; }}
  header.top {{ display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; }}
  .logo {{ font-size:30px; font-weight:800; letter-spacing:-0.5px; }}
  .logo span {{ color:var(--accent); }}
  .sub {{ color:var(--dim); font-size:13px; }}
  .summary {{ display:flex; gap:12px; margin:24px 0; flex-wrap:wrap; }}
  .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:14px;
    padding:14px 22px; min-width:120px; }}
  .stat b {{ display:block; font-size:26px; }}
  .stat.bad b {{ color:#ef4444; }} .stat.warn b {{ color:#f59e0b; }} .stat.ok b {{ color:#22c55e; }}
  .card {{ background:linear-gradient(180deg,var(--panel),var(--panel2)); border:1px solid var(--border);
    border-radius:18px; padding:24px; margin:22px 0; box-shadow:0 20px 50px rgba(0,0,0,.35); }}
  .card-head {{ display:flex; justify-content:space-between; align-items:center; gap:20px; flex-wrap:wrap; }}
  .fileline {{ display:flex; align-items:center; gap:16px; }}
  .verdict {{ color:#08111f; font-weight:800; padding:8px 14px; border-radius:10px; font-size:14px; }}
  .fname {{ font-size:19px; font-weight:700; }}
  .fpath {{ color:var(--dim); font-size:12px; word-break:break-all; }}
  .mono {{ font-family:"JetBrains Mono",Consolas,monospace; }}
  .dim {{ color:var(--dim); }}
  .hash {{ margin:14px 0; font-size:12px; color:var(--dim); word-break:break-all;
    background:#0d1424; border:1px solid var(--border); border-radius:8px; padding:8px 12px; }}
  .chips {{ display:flex; gap:6px; flex-wrap:wrap; margin-top:8px; }}
  .chip {{ background:#0d1424; border:1px solid var(--border); color:#b9c4dd; font-size:11px;
    padding:3px 9px; border-radius:999px; }}
  .chip.warn {{ border-color:#7c4a12; color:#fbbf24; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1.4fr; gap:28px; margin-top:8px; }}
  @media (max-width:820px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
  h3 {{ font-size:13px; text-transform:uppercase; letter-spacing:1px; color:var(--dim); margin:20px 0 10px; }}
  .gauge {{ --pct:0; width:110px; height:110px; border-radius:50%; flex:0 0 auto;
    background:conic-gradient(var(--col) calc(var(--pct)*1%), #26304a 0);
    display:grid; place-items:center; }}
  .gauge-hole {{ width:82px; height:82px; border-radius:50%; background:var(--panel);
    display:grid; place-items:center; align-content:center; }}
  .gauge-num {{ font-size:26px; font-weight:800; }}
  .gauge-max {{ font-size:11px; color:var(--dim); }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin:6px 0; }}
  .bar-label {{ width:64px; text-transform:capitalize; font-size:12px; color:var(--dim); }}
  .bar-track {{ flex:1; height:8px; background:#0d1424; border-radius:999px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:999px; }}
  .bar-count {{ width:26px; text-align:right; font-size:12px; color:var(--dim); }}
  table.findings {{ width:100%; border-collapse:collapse; }}
  table.findings td {{ padding:8px 8px; border-bottom:1px solid var(--border); vertical-align:top; font-size:13px; }}
  .pill {{ color:#08111f; font-weight:700; font-size:11px; padding:3px 8px; border-radius:6px;
    text-transform:uppercase; white-space:nowrap; }}
  .detail {{ color:var(--dim); font-size:12px; margin-top:3px; }}
  .tt-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(170px,1fr)); gap:10px; }}
  .tt-col {{ background:#0d1424; border:1px solid var(--border); border-radius:12px; padding:10px; opacity:.55; }}
  .tt-col.active {{ opacity:1; border-color:var(--accent); box-shadow:0 0 0 1px var(--accent) inset; }}
  .tt-head {{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#a5b4fc; margin-bottom:8px; }}
  .tt-chip {{ font-size:12px; padding:3px 0; }}
  .tree {{ list-style:none; padding-left:14px; border-left:1px dashed var(--border); margin:6px 0; }}
  .tree li {{ margin:8px 0; }}
  .artifact {{ background:#0d1424; border:1px solid var(--border); border-radius:10px; padding:8px 12px; }}
  .tt-chip .mono {{ color:#fbbf24; }}
  footer {{ color:var(--dim); font-size:12px; text-align:center; margin-top:40px; }}
  #search {{ width:100%; margin:6px 0 0; padding:10px 14px; border-radius:10px; border:1px solid var(--border);
    background:#0d1424; color:var(--text); font-size:14px; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="logo">Larva<span>nex</span> <span style="font-size:14px;color:var(--dim)">forensic report</span></div>
      <div class="sub">Generated {_esc(generated)} - static analysis, no execution</div>
    </div>
    <input id="search" placeholder="Filter findings..." oninput="filterFindings(this.value)">
  </header>

  <div class="summary">
    <div class="stat"><b>{len(results)}</b>file(s)</div>
    <div class="stat bad"><b>{malicious}</b>malicious</div>
    <div class="stat warn"><b>{suspicious}</b>suspicious</div>
    <div class="stat ok"><b>{safe}</b>likely safe</div>
  </div>

  {cards}

  <footer>Larvanex performs static analysis only. A "LIKELY SAFE" verdict is not a guarantee.</footer>
</div>
<script>
function filterFindings(q) {{
  q = (q || "").toLowerCase();
  document.querySelectorAll("table.findings tr").forEach(function (row) {{
    var hay = row.getAttribute("data-search") || "";
    row.style.display = hay.indexOf(q) === -1 ? "none" : "";
  }});
}}
</script>
</body>
</html>"""
