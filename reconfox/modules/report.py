"""Reconfox report generator — renders JSON findings into a standalone HTML report."""
from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from .. import __version__

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLORS = {"critical": "#ff1744", "high": "#ff6d00", "medium": "#ffb300",
              "low": "#00b8d4", "info": "#8d8d8d"}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Reconfox Report — {target}</title>
<style>
  :root {{ --ember:#ff6d1f; --bg:#1a120b; --panel:#241a10; --text:#e8e0d4; --muted:#9a8d7c; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font:15px/1.55 'Segoe UI',system-ui,sans-serif; padding:2.5rem 1rem; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  header {{ border:1px solid var(--ember); border-radius:14px; padding:2rem; text-align:center;
           background:linear-gradient(160deg,#2a1c10,#1a120b); margin-bottom:1.5rem; }}
  h1 {{ font-size:2rem; letter-spacing:.35em; color:var(--ember); }}
  .sub {{ color:var(--muted); margin-top:.4rem; }}
  .authors {{ margin-top:.7rem; font-weight:600; color:var(--ember); }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
  .card {{ background:var(--panel); border:1px solid #3a2a18; border-radius:12px; padding:1rem; text-align:center; }}
  .card b {{ font-size:1.6rem; color:var(--ember); display:block; }}
  .card span {{ color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.1em; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid #3a2a18;
          border-radius:12px; overflow:hidden; margin-bottom:1.5rem; }}
  th {{ background:#2f2113; color:var(--ember); text-transform:uppercase; font-size:.72rem;
       letter-spacing:.12em; padding:.7rem 1rem; text-align:left; }}
  td {{ padding:.6rem 1rem; border-top:1px solid #332412; font-size:.9rem; word-break:break-all; }}
  tr:hover td {{ background:#2b1e12; }}
  .sev {{ display:inline-block; padding:.15rem .6rem; border-radius:999px; font-size:.7rem;
         font-weight:700; color:#1a120b; text-transform:uppercase; }}
  footer {{ color:var(--muted); text-align:center; font-size:.8rem; margin-top:2rem; }}
  .errors li {{ margin-left:1.2rem; color:#ffb300; font-size:.85rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>RECONFOX</h1>
    <div class="sub">unified reconnaissance report — target <b style="color:var(--text)">{target}</b></div>
    <div class="authors">MixerMiner &amp; Anonymous-beta &amp; samuelanih043-droid</div>
  </header>
  <div class="cards">
    <div class="card"><b>{n_findings}</b><span>findings</span></div>
    <div class="card"><b>{n_critical}</b><span>critical</span></div>
    <div class="card"><b>{n_high}</b><span>high</span></div>
    <div class="card"><b>{n_errors}</b><span>soft errors</span></div>
    <div class="card"><b>{elapsed:.1f}s</b><span>scan time</span></div>
  </div>
  {tables}
  {errors_block}
  <footer>Reconfox v{version} — generated {gen_time}</footer>
</div>
</body></html>"""


def generate(data: dict[str, Any], out: Path) -> Path:
    findings: list[dict] = data.get("findings", [])
    findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity", "info"), 9), f["module"]))
    errors = data.get("errors", [])

    by_type: dict[str, list[dict]] = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)

    tables = []
    for ftype, rows in sorted(by_type.items()):
        body = []
        for f in rows:
            sev = f.get("severity", "info")
            detail = html.escape(json.dumps(f.get("detail", {}))[:160])
            body.append(
                f"<tr><td><span class='sev' style='background:{SEV_COLORS[sev]}'>{sev}</span></td>"
                f"<td>{html.escape(f['module'])}</td>"
                f"<td>{html.escape(str(f['value']))}</td>"
                f"<td style='color:var(--muted)'>{detail}</td></tr>"
            )
        tables.append(
            f"<table><thead><tr><th>sev</th><th>module</th><th>{html.escape(ftype)}</th>"
            f"<th>detail</th></tr></thead><tbody>{''.join(body)}</tbody></table>"
        )

    errors_block = ""
    if errors:
        errors_block = "<table><thead><tr><th>soft errors</th></tr></thead><tbody><tr><td><ul class='errors'>" \
                       + "".join(f"<li>{html.escape(e)}</li>" for e in errors) + "</ul></td></tr></tbody></table>"

    n = lambda sev: sum(1 for f in findings if f.get("severity") == sev)
    html_out = TEMPLATE.format(
        target=html.escape(data.get("target", "?")),
        n_findings=len(findings), n_critical=n("critical"), n_high=n("high"),
        n_errors=len(errors), elapsed=data.get("elapsed", 0.0),
        tables="\n".join(tables), errors_block=errors_block,
        version=__version__, gen_time=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    out.write_text(html_out, encoding="utf-8")
    return out
