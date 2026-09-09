"""Reconfox CLI entry point."""
from __future__ import annotations

import argparse
import json
import queue
import sys
import threading

from pathlib import Path
from rich.console import Console
from rich.live import Live

from . import __version__
from .banner import render as render_banner
from .config import Config
from .modules.report import generate as gen_report
from .pipeline import Pipeline
from .tui.theme import THEME
from .utils import normalize_domain


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconfox",
        description=f"Reconfox v{__version__} — by MixerMiner & Anonymous-beta & samuelanih043-droid",
    )
    p.add_argument("-V", "--version", action="version", version=f"reconfox {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run a full recon pipeline")
    s.add_argument("domain")
    s.add_argument("--subs", choices=["passive", "active", "both", "off"], default="both")
    s.add_argument("-w", "--wordlist")
    s.add_argument("-d", "--dirlist")
    s.add_argument("-p", "--ports", default="top100")
    s.add_argument("-t", "--threads", type=int, default=40)
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--no-dns", action="store_true")
    s.add_argument("--no-ports", action="store_true")
    s.add_argument("--no-dirs", action="store_true")
    s.add_argument("--no-fingerprint", action="store_true")
    s.add_argument("-o", "--output", default="reconfox_results.json")
    s.add_argument("--html", help="also generate an HTML report at this path")
    s.add_argument("--no-tui", action="store_true")

    r = sub.add_parser("report", help="render an HTML report from a results JSON")
    r.add_argument("results", help="path to reconfox_results.json")
    r.add_argument("-o", "--output", default="reconfox_report.html")
    return p


def cmd_scan(args) -> int:
    console = Console(theme=THEME)
    render_banner(console)

    cfg = Config(
        domain=normalize_domain(args.domain),
        wordlist_subs=args.wordlist,
        wordlist_dirs=args.dirlist,
        threads=args.threads,
        timeout=args.timeout,
        ports=args.ports,
        dns_resolve=not args.no_dns,
        passive_subs=args.subs in ("passive", "both"),
        active_subs=args.subs in ("active", "both"),
        port_scan=not args.no_ports,
        dir_fuzz=not args.no_dirs,
        fingerprint=not args.no_fingerprint,
        output=args.output,
    )
    events: queue.Queue = queue.Queue()
    pipe = Pipeline(cfg, events)
    worker = threading.Thread(target=pipe.run, daemon=True)

    if args.no_tui:
        worker.start()
        while worker.is_alive() or not events.empty():
            try:
                ev = events.get(timeout=0.3)
            except queue.Empty:
                continue
            if ev["type"] == "stage":
                console.print(f"[fox.accent]▶[/] {ev['stage']}: {ev['status']} {ev.get('msg','')}")
            elif ev["type"] == "finished":
                break
        worker.join()
    else:
        from .tui.dashboard import Dashboard
        dash = Dashboard(console, cfg.domain)
        worker.start()
        with Live(dash.render(), console=console, refresh_per_second=8) as live:
            while worker.is_alive() or not events.empty():
                try:
                    ev = events.get(timeout=0.2)
                except queue.Empty:
                    live.update(dash.render())
                    continue
                if ev["type"] == "stage":
                    dash.stages[ev["stage"]]["status"] = ev["status"]
                    dash.stages[ev["stage"]]["msg"] = ev.get("msg", "")
                elif ev["type"] == "finished":
                    dash.elapsed = ev["elapsed"]
                    dash.finished = True
                live.update(dash.render())
            worker.join()

    console.print(f"\n[fox.ok]✔ scan complete[/] — [bold]{len(pipe.ctx.findings)}[/] findings "
                  f"→  [bold]{cfg.output}[/]")
    if args.html:
        data = json.loads(Path(cfg.output).read_text())
        gen_report(data, Path(args.html))
        console.print(f"[fox.ok]✔ HTML report → {args.html}[/]")
    return 0


def cmd_report(args) -> int:
    console = Console(theme=THEME)
    data = json.loads(Path(args.results).read_text())
    out = gen_report(data, Path(args.output))
    console.print(f"[fox.ok]✔ report written → {out}[/]")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())