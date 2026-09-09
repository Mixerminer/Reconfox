"""Reconfox CLI entry point."""
from __future__ import annotations

import argparse
import queue
import sys
import time

from rich.console import Console
from rich.live import Live

from . import __version__
from .banner import render as render_banner
from .config import Config
from .pipeline import Pipeline
from .tui.dashboard import Dashboard
from .tui.theme import THEME
from .utils import normalize_domain


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconfox",
        description=f"Reconfox v{__version__} — by MixerMiner & Anonymous-beta & samuelanih043-droid",
    )
    p.add_argument("domain", help="target domain (e.g. example.com)")
    p.add_argument("--subs", choices=["passive", "active", "both", "off"], default="both")
    p.add_argument("-w", "--wordlist", help="custom subdomain wordlist")
    p.add_argument("-d", "--dirlist", help="custom directory wordlist")
    p.add_argument("-p", "--ports", default="top100",
                   help="port spec: top100 | all | '22,80,8000-8100'")
    p.add_argument("-t", "--threads", type=int, default=40)
    p.add_argument("--timeout", type=float, default=10.0)
    o = p.add_argument_group("toggles")
    o.add_argument("--no-ports", action="store_true")
    o.add_argument("--no-dirs", action="store_true")
    o.add_argument("--no-fingerprint", action="store_true")
    o.add_argument("--no-dns", action="store_true")
    p.add_argument("-o", "--output", default="reconfox_results.json")
    p.add_argument("--no-tui", action="store_true", help="plain output, no live dashboard")
    p.add_argument("-V", "--version", action="version", version=f"reconfox {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(theme=THEME)
    render_banner(console)

    cfg = Config(
        domain=normalize_domain(args.domain),
        wordlist_subs=args.wordlist,
        wordlist_dirs=args.dirlist,
        threads=args.threads,
        timeout=args.timeout,
        ports=args.ports,
        passive_subs=args.subs in ("passive", "both"),
        active_subs=args.subs in ("active", "both"),
        port_scan=not args.no_ports,
        dir_fuzz=not args.no_dirs,
        fingerprint=not args.no_fingerprint,
        output=args.output,
    )

    events: queue.Queue = queue.Queue()
    pipe = Pipeline(cfg, events)
    dash = Dashboard(console, cfg.domain)

    if args.no_tui:
        # plain mode: drain events into simple prints
        import threading
        worker = threading.Thread(target=pipe.run, daemon=True)
        worker.start()
        while worker.is_alive() or not events.empty():
            try:
                ev = events.get(timeout=0.3)
            except queue.Empty:
                continue
            if ev["type"] == "stage":
                console.print(f"[fox.accent]▶[/] {ev['stage']}: {ev['status']} {ev.get('msg','')}",
                              highlight=False)
            elif ev["type"] == "finished":
                break
        worker.join()
        console.print(f"[fox.ok]✔ results saved to {cfg.output}[/]")
        return 0

    # live TUI mode
    import threading
    worker = threading.Thread(target=pipe.run, daemon=True)
    worker.start()

    with Live(dash.render(), console=console, refresh_per_second=8, screen=False) as live:
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
                  f"in [fox.accent]{dash.elapsed:.1f}s[/]  →  [bold]{cfg.output}[/]")
    if pipe.ctx.errors:
        console.print(f"[fox.warn]! {len(pipe.ctx.errors)} soft errors (see output file)[/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
