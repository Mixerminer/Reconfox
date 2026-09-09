"""Live Rich TUI dashboard: stage progress, findings feed, summary stats."""
from __future__ import annotations

import queue
import time

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..banner import render as render_banner
from .theme import THEME

SEV_STYLE = {"critical": "fox.critical", "high": "fox.high", "medium": "fox.medium",
             "low": "fox.low", "info": "fox.info"}
STAGE_ORDER = ["dns", "passive_subs", "active_subs", "ports", "dirs", "fingerprint"]


class Dashboard:
    def __init__(self, console: Console, domain: str) -> None:
        self.console = console
        self.domain = domain
        self.stages: dict[str, dict] = {s: {"status": "pending", "msg": ""} for s in STAGE_ORDER}
        self.findings: list[dict] = []
        self.errors: list[str] = []
        self.finished = False
        self.elapsed = 0.0

    def consume(self, q: queue.Queue) -> None:
        while not self.finished:
            try:
                ev = q.get(timeout=0.2)
            except queue.Empty:
                continue
            if ev["type"] == "stage":
                self.stages[ev["stage"]]["status"] = ev["status"]
                self.stages[ev["stage"]]["msg"] = ev.get("msg", "")
            elif ev["type"] == "progress":
                pass  # hook for finer progress later
            elif ev["type"] == "finished":
                self.elapsed = ev["elapsed"]
                self.finished = True
            time.sleep(0)

    def render(self) -> Group:
        # stages table
        stages = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, border_style="fox.border")
        stages.add_column("stage", style="bold", width=16)
        stages.add_column("status", width=10)
        stages.add_column("detail", style="fox.muted")
        icons = {"pending": "[fox.muted]•[/]", "running": "[fox.accent]▶[/]",
                 "done": "[fox.ok]✔[/]", "error": "[fox.error]✘[/]", "skipped": "[fox.muted]–[/]"}
        for s in STAGE_ORDER:
            st = self.stages[s]
            style = "fox.ok" if st["status"] == "done" else (
                "fox.error" if st["status"] == "error" else (
                "fox.accent" if st["status"] == "running" else "fox.muted"))
            stages.add_row(s, Text(icons[st["status"]] + " " + st["status"], style=style), st["msg"])

        # findings feed (latest 12)
        feed = Table(box=box.SIMPLE, expand=True, show_edge=False, padding=(0, 1))
        feed.add_column("sev", width=9)
        feed.add_column("module", width=18, style="fox.muted")
        feed.add_column("value", overflow="ellipsis")
        for f in reversed(self.findings[-12:]):
            feed.add_row(Text(f["type"], style=SEV_STYLE.get(f.get("severity", "info"), "fox.info")),
                         f["module"], str(f["value"]))

        header = Table.grid(padding=(0, 2))
        header.add_column(justify="left")
        header.add_column(justify="right")
        header.add_row(
            Text(f" target: {self.domain} ", style="bold black on orange3"),
            Text(f"{len(self.findings)} findings  •  {len(self.errors)} errors", style="fox.muted"),
        )
        return Group(
            header,
            Panel(stages, title="[bold]pipeline[/]", border_style="fox.border", box=box.ROUNDED),
            Panel(feed, title="[bold]findings feed[/]", border_style="fox.border", box=box.ROUNDED),
      )
