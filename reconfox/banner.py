"""Reconfox banner — creator names permanently etched."""
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__

CREATORS = "MixerMiner  &  Anonymous-beta  &  samuelanih043-droid"


def render(console: Console) -> None:
    title = Text("  R E C O N F O X  ", style="bold black on orange3", justify="center")
    subtitle = Text(f"v{__version__}  //  unified reconnaissance suite", style="grey58", justify="center")
    authors = Text(f"CRAFTED BY  {CREATORS}", style="bold orange1", justify="center")

    body = Group(
        Text(""),
        title,
        subtitle,
        Text(""),
        authors,
        Text(""),
        Text("dns  •  subdomains  •  ports  •  dirs  •  fingerprint", style="grey58", justify="center"),
    )
    console.print(Panel(body, border_style="orange3", box=box.DOUBLE, padding=(0, 4)))


def console_only() -> str:
    return f"Reconfox v{__version__} — by {CREATORS}"
