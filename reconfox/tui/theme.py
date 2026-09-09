"""Reconfox theme — warm ember/fox palette, consistent across the whole TUI."""
from rich.theme import Theme

THEME = Theme({
    "fox.accent": "bold orange3",        # primary ember orange
    "fox.accent2": "bold dark_orange",
    "fox.text": "#e8e0d4",               # warm off-white
    "fox.muted": "grey58",
    "fox.ok": "bold spring_green3",
    "fox.warn": "bold gold3",
    "fox.error": "bold red3",
    "fox.border": "orange3",
    "fox.panel": "#2a1e14",              # deep warm brown
    "fox.critical": "bold bright_red",
    "fox.high": "bold orange_red1",
    "fox.medium": "bold gold3",
    "fox.low": "bold cyan",
    "fox.info": "grey62",
})
