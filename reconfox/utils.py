"""Shared utilities: retrying HTTP client, DNS helpers, wordlist loading."""
from __future__ import annotations

import functools
import random
from pathlib import Path
from typing import Callable, TypeVar

import httpx

T = TypeVar("T")

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def random_ua() -> str:
    return random.choice(UA_POOL)


def build_client(timeout: float = 12.0, verify: bool = False) -> httpx.Client:
    """Fault-tolerant HTTP client: retries, sane limits, HTTP/2."""
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=timeout / 2),
        verify=verify,
        http2=True,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=50),
        headers={"User-Agent": random_ua()},
    )


def retry(attempts: int = 3, delay: float = 0.6, backoff: float = 2.0):
    """Decorator with exponential backoff. Swallows final failure (caller decides)."""
    def deco(fn: Callable[..., T]) -> Callable[..., T | None]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> T | None:
            wait = delay
            for i in range(attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception:
                    if i == attempts - 1:
                        return None
                    import time
                    time.sleep(wait)
                    wait *= backoff
            return None
        return wrapper
    return deco


def load_wordlist(path: Path | None, packaged: str) -> list[str]:
    """Load a wordlist from an explicit path, or from the packaged data dir."""
    if path is None:
        path = Path(__file__).parent / "data" / packaged
    if not path.exists():
        return []
    lines = path.read_text(errors="ignore").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
