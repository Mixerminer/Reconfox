"""Directory/content fuzzer driven over a shared httpx client."""
from __future__ import annotations

import uuid

import httpx

from ..models import Finding, ScanContext, Severity
from ..utils import build_client, load_wordlist

INTERESTING_CODES = {200, 201, 301, 302, 303, 307, 308, 401, 403, 405}


class DirFuzzerModule:
    name = "dirs"

    def __init__(self, ctx: ScanContext, wordlist_path=None, base_url: str | None = None,
                 threads: int = 30, timeout: float = 10.0) -> None:
        self.ctx = ctx
        self.words = load_wordlist(wordlist_path, "dirs.txt")
        scheme = "https"
        self.base = base_url or f"{scheme}://{ctx.domain}"
        self.threads = threads
        self.timeout = timeout

    def run(self) -> None:
        if not self.words:
            self.ctx.error("dir fuzz: empty wordlist, skipping")
            return
        client = build_client(timeout=self.timeout)
        try:
            baseline = self._baseline_len(client)
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futs = [pool.submit(self._probe, client, w, baseline) for w in self.words]
                for fut in as_completed(futs):
                    try:
                        res = fut.result()
                    except Exception:
                        continue
                    if res:
                        word, status, length = res
                        sev = Severity.MEDIUM if status in (200, 401, 403) else Severity.LOW
                        self.ctx.add(Finding(self.name, "dir", f"{self.base}/{word}",
                                             severity=sev,
                                             detail={"status": status, "length": length}))
        finally:
            client.close()

    def _baseline_len(self, client: httpx.Client) -> int:
        """Soft-filter: capture length of a guaranteed-nonexistent path's response."""
        try:
            r = client.get(f"{self.base}/rfx-{uuid.uuid4().hex[:10]}")
            return len(r.content)
        except Exception:
            return -1

    def _probe(self, client: httpx.Client, word: str, baseline: int):
        try:
            r = client.get(f"{self.base}/{word}")
            if r.status_code in INTERESTING_CODES:
                # soft-404 filter: 200 with identical length to the random-path baseline
                if baseline > 0 and r.status_code == 200 and len(r.content) == baseline:
                    return None
                return (word, r.status_code, len(r.content))
        except Exception:
            return None
        return None