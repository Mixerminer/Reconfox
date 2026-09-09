"""Active subdomain brute-force with wildcard filtering and concurrent resolution."""
from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Finding, ScanContext
from ..utils import load_wordlist
from .dns_resolver import DNSResolverModule


class ActiveSubdomainModule:
    name = "subdomain_active"

    def __init__(self, ctx: ScanContext, wordlist_path=None, threads: int = 50) -> None:
        self.ctx = ctx
        self.threads = threads
        self.words = load_wordlist(wordlist_path, "subdomains.txt")

    def run(self) -> set[str]:
        if not self.words:
            self.ctx.error("active subs: empty wordlist, skipping")
            return set()

        # Wildcard detection: resolve a random nonexistent host
        probe = f"{random.randint(10**6, 10**7)}.{'x' * 12}.{self.ctx.domain}"
        wildcard_ips = set(DNSResolverModule.resolve_host(probe))

        found: set[str] = set()
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {
                pool.submit(DNSResolverModule.resolve_host, f"{w}.{self.ctx.domain}"): w
                for w in self.words
            }
            for fut in as_completed(futs):
                word = futs[fut]
                try:
                    ips = fut.result() or []
                except Exception:
                    continue
                if not ips or set(ips) == wildcard_ips:
                    continue
                host = f"{word}.{self.ctx.domain}"
                if host not in found:
                    found.add(host)
                    self.ctx.add(Finding(self.name, "subdomain", host, detail={"ips": ips}))
        return found
