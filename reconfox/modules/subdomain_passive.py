"""Passive subdomain discovery: crt.sh, HackerTarget, RapidDNS, Alienvault OTX."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Finding, ScanContext
from ..utils import build_client


class PassiveSubdomainModule:
    name = "subdomain_passive"

    SOURCES = [
        ("crtsh", lambda c, d: _crtsh(c, d)),
        ("hackertarget", lambda c, d: _hackertarget(c, d)),
        ("rapiddns", lambda c, d: _rapiddns(c, d)),
        ("otx", lambda c, d: _otx(c, d)),
    ]

    def __init__(self, ctx: ScanContext, timeout: float = 15.0) -> None:
        self.ctx = ctx
        self.timeout = timeout

    def run(self) -> set[str]:
        found: set[str] = set()
        client = build_client(timeout=self.timeout)
        try:
            with ThreadPoolExecutor(max_workers=len(self.SOURCES)) as pool:
                futs = {
                    pool.submit(fn, client, self.ctx.domain): src
                    for src, fn in self.SOURCES
                }
                for fut in as_completed(futs):
                    src = futs[fut]
                    try:
                        subs = fut.result() or set()
                    except Exception:
                        self.ctx.error(f"passive source failed: {src}")
                        subs = set()
                    for s in subs:
                        if s not in found:
                            found.add(s)
                            self.ctx.add(Finding(self.name, "subdomain", s, detail={"source": src}))
        finally:
            client.close()
        return found


def _crtsh(client, domain: str) -> set[str]:
    r = client.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
    subs = set()
    for row in r.json():
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain):
                subs.add(name)
    return subs


def _hackertarget(client, domain: str) -> set[str]:
    r = client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
    subs = set()
    if r.status_code == 200 and "API count exceeded" not in r.text:
        for line in r.text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain):
                subs.add(host)
    return subs


def _rapiddns(client, domain: str) -> set[str]:
    import re
    r = client.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=20)
    return {
        m.lower()
        for m in re.findall(r"[a-zA-Z0-9_.-]+\." + re.escape(domain), r.text)
    }


def _otx(client, domain: str) -> set[str]:
    r = client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                   timeout=25)
    subs = set()
    if r.status_code == 200:
        data = json.loads(r.text)
        for e in data.get("passive_dns", []):
            h = e.get("hostname", "").lower()
            if h.endswith(domain):
                subs.add(h)
    return subs
