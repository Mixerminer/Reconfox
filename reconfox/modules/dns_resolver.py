"""Concurrent DNS resolution with multiple record types and resilient resolvers."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from ..models import Finding, ScanContext, Target
from ..utils import retry

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSResolverModule:
    name = "dns"

    def __init__(self, ctx: ScanContext, threads: int = 20) -> None:
        self.ctx = ctx
        self.threads = threads
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = RESOLVERS
        self.resolver.timeout = 5
        self.resolver.lifetime = 8

    def run(self) -> None:
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {
                pool.submit(self._query, self.ctx.domain, rt): rt
                for rt in RECORD_TYPES
            }
            for fut in as_completed(futs):
                rt = futs[fut]
                try:
                    records = fut.result() or []
                except Exception:
                    records = []
                for r in records:
                    self.ctx.add(Finding(self.name, f"dns_{rt.lower()}", r))
                    if rt == "A":
                        try:
                            ipaddress.ip_address(r)
                            self.ctx.targets.append(Target(host=self.ctx.domain, resolved_ips=records))
                        except ValueError:
                            pass

    @retry(attempts=3)
    def _query(self, domain: str, rtype: str) -> list[str]:
        try:
            answers = self.resolver.resolve(domain, rtype)
        except Exception:
            return []
        return [str(a).rstrip(".") for a in answers]

    @staticmethod
    def resolve_host(host: str) -> list[str]:
        """Simple socket-based resolution used by other modules."""
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except socket.gaierror:
            return []
