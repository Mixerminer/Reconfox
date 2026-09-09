"""Async TCP connect scanner with service banner grabbing."""
from __future__ import annotations

import asyncio
import socket

from ..config import Config, TOP_100_PORTS, parse_ports
from ..models import Finding, ScanContext

SERVICE_PROBES = {80: b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n", 8080: b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"}
COMMON_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
                110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
                3389: "rdp", 5432: "postgres", 6379: "redis", 8080: "http-alt",
                8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch"}


class PortScannerModule:
    name = "ports"

    def __init__(self, ctx: ScanContext, cfg: Config) -> None:
        self.ctx = ctx
        self.cfg = cfg
        if cfg.ports == "top100":
            self.ports = TOP_100_PORTS
        elif cfg.ports == "all":
            self.ports = list(range(1, 65536))
        else:
            self.ports = parse_ports(cfg.ports)
        self.concurrency = 500

    async def run_async(self) -> None:
        targets = [t.host for t in self.ctx.targets] or [self.ctx.domain]
        sem = asyncio.Semaphore(self.concurrency)
        loop = asyncio.get_running_loop()

        async def probe(ip: str, port: int):
            async with sem:
                try:
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=self.cfg.timeout
                    )
                except Exception:
                    return None
                banner = await self._grab_banner(w, ip, port)
                try:
                    w.close()
                except Exception:
                    pass
                return (ip, port, banner)

        tasks = [probe(ip, p) for ip in targets for p in self.ports]
        for fut in asyncio.as_completed(tasks):
            res = await fut
            if res is None:
                continue
            ip, port, banner = res
            self.ctx.add(Finding(
                self.name, "open_port", f"{ip}:{port}",
                detail={"service": COMMON_PORTS.get(port, "unknown"), "banner": banner or ""},
            ))

    async def _grab_banner(self, writer: asyncio.StreamWriter, ip: str, port: int) -> str | None:
        try:
            if port in SERVICE_PROBES:
                writer.write(SERVICE_PROBES[port].format(host=ip).encode())
                await writer.drain()
            data = await asyncio.wait_for(writer.read(256), timeout=3)
            return data.decode(errors="replace").strip()
        except Exception:
            return None

    def run(self) -> None:
        asyncio.run(self.run_async())
