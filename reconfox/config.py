"""Runtime configuration with sane defaults."""
from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    domain: str
    wordlist_subs: Path | None = None
    wordlist_dirs: Path | None = None
    threads: int = 40
    timeout: float = 10.0
    ports: str = "top100"          # top100 | all | custom spec "22,80,443,8000-8100"
    active_subs: bool = True
    passive_subs: bool = True
    port_scan: bool = True
    dir_fuzz: bool = True
    fingerprint: bool = True
    output: Path = Path("reconfox_results.json")
    rate_limit: int = 0            # req/s, 0 = unlimited
    insecure_tls: bool = True

    @property
    def ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


def parse_ports(spec: str) -> list[int]:
    """Parse '80,443,8000-8100' into a sorted port list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


TOP_100_PORTS = [
    21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 113, 135, 139, 143, 144, 179, 199, 443, 445,
    465, 514, 515, 540, 554, 587, 623, 631, 636, 873, 990, 993, 995, 1080, 1099, 1194, 1433,
    1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2121, 2181, 2375, 2376, 3000, 3128, 3268,
    3306, 3389, 3690, 4444, 4505, 4506, 5000, 5060, 5353, 5432, 5439, 5555, 5601, 5900, 5984,
    6379, 6443, 6667, 7001, 7077, 8000, 8008, 8009, 8010, 8020, 8042, 8080, 8081, 8088, 8090,
    8161, 8181, 8443, 8500, 8765, 8888, 9000, 9080, 9090, 9092, 9200, 9300, 9418, 9600, 9999,
    11211, 15672, 27017, 28017, 50000, 50030, 50070, 61616,
  ]
