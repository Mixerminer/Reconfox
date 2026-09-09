"""Queue-driven pipeline orchestrating every module with fault isolation."""
from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass

from .config import Config
from .models import ScanContext
from .modules.dns_resolver import DNSResolverModule
from .modules.dir_fuzzer import DirFuzzerModule
from .modules.port_scanner import PortScannerModule
from .modules.subdomain_active import ActiveSubdomainModule
from .modules.subdomain_passive import PassiveSubdomainModule
from .modules.tech_fingerprint import TechFingerprintModule
from .utils import normalize_domain


@dataclass
class StageResult:
    stage: str
    status: str          # ok | error | skipped
    count: int
    elapsed: float


class Pipeline:
    """Each stage pushes findings onto a shared queue consumed by the TUI listener."""

    def __init__(self, cfg: Config, events: queue.Queue) -> None:
        self.cfg = cfg
        self.events = events
        self.ctx = ScanContext(domain=normalize_domain(cfg.domain))
        self._stop = threading.Event()

    # -- event helpers -------------------------------------------------
    def _emit(self, stage: str, status: str, msg: str = "") -> None:
        self.events.put({"type": "stage", "stage": stage, "status": status, "msg": msg})

    # -- pipeline ------------------------------------------------------
    def run(self) -> ScanContext:
        results: list[StageResult] = []

        stages = [
            ("dns", self._stage_dns),
            ("passive_subs", self._stage_passive),
            ("active_subs", self._stage_active),
            ("ports", self._stage_ports),
            ("dirs", self._stage_dirs),
            ("fingerprint", self._stage_fingerprint),
        ]
        enabled = {
            "dns": self.cfg.dns_resolve,
            "passive_subs": self.cfg.passive_subs,
            "active_subs": self.cfg.active_subs,
            "ports": self.cfg.port_scan,
            "dirs": self.cfg.dir_fuzz,
            "fingerprint": self.cfg.fingerprint,
        }

        for name, fn in stages:
            if self._stop.is_set():
                break
            if not enabled[name]:
                self._emit(name, "skipped")
                results.append(StageResult(name, "skipped", 0, 0.0))
                continue
            t0 = time.time()
            self._emit(name, "running")
            try:
                count = fn() or 0
                results.append(StageResult(name, "ok", count, time.time() - t0))
                self._emit(name, "done", f"{count} findings")
            except Exception as e:  # fault tolerance: one bad stage never kills the run
                self.ctx.error(f"{name}: {e}")
                results.append(StageResult(name, "error", 0, time.time() - t0))
                self._emit(name, "error", str(e)[:120])

        self.events.put({"type": "finished", "results": [r.__dict__ for r in results],
                         "elapsed": time.time() - self.ctx.started_at})
        self._save()
        return self.ctx

    def stop(self) -> None:
        self._stop.set()

    # -- stages (run only when enabled — gating handled in run()) ------
    def _stage_dns(self) -> int:
        mod = DNSResolverModule(self.ctx)
        n = len(self.ctx.findings)
        mod.run()
        return len(self.ctx.findings) - n

    def _stage_passive(self) -> int:
        n = len(self.ctx.findings)
        PassiveSubdomainModule(self.ctx).run()
        return len(self.ctx.findings) - n

    def _stage_active(self) -> int:
        n = len(self.ctx.findings)
        ActiveSubdomainModule(self.ctx, self.cfg.wordlist_subs, self.cfg.threads).run()
        return len(self.ctx.findings) - n

    def _stage_ports(self) -> int:
        # ensure at least the apex host is a target
        if not self.ctx.targets:
            from .models import Target
            self.ctx.targets.append(Target(host=self.ctx.domain))
        n = len(self.ctx.findings)
        PortScannerModule(self.ctx, self.cfg).run()
        return len(self.ctx.findings) - n

    def _stage_dirs(self) -> int:
        n = len(self.ctx.findings)
        DirFuzzerModule(self.ctx, self.cfg.wordlist_dirs).run()
        return len(self.ctx.findings) - n

    def _stage_fingerprint(self) -> int:
        n = len(self.ctx.findings)
        sub_hosts = [f.value for f in self.ctx.findings if f.type == "subdomain"][:15]
        TechFingerprintModule(self.ctx, [self.ctx.domain] + sub_hosts).run()
        return len(self.ctx.findings) - n

    # -- persistence ---------------------------------------------------
    def _save(self) -> None:
        payload = {
            "tool": "reconfox",
            "target": self.ctx.domain,
            "started_at": self.ctx.started_at,
            "elapsed": time.time() - self.ctx.started_at,
            "findings": [f.to_dict() for f in self.ctx.findings],
            "errors": self.ctx.errors,
        }
        try:
            self.cfg.output.write_text(json.dumps(payload, indent=2))
        except OSError as e:
            self.ctx.error(f"save failed: {e}")