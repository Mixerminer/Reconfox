"""Core data models shared across all Reconfox modules."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single recon result produced by any module."""
    module: str
    type: str
    value: str
    severity: Severity = Severity.INFO
    detail: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "module": self.module,
            "type": self.type,
            "severity": self.severity.value,
            "value": self.value,
            "detail": self.detail,
        }


@dataclass
class Target:
    """A target hostname/IP flowing through the pipeline."""
    host: str
    resolved_ips: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Mutable shared state passed through pipeline stages."""
    domain: str
    targets: list[Target] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def error(self, msg: str) -> None:
        self.errors.append(msg)
