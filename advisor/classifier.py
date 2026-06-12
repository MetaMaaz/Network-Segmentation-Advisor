"""Pure-logic host classification (no network access).

Loads ``data/role_signatures.yaml`` and assigns each host a role and a
sensitivity tier. Deliberately rules-based rather than ML: every
classification traces back to a named signature with a written rationale,
so any decision the tool makes can be defended line by line.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Host, Inventory

DEFAULT_SIGNATURES = (
    Path(__file__).resolve().parent.parent / "data" / "role_signatures.yaml"
)


@dataclass
class Signature:
    """One classification heuristic loaded from YAML."""

    name: str
    role: str
    sensitivity: str
    priority: int
    rationale: str = ""
    ports_all: set[int] = field(default_factory=set)
    ports_any: set[int] = field(default_factory=set)
    ports_only: set[int] = field(default_factory=set)
    ports_none: set[int] = field(default_factory=set)
    service_names_any: set[str] = field(default_factory=set)
    os_contains_any: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict) -> "Signature":
        m = raw.get("match", {}) or {}
        return cls(
            name=raw["name"],
            role=raw["role"],
            sensitivity=raw["sensitivity"],
            priority=int(raw.get("priority", 0)),
            rationale=(raw.get("rationale") or "").strip(),
            ports_all=set(m.get("ports_all", [])),
            ports_any=set(m.get("ports_any", [])),
            ports_only=set(m.get("ports_only", [])),
            ports_none=set(m.get("ports_none", [])),
            service_names_any={s.lower() for s in m.get("service_names_any", [])},
            os_contains_any=[s.lower() for s in m.get("os_contains_any", [])],
        )

    def _has_matchers(self) -> bool:
        return any(
            (
                self.ports_all,
                self.ports_any,
                self.ports_only,
                self.ports_none,
                self.service_names_any,
                self.os_contains_any,
            )
        )

    def matches(self, host: Host) -> bool:
        if not self._has_matchers():
            # A signature with no matchers would match everything — refuse.
            return False
        ports = host.open_ports
        if self.ports_all and not self.ports_all <= ports:
            return False
        if self.ports_any and not self.ports_any & ports:
            return False
        if self.ports_only and not ports <= self.ports_only:
            return False
        if self.ports_none and self.ports_none & ports:
            return False
        if self.service_names_any:
            names = {n.lower() for n in host.service_names}
            if not self.service_names_any & names:
                return False
        if self.os_contains_any:
            os_lower = host.os.lower()
            if not any(frag in os_lower for frag in self.os_contains_any):
                return False
        return True


class Classifier:
    """Assigns role + sensitivity to each host from data-driven signatures."""

    def __init__(self, signatures_path: str | Path = DEFAULT_SIGNATURES) -> None:
        raw = yaml.safe_load(Path(signatures_path).read_text(encoding="utf-8"))
        self.signatures: list[Signature] = sorted(
            (Signature.from_dict(s) for s in raw.get("signatures", [])),
            key=lambda s: -s.priority,
        )
        default = raw.get("default", {}) or {}
        self.default_role: str = default.get("role", "unknown")
        self.default_sensitivity: str = default.get("sensitivity", "standard")

    def match_signature(self, host: Host) -> Signature | None:
        """Return the highest-priority signature matching this host."""
        for sig in self.signatures:
            if sig.matches(host):
                return sig
        return None

    def classify_host(self, host: Host) -> Host:
        sig = self.match_signature(host)
        if sig is not None:
            host.role = sig.role
            host.sensitivity = sig.sensitivity
        else:
            host.role = self.default_role
            host.sensitivity = self.default_sensitivity
        return host

    def classify(self, inventory: Inventory) -> Inventory:
        for host in inventory.hosts:
            self.classify_host(host)
        return inventory
