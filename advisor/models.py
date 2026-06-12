"""Core data structures shared by every stage of the pipeline.

Discovery (or a hand-written mock YAML file) produces an ``Inventory``; the
classifier, recommender, attack-path analyser and reporter all consume it.
Nothing in this module touches the network — that hard separation is what
makes the interesting logic testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

SENSITIVITY_TIERS = ("critical", "high", "medium", "standard", "untrusted")


@dataclass
class Service:
    """A single open service on a host (one nmap result row)."""

    port: int
    protocol: str = "tcp"
    name: str = ""
    version: str = ""


@dataclass
class Host:
    """A discovered network asset, annotated by the classifier."""

    ip: str
    hostname: str = ""
    os: str = ""
    services: list[Service] = field(default_factory=list)
    role: str | None = None          # set by classifier
    sensitivity: str | None = None   # set by classifier

    @property
    def open_ports(self) -> set[int]:
        return {s.port for s in self.services}

    @property
    def service_names(self) -> set[str]:
        return {s.name for s in self.services if s.name}

    @property
    def label(self) -> str:
        """Human-friendly identifier used in reports and attack paths."""
        return self.hostname or self.ip


@dataclass
class Zone:
    """A proposed segmentation zone (VLAN / subnet)."""

    name: str
    description: str
    trust_tier: str
    subnet: str = ""
    hosts: list[Host] = field(default_factory=list)


@dataclass
class Rule:
    """One inter-zone firewall rule. ``port=None`` means any port.

    Every rule carries a justification citing the framework principle it
    implements — recommendations must never be a black box.
    """

    src_zone: str
    dst_zone: str
    port: int | None
    protocol: str
    action: str  # "allow" | "deny"
    justification: str


@dataclass
class Violation:
    """A segmentation/least-privilege problem found in the *current* layout."""

    title: str
    severity: str  # "high" | "medium" | "low"
    detail: str
    framework_ref: str
    affected_hosts: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    """The single data structure handed between pipeline stages.

    Serialises to/from YAML so a real nmap scan can be replayed offline and
    so mock inventories share the exact same format as live scans.
    """

    hosts: list[Host] = field(default_factory=list)
    source: str = ""  # e.g. "mock", "nmap:192.168.1.0/24"

    def get(self, key: str) -> Host | None:
        """Look a host up by IP or hostname."""
        for h in self.hosts:
            if key in (h.ip, h.hostname):
                return h
        return None

    # ------------------------------------------------------------------
    # YAML round-trip
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os": h.os,
                    **({"role": h.role} if h.role else {}),
                    **({"sensitivity": h.sensitivity} if h.sensitivity else {}),
                    "services": [
                        {
                            "port": s.port,
                            "protocol": s.protocol,
                            "name": s.name,
                            "version": s.version,
                        }
                        for s in h.services
                    ],
                }
                for h in self.hosts
            ],
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False)

    @classmethod
    def from_dict(cls, raw: dict) -> "Inventory":
        hosts = [
            Host(
                ip=h["ip"],
                hostname=h.get("hostname", ""),
                os=h.get("os", "") or "",
                role=h.get("role"),
                sensitivity=h.get("sensitivity"),
                services=[
                    Service(
                        port=int(s["port"]),
                        protocol=s.get("protocol", "tcp"),
                        name=s.get("name", ""),
                        version=s.get("version", "") or "",
                    )
                    for s in h.get("services", [])
                ],
            )
            for h in raw.get("hosts", [])
        ]
        return cls(hosts=hosts, source=raw.get("source", ""))

    @classmethod
    def from_yaml(cls, text: str) -> "Inventory":
        return cls.from_dict(yaml.safe_load(text))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_yaml(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))
