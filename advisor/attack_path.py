"""Before/after lateral-movement analysis (pure logic).

Models the network as a reachability graph and simulates an attacker who has
compromised one host (default: a workstation — the realistic phishing entry
point). The simulation runs twice:

* **before** — the current flat network: every service on every host is
  reachable from everywhere.
* **after**  — the proposed segmentation applied: a host can only reach
  ports permitted by the inter-zone allow rules (intra-zone traffic is
  unrestricted; micro-segmentation within a zone is listed as future work).

Threat model (documented, deliberately simple and defensible):

* Reaching any open port = the service is *exposed* to the attacker.
* The attacker can *pivot* (gain code execution and continue) only through
  remote-administration services: SSH, Telnet, RDP, SMB/RPC, WinRM.
  Merely being able to browse a web port does not grant a foothold. This is
  a conservative simplification — exploitable app-layer bugs exist — but it
  cleanly separates "can touch" from "can own" and matches how lateral
  movement is actually performed with harvested credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Host, Inventory, Rule, Zone

#: Services an attacker can realistically pivot through with credentials.
PIVOT_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}


@dataclass
class AttackResult:
    """Outcome of one simulation run."""

    scenario: str            # "before" | "after"
    compromised: str         # label of the initial foothold
    owned: dict[str, list[str]] = field(default_factory=dict)
    #: label -> attack path (chain of pivots from the foothold)
    exposed: dict[str, set[int]] = field(default_factory=dict)
    #: label -> ports reachable from any owned host
    critical_owned: list[str] = field(default_factory=list)
    critical_exposed: list[str] = field(default_factory=list)

    @property
    def owned_count(self) -> int:
        """Hosts owned beyond the initial foothold."""
        return len(self.owned) - 1


def _zone_map(zones: list[Zone] | None) -> dict[str, str]:
    if not zones:
        return {}
    return {h.label: z.name for z in zones for h in z.hosts}


def reachable_ports(
    src: Host,
    dst: Host,
    zone_of: dict[str, str],
    rules: list[Rule] | None,
) -> set[int]:
    """Ports on ``dst`` that ``src`` can reach under the given policy.

    With no policy (flat network) every open port is reachable. Under the
    proposed policy, intra-zone traffic is unrestricted and inter-zone
    traffic must match an explicit allow rule.
    """
    if rules is None or not zone_of:
        return set(dst.open_ports)

    src_zone = zone_of.get(src.label)
    dst_zone = zone_of.get(dst.label)
    if src_zone is None or dst_zone is None:
        return set()
    if src_zone == dst_zone:
        return set(dst.open_ports)

    allowed: set[int] = set()
    for rule in rules:
        if rule.action != "allow":
            continue
        if rule.src_zone != src_zone or rule.dst_zone != dst_zone:
            continue
        if rule.port is None:
            return set(dst.open_ports)
        if rule.port in dst.open_ports:
            allowed.add(rule.port)
    return allowed


def simulate(
    inventory: Inventory,
    zones: list[Zone] | None = None,
    rules: list[Rule] | None = None,
    compromised: str | None = None,
    scenario: str = "",
) -> AttackResult:
    """Breadth-first lateral-movement simulation from one foothold."""
    hosts = inventory.hosts
    start = _resolve_start(inventory, compromised)
    zone_of = _zone_map(zones)

    result = AttackResult(scenario=scenario, compromised=start.label)
    result.owned[start.label] = [start.label]
    queue: list[Host] = [start]

    while queue:
        src = queue.pop(0)
        for dst in hosts:
            if dst.label == src.label:
                continue
            ports = reachable_ports(src, dst, zone_of, rules)
            if not ports:
                continue
            result.exposed.setdefault(dst.label, set()).update(ports)
            if dst.label not in result.owned and ports & PIVOT_PORTS:
                result.owned[dst.label] = result.owned[src.label] + [dst.label]
                queue.append(dst)

    result.critical_owned = sorted(
        h.label for h in hosts
        if h.sensitivity == "critical" and h.label in result.owned
    )
    result.critical_exposed = sorted(
        h.label for h in hosts
        if h.sensitivity == "critical" and h.label in result.exposed
    )
    return result


def _resolve_start(inventory: Inventory, compromised: str | None) -> Host:
    if compromised:
        host = inventory.get(compromised)
        if host is None:
            raise ValueError(f"unknown host: {compromised!r}")
        return host
    for host in inventory.hosts:
        if host.role == "workstation":
            return host
    return inventory.hosts[0]


def analyze(
    inventory: Inventory,
    zones: list[Zone],
    rules: list[Rule],
    compromised: str | None = None,
) -> tuple[AttackResult, AttackResult]:
    """Run the before (flat) and after (segmented) simulations."""
    before = simulate(inventory, compromised=compromised, scenario="before")
    after = simulate(
        inventory, zones=zones, rules=rules,
        compromised=compromised, scenario="after",
    )
    return before, after


def format_path(path: list[str]) -> str:
    return " → ".join(path)
