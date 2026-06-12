"""Render the analysis into deliverables: Markdown report, Mermaid zone
diagram, and enforceable config via the exporters.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .attack_path import AttackResult, format_path
from .exporters import iptables, pfsense
from .models import Inventory, Rule, Violation, Zone

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _mermaid_id(name: str) -> str:
    return name.replace("-", "_").replace(".", "_")


def zone_diagram(zones: list[Zone], rules: list[Rule]) -> str:
    """Mermaid flowchart: zones as subgraphs, allow rules as labelled edges."""
    lines = ["flowchart TB"]
    for zone in zones:
        zid = _mermaid_id(zone.name)
        lines.append(f'    subgraph {zid}["{zone.name} ({zone.subnet})"]')
        for host in zone.hosts:
            hid = _mermaid_id(f"{zid}_{host.label}")
            lines.append(f'        {hid}["{host.label}<br/>{host.role}"]')
        lines.append("    end")

    # Collapse per-port rules into one edge per zone pair.
    edges: dict[tuple[str, str], list[int]] = {}
    for rule in rules:
        if rule.action == "allow" and rule.port is not None:
            edges.setdefault((rule.src_zone, rule.dst_zone), []).append(rule.port)
    for (src, dst), ports in edges.items():
        label = ",".join(str(p) for p in sorted(set(ports)))
        lines.append(f"    {_mermaid_id(src)} -->|{label}| {_mermaid_id(dst)}")
    lines.append("    %% All other inter-zone traffic: default deny")
    return "\n".join(lines)


def _inventory_section(inventory: Inventory) -> list[str]:
    lines = [
        "## 2. Asset inventory and classification",
        "",
        "| Host | IP | Role | Sensitivity | Key services |",
        "|---|---|---|---|---|",
    ]
    for h in inventory.hosts:
        services = ", ".join(
            f"{s.port}/{s.protocol} {s.name}".strip() for s in h.services
        )
        lines.append(
            f"| {h.label} | {h.ip} | {h.role} | {h.sensitivity} | {services} |"
        )
    lines.append("")
    return lines


def _violations_section(violations: list[Violation]) -> list[str]:
    lines = ["## 3. Violations in the current layout", ""]
    if not violations:
        lines += ["No violations detected.", ""]
        return lines
    ordered = sorted(violations, key=lambda v: SEVERITY_ORDER.get(v.severity, 9))
    for v in ordered:
        lines += [
            f"### [{v.severity.upper()}] {v.title}",
            "",
            v.detail,
            "",
            f"*Affected:* {', '.join(v.affected_hosts)}",
            "",
            f"*Framework:* {v.framework_ref}",
            "",
        ]
    return lines


def _zones_section(zones: list[Zone], diagram: str) -> list[str]:
    lines = [
        "## 4. Proposed zones",
        "",
        "| Zone | Trust tier | Proposed subnet | Hosts |",
        "|---|---|---|---|",
    ]
    for z in zones:
        members = ", ".join(h.label for h in z.hosts)
        lines.append(f"| {z.name} | {z.trust_tier} | {z.subnet} | {members} |")
    lines += ["", "```mermaid", diagram, "```", ""]
    return lines


def _rules_section(rules: list[Rule]) -> list[str]:
    lines = [
        "## 5. Inter-zone ruleset (least privilege)",
        "",
        "| # | Source | Destination | Port | Action | Justification |",
        "|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rules, 1):
        port = "any" if r.port is None else str(r.port)
        lines.append(
            f"| {i} | {r.src_zone} | {r.dst_zone} | {port}/{r.protocol} "
            f"| **{r.action}** | {r.justification} |"
        )
    lines.append("")
    return lines


def _attack_section(before: AttackResult, after: AttackResult) -> list[str]:
    lines = [
        "## 6. Attack-path analysis — before vs after",
        "",
        f"Simulated foothold: **{before.compromised}** (assumed phished "
        "workstation). \"Owned\" means the attacker can pivot through the host "
        "via a remote-admin service (SSH/RDP/SMB/RPC/Telnet/WinRM); \"exposed\" "
        "means at least one service is reachable.",
        "",
        "| Metric | Before (flat) | After (segmented) |",
        "|---|---|---|",
        f"| Hosts owned (beyond foothold) | {before.owned_count} | {after.owned_count} |",
        f"| Hosts with services exposed | {len(before.exposed)} | {len(after.exposed)} |",
        f"| **Critical assets owned** | **{len(before.critical_owned)}**"
        f" ({', '.join(before.critical_owned) or '—'}) "
        f"| **{len(after.critical_owned)}**"
        f" ({', '.join(after.critical_owned) or '—'}) |",
        "",
        "### Example attack paths cut by segmentation",
        "",
    ]
    cut = [label for label in before.owned if label not in after.owned]
    shown = 0
    for label in cut:
        if shown >= 6:
            break
        lines.append(
            f"- `{format_path(before.owned[label])}` — **blocked** after "
            "segmentation (no allow rule carries pivot traffic across zones)."
        )
        shown += 1
    if not cut:
        lines.append("- No paths were cut — review the proposed policy.")
    lines += [
        "",
        "### Residual risk (honest caveats)",
        "",
        "- Intra-zone traffic is unrestricted: a compromised workstation can "
        "still attack its neighbours. Host-level micro-segmentation is the "
        "next maturity step (NIST SP 800-207 §3.1.1).",
        "- Services that remain exposed by design (e.g. web ports, "
        "Kerberos/LDAP to the DCs) are still application-layer attack "
        "surface; segmentation reduces, not eliminates, risk.",
        "",
    ]
    return lines


def build_report(
    inventory: Inventory,
    zones: list[Zone],
    rules: list[Rule],
    violations: list[Violation],
    before: AttackResult,
    after: AttackResult,
) -> str:
    diagram = zone_diagram(zones, rules)
    allow_count = sum(1 for r in rules if r.action == "allow")
    high = sum(1 for v in violations if v.severity == "high")

    lines: list[str] = [
        "# Network Segmentation Advisory Report",
        "",
        f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        f" · Source: `{inventory.source or 'unknown'}` ·"
        f" {len(inventory.hosts)} hosts*",
        "",
        "## 1. Executive summary",
        "",
        f"The current network is assessed against zero-trust principles "
        f"(NIST SP 800-207) and PCI DSS segmentation guidance. "
        f"**{len(violations)} violations** were found ({high} high severity). "
        f"The proposed design groups assets into **{len(zones)} zones** with "
        f"**{allow_count} explicit allow rules** over a default-deny baseline. "
        f"Simulating a compromised workstation, lateral movement drops from "
        f"**{before.owned_count} hosts owned** (including "
        f"{len(before.critical_owned)} critical assets) to "
        f"**{after.owned_count}** ({len(after.critical_owned)} critical).",
        "",
    ]
    lines += _inventory_section(inventory)
    lines += _violations_section(violations)
    lines += _zones_section(zones, diagram)
    lines += _rules_section(rules)
    lines += _attack_section(before, after)
    lines += [
        "## 7. Enforcement artifacts",
        "",
        "- `iptables.rules` — Linux zone-router FORWARD-chain policy",
        "- `pfsense_rules.txt` — pfSense per-interface pass rules",
        "",
        "## Appendix: methodology",
        "",
        "Classification is signature-based (`data/role_signatures.yaml`): "
        "data-driven port/service heuristics, highest priority wins. Zoning "
        "maps roles to trust tiers. The ruleset starts from default-deny and "
        "adds only allows implied by roles actually observed — ports are "
        "never opened speculatively. The attack-path model treats any "
        "reachable service as exposure and remote-admin services as pivot "
        "channels. Every output cites the framework principle it implements.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(
    inventory: Inventory,
    zones: list[Zone],
    rules: list[Rule],
    violations: list[Violation],
    before: AttackResult,
    after: AttackResult,
    out_dir: str | Path,
) -> list[Path]:
    """Write report.md, zones.mmd and exporter configs. Returns paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "report.md": build_report(inventory, zones, rules, violations, before, after),
        "zones.mmd": zone_diagram(zones, rules) + "\n",
        "iptables.rules": iptables.export(zones, rules),
        "pfsense_rules.txt": pfsense.export(zones, rules),
    }
    paths = []
    for name, content in artifacts.items():
        path = out / name
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    return paths
