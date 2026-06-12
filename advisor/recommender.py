"""Pure-logic segmentation recommender — the core deliverable.

Takes a classified ``Inventory`` and produces:

1. **Zones** — classified hosts grouped into trust zones with proposed subnets.
2. **Ruleset** — a least-privilege inter-zone firewall policy: default-deny,
   plus only the minimal allows implied by the legitimate roles actually
   observed on the network. Every rule cites the principle it implements.
3. **Violations** — least-privilege problems found in the *current* (flat)
   layout, each mapped to NIST SP 800-207 or PCI DSS.

No ML, no black boxes: every output line traces to an explicit heuristic.
"""

from __future__ import annotations

from .models import Host, Inventory, Rule, Violation, Zone

# ---------------------------------------------------------------------------
# Framework citations used in justifications
# ---------------------------------------------------------------------------
NIST_TENET_LEAST_PRIV = (
    "NIST SP 800-207 §2.1 Tenet 3 — access granted per-session with least privilege"
)
NIST_MICROSEG = "NIST SP 800-207 §3.1.2 — network micro-segmentation"
NIST_NO_IMPLICIT_TRUST = (
    "NIST SP 800-207 §2.1 Tenet 4 — no implicit trust from network location"
)
PCI_RESTRICT = (
    "PCI DSS v4.0 Req 1.2/1.3 — restrict traffic to that which is necessary"
)
PCI_SCOPE = (
    "PCI DSS v4.0 scoping guidance — segmentation isolates the cardholder/"
    "sensitive data environment and reduces audit scope"
)
PCI_INSECURE_SVC = "PCI DSS v4.0 Req 2.2.5 — insecure services/protocols"

# ---------------------------------------------------------------------------
# Zone definitions and role -> zone mapping
# ---------------------------------------------------------------------------
ZONE_META: dict[str, tuple[str, str, str]] = {
    # name: (description, trust_tier, proposed subnet)
    "dmz": ("Public-facing web tier", "exposed", "10.10.10.0/24"),
    "app-tier": ("Internal application services", "internal", "10.10.20.0/24"),
    "data-tier": ("Databases and data stores", "restricted", "10.10.30.0/24"),
    "user-vlan": ("End-user workstations", "internal", "10.10.40.0/24"),
    "iot-vlan": ("Printers, cameras and other IoT", "untrusted", "10.10.50.0/24"),
    "management": ("Identity and administration", "restricted", "10.10.60.0/24"),
    "quarantine": ("Unclassified assets pending review", "untrusted", "10.10.99.0/24"),
}

ROLE_ZONE: dict[str, str] = {
    "web-server": "dmz",
    "app-server": "app-tier",
    "database": "data-tier",
    "file-server": "data-tier",
    "domain-controller": "management",
    "jump-host": "management",
    "workstation": "user-vlan",
    "printer": "iot-vlan",
    "iot": "iot-vlan",
    "unknown": "quarantine",
}

# Port families used when deriving minimal allow rules from observed services.
WEB_PORTS = {80, 443}
APP_PORTS = {5000, 8000, 8080, 8443, 9000}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 27017}
PRINT_PORTS = {515, 631, 9100}
ADMIN_PORTS = {22, 3389}
# Directory/auth services clients legitimately need from a domain controller.
# Deliberately excludes SMB (445): SMB to DCs is a prime lateral-movement
# channel and is restricted to the management zone.
AD_CLIENT_PORTS = {53, 88, 389, 636}

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet"}
MGMT_EXPOSED_PORTS = {22, 23, 3389, 5900}


def build_zones(inventory: Inventory) -> list[Zone]:
    """Group classified hosts into zones (only zones that have members)."""
    zones: dict[str, Zone] = {}
    for host in inventory.hosts:
        zone_name = ROLE_ZONE.get(host.role or "unknown", "quarantine")
        if zone_name not in zones:
            desc, tier, subnet = ZONE_META[zone_name]
            zones[zone_name] = Zone(zone_name, desc, tier, subnet)
        zones[zone_name].hosts.append(host)
    # Stable, report-friendly ordering.
    order = list(ZONE_META)
    return sorted(zones.values(), key=lambda z: order.index(z.name))


def _zone_ports(zone: Zone, port_family: set[int]) -> list[int]:
    """Ports from a family actually observed on hosts inside a zone."""
    observed: set[int] = set()
    for host in zone.hosts:
        observed |= host.open_ports & port_family
    return sorted(observed)


def build_rules(zones: list[Zone]) -> list[Rule]:
    """Generate the least-privilege inter-zone ruleset.

    Strategy: start from default-deny, then add only the allows implied by
    the roles actually present. A rule is only emitted if both endpoint
    zones exist and the destination zone really exposes the port — no
    speculative openings.
    """
    by_name = {z.name: z for z in zones}
    rules: list[Rule] = []

    def allow(src: str, dst: str, port: int, why: str) -> None:
        if src in by_name and dst in by_name:
            rules.append(Rule(src, dst, port, "tcp", "allow", why))

    def allow_observed(src: str, dst: str, family: set[int], why: str) -> None:
        if dst not in by_name:
            return
        for port in _zone_ports(by_name[dst], family):
            allow(src, dst, port, why)

    # Users consume published web services — and nothing else from the DMZ.
    allow_observed(
        "user-vlan", "dmz", WEB_PORTS,
        f"Users may reach published web services only; {NIST_TENET_LEAST_PRIV}",
    )
    # Web tier calls internal application APIs.
    allow_observed(
        "dmz", "app-tier", APP_PORTS,
        f"Web tier may call internal app APIs on observed ports only; {PCI_RESTRICT}",
    )
    # Users reach internal apps directly (intranet applications).
    allow_observed(
        "user-vlan", "app-tier", APP_PORTS,
        f"Users may reach internal applications on observed ports; {NIST_TENET_LEAST_PRIV}",
    )
    # Only the app tier talks to databases — never users, never the DMZ.
    allow_observed(
        "app-tier", "data-tier", DB_PORTS,
        "Only the application tier may query databases, on observed DB ports; "
        f"{PCI_SCOPE}",
    )
    # Domain-joined zones need directory services from the DCs.
    for src in ("user-vlan", "app-tier"):
        allow_observed(
            src, "management", AD_CLIENT_PORTS,
            "Domain clients need DNS/Kerberos/LDAP from domain controllers; "
            f"SMB (445) deliberately excluded — {NIST_NO_IMPLICIT_TRUST}",
        )
    # Printing is the only thing users need from the IoT VLAN.
    allow_observed(
        "user-vlan", "iot-vlan", PRINT_PORTS,
        f"Workstations may print, nothing more; IoT stays isolated — {NIST_MICROSEG}",
    )
    # All administration originates from the management zone.
    for zone in zones:
        if zone.name == "management":
            continue
        for port in _zone_ports(zone, ADMIN_PORTS):
            allow(
                "management", zone.name, port,
                "Administrative access (SSH/RDP) originates only from the "
                f"management zone via the jump host; {NIST_TENET_LEAST_PRIV}",
            )

    # Everything not explicitly allowed is denied.
    rules.append(
        Rule(
            "*", "*", None, "any", "deny",
            f"Zero-trust default-deny between zones; {NIST_MICROSEG}; {PCI_RESTRICT}",
        )
    )
    return rules


# ---------------------------------------------------------------------------
# Violations in the current (pre-segmentation) layout
# ---------------------------------------------------------------------------
def _subnet_of(host: Host) -> str:
    return ".".join(host.ip.split(".")[:3]) + ".0/24"


def find_violations(inventory: Inventory) -> list[Violation]:
    violations: list[Violation] = []
    hosts = inventory.hosts
    subnets = {_subnet_of(h) for h in hosts}
    flat = len(subnets) == 1

    if flat:
        violations.append(
            Violation(
                title="Flat network — no segmentation",
                severity="high",
                detail=(
                    f"All {len(hosts)} hosts share {next(iter(subnets))}. Any "
                    "compromised host can attempt connections to every service "
                    "on the network; trust is implied by network location."
                ),
                framework_ref=f"{NIST_NO_IMPLICIT_TRUST}; {NIST_MICROSEG}",
                affected_hosts=[h.label for h in hosts],
            )
        )

    workstation_subnets = {_subnet_of(h) for h in hosts if h.role == "workstation"}

    def shares_user_subnet(host: Host) -> bool:
        return flat or _subnet_of(host) in workstation_subnets

    dbs = [h for h in hosts if h.role in ("database", "file-server")
           and shares_user_subnet(h)]
    if dbs:
        violations.append(
            Violation(
                title="Critical data stores directly reachable from user workstations",
                severity="high",
                detail=(
                    "Database/file-store ports are reachable from the user "
                    "segment with no policy enforcement point in between. A "
                    "single phished workstation is one hop from the data."
                ),
                framework_ref=f"{NIST_TENET_LEAST_PRIV}; {PCI_SCOPE}",
                affected_hosts=[h.label for h in dbs],
            )
        )

    iot = [h for h in hosts if h.role in ("printer", "iot") and shares_user_subnet(h)]
    if iot:
        violations.append(
            Violation(
                title="Unmanaged IoT devices share a segment with workstations",
                severity="medium",
                detail=(
                    "Printers/cameras are rarely patched and frequently expose "
                    "weak services; co-locating them with user endpoints gives "
                    "an attacker an easy persistence point."
                ),
                framework_ref=NIST_MICROSEG,
                affected_hosts=[h.label for h in iot],
            )
        )

    exposed = [
        h for h in hosts
        if h.role != "workstation" and h.open_ports & MGMT_EXPOSED_PORTS
        and shares_user_subnet(h)
    ]
    if exposed:
        violations.append(
            Violation(
                title="Management interfaces exposed to the entire network",
                severity="high",
                detail=(
                    "SSH/RDP/Telnet/VNC on servers is reachable from every "
                    "host. Administrative access should originate only from a "
                    "management zone or jump host."
                ),
                framework_ref=f"{NIST_TENET_LEAST_PRIV}; {PCI_RESTRICT}",
                affected_hosts=[h.label for h in exposed],
            )
        )

    cleartext = [
        (h, p) for h in hosts for p in sorted(h.open_ports & set(CLEARTEXT_PORTS))
    ]
    if cleartext:
        violations.append(
            Violation(
                title="Cleartext management protocols in use",
                severity="high",
                detail="; ".join(
                    f"{h.label} exposes {CLEARTEXT_PORTS[p]} ({p}/tcp)"
                    for h, p in cleartext
                )
                + ". Credentials cross the wire unencrypted.",
                framework_ref=PCI_INSECURE_SVC,
                affected_hosts=sorted({h.label for h, _ in cleartext}),
            )
        )

    unknown = [h for h in hosts if h.role == "unknown"]
    if unknown:
        violations.append(
            Violation(
                title="Unclassified assets on the network",
                severity="low",
                detail=(
                    "These hosts match no known role signature. Zero trust "
                    "grants no implicit access: quarantine until identified."
                ),
                framework_ref=NIST_NO_IMPLICIT_TRUST,
                affected_hosts=[h.label for h in unknown],
            )
        )

    return violations


def recommend(
    inventory: Inventory,
) -> tuple[list[Zone], list[Rule], list[Violation]]:
    """Full recommendation pass: zones, ruleset and current-state violations."""
    zones = build_zones(inventory)
    rules = build_rules(zones)
    violations = find_violations(inventory)
    return zones, rules, violations
