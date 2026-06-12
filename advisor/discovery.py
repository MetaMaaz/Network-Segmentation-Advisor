"""Network discovery — the ONLY module that touches the network.

Thin wrapper around nmap (via python-nmap) that produces an ``Inventory``.
Everything intelligent happens downstream in pure-logic modules, which is
what makes the rest of the pipeline testable offline.

Scan results are saved to YAML so a real scan can be replayed through the
analysis pipeline any number of times without re-scanning.

Only scan networks you own or are explicitly authorised to test.
"""

from __future__ import annotations

try:
    import nmap  # type: ignore
except ImportError:  # pragma: no cover - exercised only without the package
    nmap = None

from .models import Host, Inventory, Service


def scan(target: str, ports: str | None = None) -> Inventory:
    """Run a service/version scan (``-sV``) over a target range.

    ``target`` accepts anything nmap does: ``192.168.1.0/24``,
    ``172.28.0.10-20``, a hostname, etc.
    """
    if nmap is None:
        raise RuntimeError(
            "python-nmap is not installed (and the nmap binary is required). "
            "Install with: pip install python-nmap && <pkg manager> install nmap"
        )

    scanner = nmap.PortScanner()
    arguments = "-sV --open"
    scanner.scan(hosts=target, ports=ports, arguments=arguments)

    hosts: list[Host] = []
    for ip in scanner.all_hosts():
        entry = scanner[ip]
        services: list[Service] = []
        for proto in ("tcp", "udp"):
            for port, info in sorted(entry.get(proto, {}).items()):
                if info.get("state") != "open":
                    continue
                version = " ".join(
                    part for part in (info.get("product", ""), info.get("version", ""))
                    if part
                )
                services.append(
                    Service(
                        port=int(port),
                        protocol=proto,
                        name=info.get("name", ""),
                        version=version,
                    )
                )
        hosts.append(
            Host(
                ip=ip,
                hostname=entry.hostname() or "",
                os="",  # OS detection (-O) needs root; left to the operator
                services=services,
            )
        )
    return Inventory(hosts=hosts, source=f"nmap:{target}")
