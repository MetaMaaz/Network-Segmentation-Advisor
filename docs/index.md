---
title: Network Segmentation Advisor
description: A zero-trust segmentation advisor that turns a network inventory into a least-privilege, framework-justified firewall plan.
---

# Network Segmentation Advisor

A zero-trust segmentation advisor: it takes a network inventory (a live Nmap scan or replayed YAML), classifies every host by role and sensitivity, and produces a least-privilege segmentation plan — security zones, an inter-zone firewall ruleset where every rule cites the NIST SP 800-207 / PCI DSS principle it implements, and a before/after attack-path simulation that shows how much lateral movement the plan removes.

Scanning a network is table stakes — Nmap already does that. The point here is the advisory engine on top: explainable, framework-grounded recommendations plus enforceable config (iptables / pfSense), not prose advice.

## The result, in one example

```
ws-01 compromised (phished workstation)
before (flat):     owns 11 of 13 other hosts — including both databases and the domain controller
after (segmented): owns 3 (its own VLAN)   — 0 critical assets reachable on a pivot port
```

## Explore

- [Source code & quickstart on GitHub](https://github.com/MetaMaaz/Network-Segmentation-Advisor)
- [Sample report](https://github.com/MetaMaaz/Network-Segmentation-Advisor/blob/main/docs/sample-output/report.md) — inventory, violations, zones, justified ruleset, and the before/after attack-path comparison
- [Project spec](https://github.com/MetaMaaz/Network-Segmentation-Advisor/blob/main/docs/PROJECT_SPEC.md) — design goals and scope

## How it works

Discovery (Nmap) is the only module that touches the network. Everything downstream — classifier, recommender, attack-path simulator, reporter — runs against a YAML inventory, so the entire advisory engine works offline against a mock network. That is also how it is tested: 30 tests, CI on Python 3.11 and 3.12.

- **Classifier** — assigns each host a role and sensitivity tier from port/service signatures with priorities and negative evidence (SMB + RDP present means workstation, not file server).
- **Recommender** — groups hosts into trust zones (DMZ, app-tier, data-tier, user-vlan, iot-vlan, management, and a quarantine zone for unknown assets) and derives the minimal allow set from services actually observed. Ports are never opened speculatively.
- **Attack-path simulator** — models reachability as a graph and runs breadth-first lateral movement from a chosen foothold, twice: against the flat network and against the proposed policy.
- **Exporters** — emit the ruleset as iptables and pfSense rules, each line annotated with its framework justification.

## Framework mapping

| Output | Principle |
|---|---|
| Default-deny inter-zone baseline | NIST SP 800-207 §3.1.2; PCI DSS v4.0 Req 1.2/1.3 |
| Per-rule justifications | NIST SP 800-207 §2.1 Tenet 3 (least-privilege, per-session access) |
| Quarantine zone for unknown assets | NIST SP 800-207 §2.1 Tenet 4 (no implicit trust from location) |
| Data-tier isolation from user VLAN | PCI DSS v4.0 scoping / segmentation guidance |
| Cleartext-protocol flags | PCI DSS v4.0 Req 2.2.5 (insecure services) |

---

MIT licensed. Built by [MetaMaaz](https://github.com/MetaMaaz).
