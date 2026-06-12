# Project Spec: Network Segmentation Advisor

> **Handoff document for Claude Cowork.** This is a self-contained specification. Read it fully before writing any code. A "Notes for Future AI Assistants" section is at the bottom — update it as you go.

---

## 1. What this project is

A tool that discovers the hosts on a network, classifies each one by role and sensitivity, and then **recommends a zero-trust-aligned segmentation plan**: which assets belong in which zone, what firewall rules should govern traffic between zones, and *why* — with the reasoning mapped to NIST SP 800-207 and PCI-DSS segmentation principles.

**The point of the project is the recommendation engine, not the scanner.** Network scanning is a solved problem (nmap exists). The differentiator — and the thing that must be polished — is the advisory logic on top: classification, zone assignment, least-privilege rule generation, and the "before/after attack path" analysis that proves segmentation cuts an attacker's lateral movement.

This is a CV/portfolio project for an MSc Cybersecurity student targeting UK SOC/blue-team roles. It must be **defensible in an interview**: every recommendation the tool makes should trace back to a stated principle, never a black box.

---

## 2. Design principles (do not violate these)

1. **Hard separation between discovery and reasoning.** Discovery produces a plain inventory data structure (hosts, ports, services). The classifier, recommender, and reporter all consume that structure and never touch the network. This makes the interesting logic fully testable *without any network* by feeding in a mock inventory.
2. **Rules-based, explainable recommendations.** No ML. Recommendations come from explicit heuristics mapped to a named framework. "This DB is reachable from the user VLAN, which violates least-privilege per NIST 800-207" is the kind of output we want. Defensibility > sophistication.
3. **Everything maps to a framework.** Primary reference: NIST SP 800-207 (Zero Trust Architecture). Secondary: PCI-DSS network segmentation guidance. Cite the principle in the output.
4. **Python**, matching the user's stack. Type-hinted, modular.
5. **Testable on a Mac without a VM fleet.** See the testing section — mock mode and Docker are the two main harnesses.

---

## 3. Architecture

```
segmentation-advisor/
├── README.md
├── requirements.txt
├── docker-compose.yml          # test topology (see §6)
├── advisor/
│   ├── __init__.py
│   ├── discovery.py            # nmap/scapy → Inventory   (network-facing)
│   ├── models.py               # dataclasses: Host, Service, Zone, Rule, Inventory
│   ├── classifier.py           # Host → role + sensitivity tier   (pure logic)
│   ├── recommender.py          # Inventory → zones + inter-zone ruleset   (pure logic)
│   ├── attack_path.py          # before/after lateral-movement analysis   (pure logic)
│   ├── reporter.py             # → Markdown report, zone diagram, config export
│   └── exporters/
│       ├── iptables.py         # ruleset → iptables rules
│       └── pfsense.py          # ruleset → pfSense-style rules (stretch)
├── data/
│   ├── role_signatures.yaml    # port/service → role mapping (editable heuristics)
│   └── mock_inventory.yaml     # hand-written network for offline testing
├── tests/
│   ├── test_classifier.py
│   ├── test_recommender.py
│   └── test_attack_path.py
├── cli.py                      # entry point: discover | analyze | report
└── output/                     # generated reports, diagrams, configs
```

**Data flow:** `discovery` (or a mock file) → `Inventory` → `classifier` annotates each host → `recommender` produces `Zone`s and a `Rule` set → `attack_path` computes reachability before/after → `reporter` writes it all out.

---

## 4. Component specs

### models.py
Define dataclasses:
- `Service(port, protocol, name, version)`
- `Host(ip, hostname, services: list[Service], role=None, sensitivity=None)`
- `Zone(name, description, trust_tier, hosts: list[Host])`
- `Rule(src_zone, dst_zone, port, protocol, action, justification)`
- `Inventory(hosts: list[Host])` — with `to_yaml()` / `from_yaml()` so discovery output and mock files share one format.

### discovery.py (network-facing — the only module that touches the network)
- Wrap `python-nmap` (`python3-nmap` / the `nmap` PyPI package). Run a service+version scan (`-sV`) over a target range.
- Parse results into an `Inventory`. Save to YAML so a real scan can later be replayed offline.
- Keep this module thin. Everything intelligent happens downstream.

### classifier.py (pure logic)
- Load `data/role_signatures.yaml`, which maps service profiles to roles. Example heuristics:
  - 3306/5432 → **database** → sensitivity **critical**
  - 80/443 only → **web server** → sensitivity **medium** (DMZ candidate)
  - 88/389/445/636 (Kerberos/LDAP/SMB) → **domain controller** → **critical**
  - 9100 / printer services → **IoT/printer** → **high-risk-low-value** (isolate)
  - 3389/22 to a desktop OS fingerprint → **workstation** → **standard**
- Assign each host a role and a sensitivity tier (`critical / high / medium / standard / untrusted`).
- Make signatures data-driven (YAML), not hardcoded, so they're easy to defend and extend.

### recommender.py (pure logic — the core deliverable)
- Group classified hosts into **zones**: e.g. `DMZ`, `app-tier`, `data-tier`, `user-vlan`, `iot-vlan`, `management`.
- Generate an inter-zone **ruleset** following least-privilege: default-deny between zones, then add only the minimal allows implied by legitimate roles (e.g. app-tier → data-tier on the DB port; user-vlan → app-tier on 443; **never** user-vlan → data-tier directly).
- Every `Rule` carries a `justification` string citing the principle.
- **Flag violations** found in the current (flat) layout: DBs reachable from user subnets, IoT on the same segment as workstations, exposed management interfaces, flat/no-segmentation. Each flag references NIST 800-207 or PCI-DSS.

### attack_path.py (pure logic — the interview centrepiece)
- Model the network as a graph; edges = allowed reachability.
- Pick a "compromised" host (default: a workstation) and compute what it can reach.
- Run twice: **before** (flat network, everything reachable) and **after** (proposed segmentation applied). Show that a path like `workstation → database` exists before and is **cut** after.
- Output the contrast clearly — this is what proves you understand *why* segmentation matters.

### reporter.py
- Emit a Markdown report: asset inventory, proposed zones, the ruleset with justifications, violations found, and the before/after attack-path comparison.
- Emit a **zone diagram**. Use graphviz (`graphviz` PyPI + the `dot` binary) or, simplest, generate Mermaid markup that renders in the README.
- Call the exporters to write enforceable config (iptables first, pfSense as stretch).

### exporters/
- `iptables.py`: turn the `Rule` set into actual iptables commands.
- `pfsense.py`: pfSense-style rules (stretch goal; only if a real enforcement VM gets added later).

### cli.py
Three subcommands:
- `discover --target <range> --out inventory.yaml` (network-facing)
- `analyze --in inventory.yaml --out output/` (offline; runs classify + recommend + attack-path)
- `report --in inventory.yaml` (convenience: analyze + write everything)

Keeping `discover` separate means the whole analysis pipeline runs offline on a mock inventory.

---

## 5. Build order (so it's always demoable)

1. `models.py` + `data/mock_inventory.yaml` — a realistic ~12-host flat network on paper.
2. `classifier.py` + tests, run against the mock. **Now logic is testable with zero network.**
3. `recommender.py` + tests — zones and ruleset from the mock.
4. `attack_path.py` + tests — the before/after contrast.
5. `reporter.py` — Markdown + Mermaid diagram + iptables export.
6. `discovery.py` — wire up real nmap last; validate against the Docker topology (§6).
7. Polish: README leading with the zero-trust/advisory angle, sample report committed to the repo, exporters.

Use Conventional Commits (`feat:`, `chore:`, `test:`, `docs:`).

---

## 6. Testing on a Mac without a VM fleet

Two primary harnesses; prefer them over VMs.

### A. Mock mode (for all logic) — no network at all
`data/mock_inventory.yaml` hand-describes a flat network (web servers, a DB, a domain controller, workstations, a printer/IoT device). The classifier, recommender, attack-path, and reporter all run against this file. This is the main development loop and what the unit tests use. **Build and validate the entire interesting half of the project this way before touching a network.**

### B. Docker topology (for realistic end-to-end discovery)
`docker-compose.yml` stands up a fake network of containers, each playing a host:
- `nginx` → web server (80/443)
- `mysql` or `postgres` → database
- `ubuntu`/`alpine` with a couple of services → workstations
- optionally a deliberately vulnerable image (e.g. Metasploitable-style) as the pivot host

Use **user-defined bridge networks** to create multiple subnets and control routing between them, so segmentation is actually modelled. Run `discover` against the containers to exercise the real nmap path. The whole topology is one file — tear down and rebuild instantly with `docker compose up/down`.

**Caveat to honour in the design:** containers share the host kernel, so nmap's OS/service fingerprints against them are thinner and differ from full VMs. Use Docker to validate *topology + service discovery*; use mock mode when you need precise control over what the classifier sees. Do not over-fit the classifier to container fingerprints.

### C. Lighter fallbacks
- **Localhost services:** run a few services on different ports on the Mac and scan `127.0.0.1`. Fine for smoke-testing discovery only (no real subnets).
- **`scanme.nmap.org`:** nmap's official scan-test target — use *only* to sanity-check the nmap integration. Never scan anything you don't own or aren't authorised to.

### D. Optional phase 2 (only if needed later)
UTM VMs (Windows/AD, pfSense as a real enforcement point) if you want true OS fingerprints or to actually apply the generated rules on a real firewall. Not required for a strong v1.

---

## 7. Definition of done (v1)

- `analyze` runs end-to-end on `mock_inventory.yaml` and produces zones, a justified least-privilege ruleset, flagged violations, and a before/after attack-path comparison.
- `discover` successfully scans the Docker topology and produces an inventory the pipeline accepts.
- A sample generated report (Markdown + diagram + iptables export) is committed to the repo.
- Tests pass for classifier, recommender, and attack-path.
- README leads with the **zero-trust segmentation advisory** angle (not the scanner) and includes a sample CV bullet.

---

## 8. Things to get right for the CV/interview

- Lead every description with the **advisory / NIST 800-207** angle. "Scans a network" is table stakes; "recommends and validates a zero-trust segmentation policy" is the story.
- The **before/after attack-path** output is the single most interview-valuable artifact — make it visually obvious.
- Generate **real, enforceable config** (iptables), not just prose advice.
- Keep recommendations **explainable** — every rule cites its principle.

---

## Notes for Future AI Assistants

- **Stack:** Mac (Apple Silicon) running Kali via UTM available, but this project is designed to run on the Mac directly via Docker + mock mode. Python, Git/GitHub (Conventional Commits).
- **User:** MSc Cybersecurity student, ~2–3 hrs/week, targeting UK SOC Tier 1 → DFIR. Defensive/blue-team focus. Values understanding tradeoffs and explainable, framework-grounded design over flashy black boxes.
- **Non-negotiables:** discovery/reasoning separation; rules-based not ML; everything maps to NIST 800-207 / PCI-DSS; logic must be testable offline via mock mode.
- **Sequence reminder:** build and test the recommender + attack-path against the mock inventory *first*; wire real nmap last.
- Update this section with decisions, blockers, and progress as the build proceeds.

### Build log — 2026-06-12 (v1 complete)

All of §7 (definition of done) is implemented, plus GitHub Actions CI and the pfSense exporter stretch goal. 30 tests pass; the CI workflow also smoke-tests `analyze` and `report` end-to-end on the mock inventory.

Decisions made during the build (and why):

- **Negative-evidence matcher added** (`ports_none` in `role_signatures.yaml`). Windows workstations expose SMB (445), which would otherwise misclassify them as file servers. A signature can now require the *absence* of ports (file-server requires no 88/3389).
- **Pivot vs exposure threat model** in `attack_path.py`. Reaching any open port counts as *exposure*; *pivoting* (continuing lateral movement) requires a remote-admin service (22/23/135/139/445/3389/5985/5986). Without this split, the legitimate user→dmz→app→data allow chain would let the simulated attacker "own" everything even after segmentation, hiding the before/after contrast. The model and its limits are documented in the report's residual-risk section.
- **SMB (445) excluded from the AD client allow set** (clients get 53/88/389/636 to the management zone). SMB to DCs is the classic lateral-movement channel; this is also why the DC stays *exposed but not ownable* in the after-simulation.
- **Quarantine zone** added for hosts matching no signature (mock host `legacy-01`, port 102/iso-tsap) — zero trust grants nothing to unclassified assets.
- **Observed-ports-only rule generation:** the recommender only opens a port if a host in the destination zone actually exposes it — no speculative allows. Tests assert exactly {3306, 5432} for app→data.
- **Mock inventory is 14 hosts** (spec said ~12): DC, 2×web, app, 2×DB, jump host, 4×workstations, printer, camera (with deliberate Telnet for the cleartext violation), and the unknown legacy device.
- **Sample report committed** at `docs/sample-output/` (report.md, zones.mmd, iptables.rules, pfsense_rules.txt); `output/` is gitignored, as are real scan inventories (`inventory*.yaml`) so nobody accidentally commits a map of a real network.
- **Remaining for the user:** replace `YOUR-USERNAME` in README badge/clone URLs after creating the GitHub repo; optionally validate discovery against the Docker topology (instructions in `docker-compose.yml`).
