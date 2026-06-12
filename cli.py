#!/usr/bin/env python3
"""segmentation-advisor command-line interface.

Subcommands:
  discover  Scan a network with nmap and save an inventory YAML (network-facing).
  analyze   Run the offline pipeline and print a console summary.
  report    Run the offline pipeline and write the full report bundle.

``discover`` is the only network-facing command — ``analyze`` and ``report``
run entirely offline against an inventory file (real or mock).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from advisor import attack_path, recommender
from advisor.classifier import Classifier
from advisor.models import Inventory
from advisor.reporter import write_outputs

DEFAULT_INVENTORY = Path("data/mock_inventory.yaml")


def _run_pipeline(inventory_path: Path, compromised: str | None):
    inventory = Inventory.load(inventory_path)
    Classifier().classify(inventory)
    zones, rules, violations = recommender.recommend(inventory)
    before, after = attack_path.analyze(inventory, zones, rules, compromised)
    return inventory, zones, rules, violations, before, after


def cmd_discover(args: argparse.Namespace) -> int:
    from advisor import discovery  # imported lazily: needs python-nmap

    print(f"[*] Scanning {args.target} (nmap -sV) ...")
    inventory = discovery.scan(args.target, ports=args.ports)
    inventory.save(args.out)
    print(f"[+] {len(inventory.hosts)} hosts -> {args.out}")
    print("[i] Next: python cli.py report --inventory", args.out)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    inventory, zones, rules, violations, before, after = _run_pipeline(
        Path(args.inventory), args.compromised
    )
    print(f"Inventory: {len(inventory.hosts)} hosts ({inventory.source})\n")

    print("Zones:")
    for zone in zones:
        members = ", ".join(h.label for h in zone.hosts)
        print(f"  {zone.name:<12} {zone.subnet:<15} {members}")

    print(f"\nRuleset: {sum(1 for r in rules if r.action == 'allow')} allow rules "
          "+ default deny (run `report` for justifications)")

    print(f"\nViolations ({len(violations)}):")
    for v in violations:
        print(f"  [{v.severity.upper():<6}] {v.title}")

    print(f"\nAttack path (foothold: {before.compromised}):")
    print(f"  before: owns {before.owned_count} hosts, "
          f"{len(before.critical_owned)} critical ({', '.join(before.critical_owned) or '-'})")
    print(f"  after:  owns {after.owned_count} hosts, "
          f"{len(after.critical_owned)} critical ({', '.join(after.critical_owned) or '-'})")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    bundle = _run_pipeline(Path(args.inventory), args.compromised)
    paths = write_outputs(*bundle, out_dir=args.out)
    print(f"[+] Report bundle written to {args.out}/")
    for path in paths:
        print(f"    {path.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="segmentation-advisor",
        description="Zero-trust network segmentation advisor "
                    "(NIST SP 800-207 / PCI DSS aligned).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_discover = sub.add_parser("discover", help="nmap scan -> inventory YAML")
    p_discover.add_argument("--target", required=True,
                            help="nmap target spec, e.g. 192.168.1.0/24")
    p_discover.add_argument("--ports", default=None,
                            help="optional port spec, e.g. 1-1024")
    p_discover.add_argument("--out", default="inventory.yaml",
                            help="output inventory path")
    p_discover.set_defaults(func=cmd_discover)

    common = dict(default=str(DEFAULT_INVENTORY),
                  help="inventory YAML (default: mock inventory)")
    p_analyze = sub.add_parser("analyze", help="offline analysis, console summary")
    p_analyze.add_argument("--inventory", "--in", dest="inventory", **common)
    p_analyze.add_argument("--compromised", default=None,
                           help="foothold host for attack-path (label or IP)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_report = sub.add_parser("report", help="offline analysis, full report bundle")
    p_report.add_argument("--inventory", "--in", dest="inventory", **common)
    p_report.add_argument("--compromised", default=None,
                          help="foothold host for attack-path (label or IP)")
    p_report.add_argument("--out", default="output",
                          help="output directory (default: output/)")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
