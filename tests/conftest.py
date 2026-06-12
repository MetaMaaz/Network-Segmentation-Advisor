"""Shared fixtures: the classified mock inventory used across test suites."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from advisor.classifier import Classifier          # noqa: E402
from advisor.models import Host, Inventory, Service  # noqa: E402

MOCK_INVENTORY = ROOT / "data" / "mock_inventory.yaml"


def make_host(ip: str, ports: list[int], hostname: str = "", os: str = "",
              names: dict[int, str] | None = None) -> Host:
    names = names or {}
    return Host(
        ip=ip,
        hostname=hostname,
        os=os,
        services=[Service(port=p, name=names.get(p, "")) for p in ports],
    )


@pytest.fixture()
def raw_inventory() -> Inventory:
    return Inventory.load(MOCK_INVENTORY)


@pytest.fixture()
def classified(raw_inventory: Inventory) -> Inventory:
    return Classifier().classify(raw_inventory)
