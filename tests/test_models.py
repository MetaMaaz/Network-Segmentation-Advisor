"""Inventory YAML round-trip: discovery output and mock files share a format."""

from advisor.models import Inventory


def test_yaml_round_trip(classified: Inventory):
    text = classified.to_yaml()
    restored = Inventory.from_yaml(text)
    assert len(restored.hosts) == len(classified.hosts)
    original = classified.get("db-01")
    copy = restored.get("db-01")
    assert copy is not None
    assert copy.ip == original.ip
    assert copy.open_ports == original.open_ports
    # classification annotations survive the round trip
    assert copy.role == "database"
    assert copy.sensitivity == "critical"


def test_lookup_by_ip_and_hostname(raw_inventory: Inventory):
    assert raw_inventory.get("192.168.1.30").hostname == "db-01"
    assert raw_inventory.get("db-01").ip == "192.168.1.30"
    assert raw_inventory.get("nope") is None
