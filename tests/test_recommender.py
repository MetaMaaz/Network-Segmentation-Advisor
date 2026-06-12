"""Recommender: zones, least-privilege ruleset and violation flags."""

import pytest

from advisor import recommender
from advisor.models import Inventory


@pytest.fixture()
def result(classified: Inventory):
    return recommender.recommend(classified)


def _zone(zones, name):
    return next(z for z in zones if z.name == name)


def test_hosts_grouped_into_expected_zones(result):
    zones, _, _ = result
    assert {h.label for h in _zone(zones, "dmz").hosts} == {"web-01", "web-02"}
    assert {h.label for h in _zone(zones, "data-tier").hosts} == {"db-01", "db-02"}
    assert {h.label for h in _zone(zones, "management").hosts} == {"dc-01", "jump-01"}
    assert {h.label for h in _zone(zones, "iot-vlan").hosts} == {"printer-01", "cam-01"}
    assert len(_zone(zones, "user-vlan").hosts) == 4


def test_unknown_hosts_are_quarantined(result):
    zones, _, _ = result
    assert {h.label for h in _zone(zones, "quarantine").hosts} == {"legacy-01"}


def test_default_deny_is_the_final_rule(result):
    _, rules, _ = result
    last = rules[-1]
    assert (last.action, last.src_zone, last.dst_zone) == ("deny", "*", "*")


def test_user_vlan_never_reaches_data_tier(result):
    _, rules, _ = result
    assert not any(
        r.action == "allow"
        and r.src_zone == "user-vlan" and r.dst_zone == "data-tier"
        for r in rules
    )


def test_app_tier_reaches_databases_on_observed_ports_only(result):
    _, rules, _ = result
    db_allows = {
        r.port for r in rules
        if r.action == "allow"
        and r.src_zone == "app-tier" and r.dst_zone == "data-tier"
    }
    # exactly the DB ports present in the mock — nothing speculative
    assert db_allows == {3306, 5432}


def test_no_smb_allowed_to_domain_controllers_from_user_vlan(result):
    _, rules, _ = result
    assert not any(
        r.action == "allow" and r.dst_zone == "management" and r.port == 445
        for r in rules
    )


def test_admin_access_only_from_management(result):
    _, rules, _ = result
    for rule in rules:
        if rule.action == "allow" and rule.port in (22, 3389):
            assert rule.src_zone == "management"


def test_every_rule_cites_a_framework(result):
    _, rules, _ = result
    for rule in rules:
        assert rule.justification.strip()
        assert "NIST" in rule.justification or "PCI" in rule.justification


def test_expected_violations_flagged(result):
    _, _, violations = result
    titles = " | ".join(v.title for v in violations)
    assert "Flat network" in titles
    assert "reachable from user workstations" in titles
    assert "IoT" in titles
    assert "Cleartext" in titles          # cam-01 telnet
    assert "Unclassified" in titles       # legacy-01


def test_violations_reference_frameworks_and_hosts(result):
    _, _, violations = result
    for v in violations:
        assert v.affected_hosts
        assert "NIST" in v.framework_ref or "PCI" in v.framework_ref
