"""Attack-path analysis: segmentation must demonstrably cut lateral movement."""

import pytest

from advisor import attack_path, recommender
from advisor.models import Inventory


@pytest.fixture()
def results(classified: Inventory):
    zones, rules, _ = recommender.recommend(classified)
    before, after = attack_path.analyze(classified, zones, rules,
                                        compromised="ws-01")
    return before, after


def test_flat_network_owns_critical_assets(results):
    before, _ = results
    assert "db-01" in before.owned
    assert "dc-01" in before.owned
    assert len(before.critical_owned) == 3  # db-01, db-02, dc-01


def test_segmentation_cuts_paths_to_critical_assets(results):
    _, after = results
    assert "db-01" not in after.owned
    assert "db-02" not in after.owned
    assert "dc-01" not in after.owned
    assert after.critical_owned == []


def test_database_not_even_exposed_after_segmentation(results):
    _, after = results
    assert "db-01" not in after.exposed
    assert "db-02" not in after.exposed


def test_dc_exposed_on_auth_ports_but_not_ownable(results):
    # Users still need Kerberos/LDAP/DNS, so the DC is reachable —
    # but only on non-pivot ports (445 excluded), so it can't be owned.
    _, after = results
    assert "dc-01" in after.exposed
    assert after.exposed["dc-01"] <= {53, 88, 389, 636}
    assert "dc-01" not in after.owned


def test_intra_zone_movement_remains(results):
    # Honest model: zone segmentation does not stop workstation->workstation.
    _, after = results
    assert "ws-02" in after.owned


def test_lateral_movement_shrinks(results):
    before, after = results
    assert after.owned_count < before.owned_count
    assert len(after.exposed) < len(before.exposed)


def test_camera_unreachable_after_segmentation(results):
    # user-vlan -> iot-vlan only opens print ports; cam-01 has none of them.
    _, after = results
    assert "cam-01" not in after.exposed


def test_attack_paths_are_chains_from_foothold(results):
    before, _ = results
    for target, path in before.owned.items():
        assert path[0] == "ws-01"
        assert path[-1] == target


def test_unknown_foothold_raises(classified):
    with pytest.raises(ValueError):
        attack_path.simulate(classified, compromised="ghost-99")
