"""Classifier: every assignment must trace to a named, data-driven signature."""

import textwrap

from advisor.classifier import Classifier
from advisor.models import Inventory

from conftest import make_host


def _roles(classified: Inventory) -> dict[str, tuple[str, str]]:
    return {h.label: (h.role, h.sensitivity) for h in classified.hosts}


def test_domain_controller_is_critical(classified):
    assert _roles(classified)["dc-01"] == ("domain-controller", "critical")


def test_databases_are_critical(classified):
    roles = _roles(classified)
    assert roles["db-01"] == ("database", "critical")
    assert roles["db-02"] == ("database", "critical")


def test_web_servers_are_dmz_candidates(classified):
    assert _roles(classified)["web-01"] == ("web-server", "medium")


def test_printer_and_camera_are_untrusted(classified):
    roles = _roles(classified)
    assert roles["printer-01"] == ("printer", "untrusted")
    assert roles["cam-01"] == ("iot", "untrusted")


def test_jump_host_requires_ssh_only(classified):
    # jump-01 exposes only 22 -> jump-host; web-01 also has 22 but more.
    roles = _roles(classified)
    assert roles["jump-01"] == ("jump-host", "high")
    assert roles["web-01"][0] != "jump-host"


def test_workstations_despite_smb_open(classified):
    # 445 is open on workstations, but ports_none on the file-server
    # signature (negative evidence: 3389 present) prevents misclassification.
    assert _roles(classified)["ws-01"] == ("workstation", "standard")


def test_unmatched_host_falls_back_to_unknown(classified):
    assert _roles(classified)["legacy-01"][0] == "unknown"


def test_priority_resolves_overlaps(classified):
    # printer-01 exposes 80 (web signature) and 9100 (printer signature);
    # the higher-priority printer signature must win.
    assert _roles(classified)["printer-01"][0] == "printer"


def test_signatures_are_data_driven(tmp_path):
    custom = tmp_path / "sigs.yaml"
    custom.write_text(textwrap.dedent("""
        signatures:
          - name: scada
            role: scada-plc
            sensitivity: critical
            priority: 99
            match:
              ports_any: [102, 502]
        default: {role: unknown, sensitivity: standard}
    """))
    classifier = Classifier(custom)
    host = classifier.classify_host(make_host("10.0.0.9", [102]))
    assert (host.role, host.sensitivity) == ("scada-plc", "critical")
