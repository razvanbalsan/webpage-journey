import json
from pathlib import Path

import pytest

from wj import schema

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
NAMES = ["cdn-host.json", "plain-host.json", "partial-unprivileged.json"]


@pytest.mark.parametrize("name", NAMES)
def test_golden_trace_validates(name):
    trace = json.loads((GOLDEN / name).read_text())
    assert schema.validate(trace) == []


@pytest.mark.parametrize("name", NAMES)
def test_golden_trace_has_all_seven_osi_layers(name):
    trace = json.loads((GOLDEN / name).read_text())
    assert set(trace["osi"]) == {"l1", "l2", "l3", "l4", "l5", "l6", "l7"}


def test_cdn_golden_observes_every_section():
    trace = json.loads((GOLDEN / "cdn-host.json").read_text())
    for name in schema.SECTIONS:
        assert trace[name]["observed"] is True, name
    assert trace["osi"]["l2"]["observed"] is True


def test_partial_golden_explains_what_it_could_not_see():
    trace = json.loads((GOLDEN / "partial-unprivileged.json").read_text())
    assert trace["local"]["observed"] is False
    assert trace["path"]["observed"] is False
    assert trace["osi"]["l1"]["why_not"]
    assert trace["osi"]["l3"]["observed"] is True


def test_golden_traces_carry_findings():
    trace = json.loads((GOLDEN / "cdn-host.json").read_text())
    texts = " ".join(n["text"] for n in trace["notes"])
    assert "expires in 10 days" in texts
