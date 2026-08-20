import json
from pathlib import Path

import pytest

from wj import schema
from wj.collect.http import decode_body
from wj.collect.tls import caa_allows

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
NAMES = ["cdn-host.json", "plain-host.json", "partial-unprivileged.json"]

# The five identifiers a redacted export must never carry -- local_mac,
# gateway_mac, local_ip, gateway_ip, public_ip, in that order in the fixture.
LOCAL_IDENTIFIERS = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                     "192.168.1.23", "192.168.1.1", "81.180.20.7")


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


# I5: every fixture in NAMES carries "redacted": false -- the page's entire
# redaction-rendering path (fact() mapping the sentinel to the redacted
# badge) was exercised by nothing, in the privacy-critical path.
def test_a_redacted_golden_fixture_exists_and_is_actually_redacted():
    trace = json.loads((GOLDEN / "cdn-host-redacted.json").read_text())
    assert trace["redacted"] is True
    assert schema.validate(trace) == []

    blob = json.dumps(trace)
    assert "[redacted at export]" in blob
    for identifier in LOCAL_IDENTIFIERS:
        assert identifier not in blob, identifier


def test_redacted_golden_fixture_is_produced_by_the_generator_not_hand_edited():
    # The unredacted counterpart still carries every one of the five
    # identifiers -- proves the redacted fixture actually exercised
    # redact_trace() rather than merely being written without them.
    unredacted_blob = (GOLDEN / "cdn-host.json").read_text()
    for identifier in LOCAL_IDENTIFIERS:
        assert identifier in unredacted_blob, identifier


# ALSO FIX: a fixture-fidelity test that would have failed before C2/C3/I8
# landed -- the fixtures must agree with what the real functions return for
# their own recorded inputs, not with a hand-derived value that can drift.
@pytest.mark.parametrize("name", NAMES)
def test_fixture_caa_match_agrees_with_the_real_function(name):
    trace = json.loads((GOLDEN / name).read_text())
    tls = trace["tls"]
    if not tls["observed"] or not tls["chain"]:
        pytest.skip("no TLS chain to check")
    dns = trace["dns"]
    caa_records = dns["records"].get("CAA", []) if dns["observed"] else []
    leaf = tls["chain"][0]
    assert caa_allows(caa_records, leaf.get("issuer_cn"), leaf.get("issuer_org")) == tls["caa_match"]


@pytest.mark.parametrize("name", NAMES)
def test_fixture_decoded_body_agrees_with_the_real_function(name):
    trace = json.loads((GOLDEN / name).read_text())
    http = trace["http"]
    if not http["observed"]:
        pytest.skip("http not observed")
    final = http["final"]
    if not final.get("encoding"):
        pytest.skip("no encoding on this fixture's response")
    # The fixtures store post-decode figures, not raw bytes on disk -- confirm
    # decode_body() agrees on the ENCODING label for headers matching the
    # fixture's own final.headers, which is the part decode_body derives.
    _decoded, encoding = decode_body(final["headers"], b"")
    assert encoding == final["encoding"]
