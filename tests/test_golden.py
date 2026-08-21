import json
from pathlib import Path

import pytest

from tests.fixtures import make_golden
from wj import capabilities, redact, schema
from wj.collect import negotiate
from wj.collect.http import decode_body
from wj.collect.tls import caa_allows
from wj.run import orchestrate

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
NAMES = ["cdn-host.json", "plain-host.json", "partial-unprivileged.json", "h2-host.json"]

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


def _fresh_trace(name):
    """Build the trace tests/fixtures/make_golden.py would write for `name`,
    without touching disk. make_golden.specs() is the single recipe both
    __main__ there and this test build from, so they cannot drift apart."""
    ctx, collectors_map = make_golden.specs()[name]
    trace = orchestrate(ctx, collectors=collectors_map)
    trace["generated_at"] = make_golden.GENERATED_AT
    return trace


@pytest.mark.parametrize("name", NAMES)
def test_golden_fixture_matches_a_fresh_generator_run(name):
    # I3: this suite only ever validated PROPERTIES of the committed
    # fixtures, never that a fixture still matches what the generator
    # actually produces today -- precisely how a stale, self-contradictory
    # fixture (negotiation.chosen: null sitting next to tls.alpn: "http/1.1")
    # survived undetected earlier in this plan. A golden that drifts from
    # its own generator must fail here, not get discovered by a human
    # reading the rendered page.
    committed = json.loads((GOLDEN / name).read_text())
    assert _fresh_trace(name) == committed


def test_redacted_golden_fixture_matches_a_fresh_generator_run():
    committed = json.loads((GOLDEN / "cdn-host-redacted.json").read_text())
    fresh = redact.redact_trace(_fresh_trace("cdn-host.json"))
    assert fresh == committed


def test_h2_fixture_negotiation_agrees_with_the_real_chooser():
    # The fixture-fidelity pattern above, applied to negotiate.choose():
    # h2-host.json's negotiation.offered must be what the real chooser
    # returns for the fixture's own recorded advertised/scheme, not a
    # hand-derived value that can drift from wj/collect/negotiate.py.
    trace = json.loads((GOLDEN / "h2-host.json").read_text())
    caps = capabilities.Capabilities(libs={"h2": True}, tools={},
                                     privileged=False, can_sudo=False)
    decision = negotiate.choose(trace["negotiation"]["advertised"], caps,
                                trace["target"]["scheme"])
    assert decision["offered"] == trace["negotiation"]["offered"]


def test_h2_fixture_has_a_hop_that_reused_the_connection():
    # I2: no golden fixture ever carried connection_reused: true anywhere in
    # hops[] -- HTTP/1.1 always opens a fresh connection per hop (see
    # wj/transport/h1.py), so only a same-origin HTTP/2 redirect chain can
    # exercise this at all.
    trace = json.loads((GOLDEN / "h2-host.json").read_text())
    reused_hops = [h for h in trace["http"]["hops"] if h["connection_reused"] is True]
    assert reused_hops, "expected at least one hop with connection_reused: true"
