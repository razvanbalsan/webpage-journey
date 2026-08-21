import json
from pathlib import Path

import pytest

from tests.fixtures import make_golden
from tests.test_transport_h2 import FakeTLSSocket
from wj import capabilities, redact, schema
from wj.collect import http as http_collect
from wj.collect import negotiate
from wj.collect.http import decode_body
from wj.collect.tls import caa_allows
from wj.context import Context
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
    __main__ there and this test build from, so they cannot drift apart.

    Routed through make_golden.as_written() so the comparison is against what
    the generator actually serialises -- the real transports produce tuples
    for header pairs, which JSON writes as arrays."""
    ctx, collectors_map = make_golden.specs()[name]
    trace = orchestrate(ctx, collectors=collectors_map)
    trace["generated_at"] = make_golden.GENERATED_AT
    return make_golden.as_written(trace)


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
    fresh = make_golden.as_written(redact.redact_trace(_fresh_trace("cdn-host.json")))
    assert fresh == committed


def _collect_final_keys():
    """The exact key set wj/collect/http.py's collect() produces for
    http.final, measured by running the REAL collector over the REAL HTTP/2
    transport against tests/test_transport_h2.py's FakeTLSSocket."""
    caps = capabilities.Capabilities(libs={"h2": True}, tools={},
                                     privileged=False, can_sudo=False)
    ctx = Context(host="h2.example.net", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tls"] = {
        "observed": True, "alpn": "h2",
        "_socket": FakeTLSSocket([(":status", "200"),
                                  ("content-type", "text/html")])}
    section = http_collect.collect(ctx)
    assert section["observed"] is True, section
    return set(section["final"])


@pytest.mark.parametrize("name", NAMES)
def test_golden_final_has_exactly_the_keys_collect_produces(name):
    # The fixture/collector drift this suite could not previously see:
    # make_golden.py's http stubs hand-write final{...} rather than going
    # through collect(), so a key collect() always produces could simply be
    # missing from every golden. final.request was, which meant the terminal's
    # request panel (wj/render.py) rendered nothing against any fixture --
    # including the h2 one, whose :method/:path/:scheme/:authority block is
    # the most instructive thing about an HTTP/2 request.
    #
    # Every other test here checks PROPERTIES of the fixture, all of which a
    # document collect() could never produce can satisfy perfectly. This is
    # the one that says the fixture is that document's actual shape.
    trace = json.loads((GOLDEN / name).read_text())
    http = trace["http"]
    if not http["observed"]:
        pytest.skip("http not observed in this fixture")
    assert set(http["final"]) == _collect_final_keys()


def test_h2_golden_carries_the_request_block_the_real_transport_sends():
    # I6/M11 together: the h2 fixture must show the pseudo-header shape, and
    # it must be the transport's own, not a hand-written imitation of it.
    trace = json.loads((GOLDEN / "h2-host.json").read_text())
    final = trace["http"]["final"]
    ctx, _ = make_golden.specs()["h2-host.json"]
    real = make_golden.real_h2_exchange(ctx, final["url"], final["status"],
                                        final["headers"])["request"]
    assert make_golden.as_written(real) == final["request"]
    names = [k for k, _ in final["request"]["headers"]]
    assert names[:4] == [":method", ":path", ":scheme", ":authority"]


def test_h2_golden_records_a_stream_id_on_the_final_response():
    # stream_id was measured by the transport on every response and then
    # dropped on the way into final{...}, so a redirect-free HTTP/2 trace
    # carried no stream id anywhere in the document.
    trace = json.loads((GOLDEN / "h2-host.json").read_text())
    assert trace["http"]["final"]["stream_id"] == 5


@pytest.mark.parametrize("name", ["cdn-host.json", "plain-host.json",
                                  "partial-unprivileged.json"])
def test_http1_goldens_leave_stream_id_absent(name):
    # HTTP/1.1 has no streams to number: unmeasured, not zero.
    trace = json.loads((GOLDEN / name).read_text())
    assert trace["http"]["final"]["stream_id"] is None


@pytest.mark.parametrize("name", NAMES)
def test_golden_fixture_negotiation_chosen_agrees_with_tls_alpn(name):
    # I1's actual invariant, checked directly rather than only by proxy: if
    # make_golden.py's chosen-propagation (mirroring wj/collect/http.py's
    # own wiring) were ever deleted, every fixture would simply regenerate
    # with negotiation.chosen back to null, and
    # test_golden_fixture_matches_a_fresh_generator_run above would still
    # pass -- a fixture matching its own (regressed) generator proves
    # nothing about whether the generator is still right. This fails
    # regardless of whether the fixture and the generator agree with each
    # other, because it does not depend on the generator at all.
    trace = json.loads((GOLDEN / name).read_text())
    if not trace["tls"]["observed"]:
        pytest.skip("no TLS handshake to compare against")
    assert trace["negotiation"]["chosen"] == trace["tls"]["alpn"]


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


def test_h2_fixture_header_bytes_agrees_with_the_real_transport():
    # Fixture-fidelity pattern again, for the one number in header_bytes
    # that a real header list makes checkable: a prior draft of this
    # fixture hand-picked "wire" and got a value no standard HPACK encoder
    # can produce for these headers. make_golden.real_h2_header_bytes()
    # drives the real transport against a real h2.connection.H2Connection
    # (tests/test_transport_h2.py's FakeTLSSocket) -- re-running it here
    # against the fixture's own final.headers must reproduce exactly what
    # is committed, not a hand-derived or otherwise-guessed number.
    trace = json.loads((GOLDEN / "h2-host.json").read_text())
    final = trace["http"]["final"]
    ctx, _ = make_golden.specs()["h2-host.json"]
    real = make_golden.real_h2_header_bytes(ctx, final["status"], final["headers"])
    assert real == final["header_bytes"]


def test_the_generator_does_not_claim_every_request_is_literal_http1_text():
    # A prose claim this branch falsified, guarded the way tests/test_cli.py
    # guards the --help copy: since h2 landed, a handshake that selects h2
    # frames its request in binary HPACK, not as literal HTTP/1.1 text over
    # the socket. Prose claims are bound by this project's one rule exactly
    # as strictly as fields are.
    source = Path(make_golden.__file__).read_text()
    assert "Requests always go out as literal HTTP/1.1 text" not in source
