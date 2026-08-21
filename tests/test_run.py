import pytest

from wj import capabilities, run, schema
from wj.context import Context


def make_ctx(deadline=1e9):
    caps = capabilities.Capabilities(libs={"dns": True}, tools={},
                                     privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=5.0, deadline=deadline, caps=caps, results={})


def fake_collectors(**overrides):
    base = {
        "local": lambda ctx: schema.observed(interface="en0"),
        "dns": lambda ctx: schema.observed(
            records={"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": []},
            timing_ms={"cold": 40.0, "warm": 1.0}, dnssec="secure",
            resolver={"servers": [], "source": "none"}, alpn_advertised=[]),
        "negotiation": lambda ctx: schema.observed(
            advertised=[], offered=["http/1.1"], signal="no HTTPS record",
            unavailable=[], chosen=None, attempted=[]),
        "tcp": lambda ctx: schema.observed(
            chosen={"ip": "93.184.216.34", "family": "ipv4", "port": 443},
            candidates=[{"ip": "93.184.216.34", "family": "ipv4",
                         "connect_ms": 12.0, "error": None}],
            local={"ip": "192.168.1.5", "port": 51000}, kernel={}, winner_family="ipv4"),
        "tls": lambda ctx: schema.observed(
            version="TLSv1.3", cipher="X", alpn="h2", handshake_ms=30.0,
            chain=[], trust_root=None, verified=True, caa_match=None,
            resumption={"tested": False}, legacy_versions_accepted=[]),
        "http": lambda ctx: schema.observed(
            hops=[], final={"url": "https://example.com/", "status": 200,
                            "protocol": "HTTP/1.1", "ttfb_ms": 80.0, "total_ms": 95.0,
                            "wire_bytes": 100, "decoded_bytes": 100, "encoding": None,
                            "ratio": None, "content_type": "text/html"},
            cache={}, cdn=None,
            security={"grade": "A", "present": {}, "missing": [], "cookies": []},
            conditional={"tested": False}),
        "path": lambda ctx: schema.observed(source="traceroute", hops=[],
                                            asn_path=[], path_mtu=None),
    }
    base.update(overrides)
    return base


def test_orchestrate_fills_every_section():
    trace = run.orchestrate(make_ctx(), collectors=fake_collectors())
    for name in schema.SECTIONS:
        assert trace[name]["observed"] is True
    assert schema.validate(trace) == []


def test_orchestrate_records_a_collector_failure_without_aborting():
    def explode(ctx):
        raise RuntimeError("boom")

    trace = run.orchestrate(make_ctx(), collectors=fake_collectors(tls=explode))
    assert trace["tls"]["observed"] is False
    assert "boom" in trace["tls"]["why_not"]
    assert trace["http"]["observed"] is True


def test_orchestrate_skips_dependents_when_dns_fails():
    def no_dns(ctx):
        return schema.unobserved("did not resolve")

    trace = run.orchestrate(make_ctx(), collectors=fake_collectors(dns=no_dns))
    assert trace["dns"]["observed"] is False
    assert trace["tcp"]["observed"] is False
    assert "dns" in trace["tcp"]["why_not"]


def test_orchestrate_marks_unstarted_collectors_when_the_budget_is_gone():
    ctx = make_ctx(deadline=0.0)
    trace = run.orchestrate(ctx, collectors=fake_collectors(), now=lambda: 100.0)
    assert trace["http"]["observed"] is False
    assert "budget exhausted" in trace["http"]["why_not"]


def test_build_timings_produces_a_cumulative_waterfall():
    trace = run.orchestrate(make_ctx(), collectors=fake_collectors())
    timings = trace["timings"]
    labels = [row["label"] for row in timings["waterfall"]]
    assert labels == ["DNS", "TCP", "TLS", "TTFB", "Download"]
    starts = [row["start_ms"] for row in timings["waterfall"]]
    assert starts == sorted(starts)
    assert timings["waterfall"][1]["start_ms"] == pytest.approx(40.0)
    assert timings["total_ms"] > 0


def test_strip_private_removes_socket_handles():
    trace = {"tcp": {"observed": True, "_socket": object(), "chosen": {}},
             "tls": {"observed": True, "_socket": object()}}
    out = run.strip_private(trace)
    assert "_socket" not in out["tcp"]
    assert "_socket" not in out["tls"]
    assert out["tcp"]["chosen"] == {}


def test_orchestrate_attaches_findings_and_osi():
    trace = run.orchestrate(make_ctx(), collectors=fake_collectors())
    assert set(trace["osi"]) == {"l1", "l2", "l3", "l4", "l5", "l6", "l7"}
    assert isinstance(trace["notes"], list)
