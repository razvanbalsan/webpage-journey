from wj import capabilities, schema
from wj.collect import negotiate
from wj.context import Context


def caps_with(h2=True):
    return capabilities.Capabilities(libs={"h2": h2}, tools={},
                                     privileged=False, can_sudo=False)


def make_ctx(advertised, h2=True, scheme="https"):
    ctx = Context(host="example.com", scheme=scheme, port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps_with(h2), results={})
    ctx.results["dns"] = {"observed": True, "alpn_advertised": advertised}
    return ctx


def test_offers_h2_when_the_host_advertises_it():
    out = negotiate.choose(["h3", "h2"], caps_with(), "https")
    assert out["offered"] == ["h2", "http/1.1"]
    assert out["signal"] == "HTTPS record"


def test_offers_only_http1_when_the_host_advertises_nothing():
    out = negotiate.choose([], caps_with(), "https")
    assert out["offered"] == ["http/1.1"]
    assert out["signal"] == "no HTTPS record"


def test_offers_only_http1_when_this_build_cannot_speak_h2():
    out = negotiate.choose(["h2"], caps_with(h2=False), "https")
    assert out["offered"] == ["http/1.1"]
    assert "h2" in out["unavailable"]


def test_signal_distinguishes_a_failed_https_query_from_no_record_at_all():
    # dns.py's own contract: records_failed means the query never completed --
    # an empty alpn_advertised list here means "could not tell", not "this
    # host publishes no HTTPS record". Collapsing the two would assert an
    # absence the code never actually observed.
    out = negotiate.choose([], caps_with(), "https", https_failed=True)
    assert out["offered"] == ["http/1.1"]
    assert out["signal"] != "no HTTPS record"
    assert "could not tell" in out["signal"]


def test_signal_distinguishes_a_record_with_no_alpn_parameter_from_no_record():
    # The HTTPS record exists (the query succeeded and returned an answer) but
    # carries no alpn= parameter -- genuinely different from no record at all.
    out = negotiate.choose([], caps_with(), "https", https_present=True)
    assert out["offered"] == ["http/1.1"]
    assert out["signal"] != "no HTTPS record"
    assert out["signal"] != "could not tell — the HTTPS record query did not complete"


def test_plain_http_has_no_alpn_at_all():
    # ALPN is a TLS extension. Over plain HTTP there is no handshake to carry it.
    out = negotiate.choose(["h2"], caps_with(), "http")
    assert out["offered"] == []
    assert out["signal"] == "no TLS — ALPN does not apply"


def test_chosen_is_absent_until_the_handshake_reports_it():
    section = negotiate.collect(make_ctx(["h2"]))
    assert section["observed"] is True
    assert section["chosen"] is None
    assert section["offered"] == ["h2", "http/1.1"]


def test_collect_reports_could_not_tell_when_the_https_query_failed():
    ctx = make_ctx([])
    ctx.results["dns"] = {"observed": True, "alpn_advertised": [],
                          "records_failed": ["HTTPS"], "records": {"HTTPS": []}}
    section = negotiate.collect(ctx)
    assert section["observed"] is True
    assert "could not tell" in section["signal"]


def test_unobserved_when_dns_did_not_resolve():
    ctx = make_ctx([])
    ctx.results["dns"] = {"observed": False, "why_not": "did not resolve"}
    section = negotiate.collect(ctx)
    assert section["observed"] is False
    assert "dns" in section["why_not"]


def test_negotiation_is_a_schema_section():
    assert "negotiation" in schema.SECTIONS
