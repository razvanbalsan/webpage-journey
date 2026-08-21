import io

from rich.console import Console

from wj import render, schema
from tests.test_build_osi import full_trace


def capture(fn, trace, width=110):
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, force_terminal=False, no_color=True)
    fn(console, trace)
    return buffer.getvalue()


def test_render_trace_mentions_every_layer():
    out = capture(render.render_trace, full_trace())
    for n in range(1, 8):
        assert f"L{n}" in out


def test_render_osi_stack_shows_measured_values_not_apologies():
    out = capture(render.render_osi_stack, full_trace())
    assert "11:22:33:44:55:66" in out
    assert "not visible to a userspace socket" not in out


def test_render_osi_stack_explains_an_unobserved_layer():
    trace = full_trace()
    trace["local"] = {"observed": False, "why_not": "neither route nor ip is on PATH"}
    trace["osi"] = schema.build_osi(trace)
    out = capture(render.render_osi_stack, trace)
    assert "neither route nor ip is on PATH" in out


def test_render_waterfall_rows_are_cumulative():
    trace = full_trace()
    trace["timings"] = {"waterfall": [
        {"label": "DNS", "start_ms": 0.0, "end_ms": 40.0},
        {"label": "TCP", "start_ms": 40.0, "end_ms": 52.0},
    ], "total_ms": 52.0}
    out = capture(render.render_waterfall, trace)
    assert "DNS" in out and "TCP" in out
    assert "52.0" in out


def test_render_findings_lists_notes_by_severity():
    trace = full_trace()
    trace["notes"] = [
        {"severity": "info", "section": "dns", "text": "no AAAA record"},
        {"severity": "critical", "section": "tls", "text": "certificate expired"},
    ]
    out = capture(render.render_findings, trace)
    assert out.index("certificate expired") < out.index("no AAAA record")


def test_render_findings_says_so_when_there_is_nothing_to_report():
    trace = full_trace()
    trace["notes"] = []
    out = capture(render.render_findings, trace)
    assert "Nothing" in out or "No findings" in out


def test_render_findings_says_nothing_worth_flagging_with_only_info_notes():
    # An info-severity note (e.g. "no HTTP/3 advertised") fires for most real
    # hosts -- gating the green "nothing worth flagging" message on ANY note
    # made it effectively unreachable. It must still say so when only
    # advisory (info) notes are present, and show them separately.
    trace = full_trace()
    trace["notes"] = [{"severity": "info", "section": "dns", "text": "no HTTP/3 advertised"}]
    out = capture(render.render_findings, trace)
    assert "Nothing worth flagging" in out
    assert "no HTTP/3 advertised" in out
    assert "Advisory" in out


def test_render_ladder_prints_this_hosts_commands():
    out = capture(render.render_ladder, full_trace())
    assert "ping 93.184.216.34" in out
    assert "nc -vz example.com 443" in out


def test_render_trace_survives_a_fully_unobserved_document():
    trace = schema.new_trace(
        target={"input": "x", "host": "x.test", "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.1.0", generated_at="t", capabilities={}, redacted=False)
    trace["timings"] = {"waterfall": [], "total_ms": 0.0}
    trace["osi"] = schema.build_osi(trace)
    out = capture(render.render_trace, trace)
    assert "not collected" in out


def test_render_dns_shows_records_failed_as_query_failures():
    # An empty list under a record type means "unknown" for that type when the
    # type is also in records_failed -- distinct from a confirmed absence.
    trace = full_trace()
    trace["dns"]["records_failed"] = ["CAA", "MX"]
    out = capture(render.render_dns, trace)
    assert "CAA" in out
    assert "MX" in out
    assert "failed" in out.lower()


def test_render_dns_distinguishes_present_absent_and_failed_record_types():
    # Task 24's central subtlety: a record type sits in one of three states
    # that must never collapse into each other -- has records, confirmed
    # absent (the query succeeded and the zone publishes none), or unknown
    # (the query itself failed). Collapsing "confirmed absent" into "skip
    # entirely" (the old behaviour) made it visually identical to a type
    # that was never queried; collapsing "failed" into "confirmed absent"
    # would misreport an unknown as a real measurement.
    trace = full_trace()
    trace["dns"]["records"]["CNAME"] = []   # confirmed absent
    trace["dns"]["records"]["MX"] = []      # query failed
    trace["dns"]["records_failed"] = ["MX"]
    out = capture(render.render_dns, trace)
    lines = [l.strip(" │├└─") for l in out.splitlines()]

    def line_for(rtype):
        return next(l for l in lines if l.startswith(rtype + "  "))

    has_line = line_for("A")
    absent_line = line_for("CNAME")
    failed_line = line_for("MX")

    assert "none published" not in has_line
    assert "none published" in absent_line
    assert "none published" not in failed_line
    assert "unknown" in failed_line.lower() and "failed" in failed_line.lower()
    assert absent_line != failed_line


def test_render_dns_https_extensions_follow_the_https_records_own_state():
    # alpn_advertised/ech come off the HTTPS record and must follow the same
    # three-state rule the HTTPS record itself is in -- not invent "no
    # ALPN"/"no ECH" when the record's own state is absent or unknown.
    trace = full_trace()

    # 1) HTTPS record present -> show what it actually advertises.
    trace["dns"]["records"]["HTTPS"] = [{"data": '1 . alpn="h2,h3" ech="AEX"', "ttl": 300}]
    trace["dns"]["alpn_advertised"] = ["h2", "h3"]
    trace["dns"]["ech"] = True
    out = capture(render.render_dns, trace)
    assert "h2, h3" in out
    assert "ECH" in out and "yes" in out
    assert "no HTTPS record" not in out

    # 2) HTTPS confirmed absent (query succeeded, zone publishes none) --
    # must say so plainly, not invent "no ALPN"/"ECH: no".
    trace["dns"]["records"]["HTTPS"] = []
    trace["dns"]["records_failed"] = []
    trace["dns"]["alpn_advertised"] = []
    trace["dns"]["ech"] = False
    out = capture(render.render_dns, trace)
    assert "no HTTPS record published" in out
    assert "None" not in out

    # 3) HTTPS query failed -> unknown; must not claim absence, and must
    # read differently from state 2.
    trace["dns"]["records_failed"] = ["HTTPS"]
    out = capture(render.render_dns, trace)
    assert "no HTTPS record published" not in out
    assert "ALPN advertised" not in out
    assert "unknown" in out.lower() and "failed" in out.lower()


def test_render_http_says_truncated_when_redirect_limit_reached():
    trace = full_trace()
    trace["http"]["hops"] = [
        {"status": 301, "url": "https://example.com/a", "location": "https://example.com/b"},
        {"status": 302, "url": "https://example.com/b", "location": "https://example.com/c"},
    ]
    trace["http"]["redirect_limit_reached"] = True
    out = capture(render.render_http, trace)
    assert "truncated" in out.lower()


def test_render_http_shows_every_request_and_response_header():
    trace = full_trace()
    trace["http"]["final"]["request"] = {
        "method": "GET", "target": "/dashboard", "http_version": "HTTP/1.1",
        "headers": [("Host", "example.com"),
                    ("User-Agent", "webpage-journey/2.0"),
                    ("Accept-Encoding", "gzip, deflate"),
                    ("Accept", "*/*"),
                    ("Connection", "close")]}
    trace["http"]["final"]["headers"] = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Server", "ECS"),
        ("Set-Cookie", "session=abc123; Path=/; Secure"),
        ("X-Empty", "")]
    out = capture(render.render_http, trace, width=120)

    # Every request header, name and value, is shown -- not summarised away.
    for name, value in trace["http"]["final"]["request"]["headers"]:
        assert name in out
        assert value in out
    # Every response header is shown, including one the summary never surfaces.
    assert "Server" in out and "ECS" in out
    assert "Set-Cookie" in out and "session=abc123" in out
    # A header sent with an empty value is shown, not silently dropped.
    assert "X-Empty" in out
    assert "None" not in out


def test_render_http_without_captured_headers_shows_only_the_summary():
    # A trace document that never captured headers (unobserved, or hand-built)
    # must not sprout an empty "Request headers"/"Response headers" heading.
    trace = full_trace()
    trace["http"]["final"].pop("headers", None)
    trace["http"]["final"].pop("request", None)
    out = capture(render.render_http, trace)
    assert "Request headers" not in out
    assert "Response headers" not in out
    assert "None" not in out


def test_render_http_header_value_with_brackets_is_shown_literally():
    # A header value containing square brackets must not be parsed as Rich
    # markup (which would drop or mangle it) -- values are rendered as Text.
    trace = full_trace()
    trace["http"]["final"]["headers"] = [("X-Trace", "[edge/7] cache=[hit]")]
    out = capture(render.render_http, trace, width=120)
    assert "[edge/7]" in out
    assert "cache=[hit]" in out


def test_render_never_prints_the_literal_none_for_absent_optional_values():
    # kernel.rtt_ms is legitimately None on some platforms; cache.state/age are
    # None when the response advertises no caching; cdn is None when undetected.
    trace = full_trace()
    trace["tcp"]["kernel"] = {"rtt_ms": None, "mss": 1460, "retransmits": None,
                              "source": "TCP_MAXSEG"}
    trace["http"]["cache"] = {"state": None, "age": None, "header": None,
                              "directives": None}
    trace["http"]["cdn"] = None
    out = capture(render.render_trace, trace)
    assert "None" not in out


def test_http_status_row_never_fabricates_a_status_code():
    trace = full_trace()
    trace["http"]["final"]["status"] = None
    trace["http"]["final"]["protocol"] = None
    out = capture(render.render_http, trace)
    assert "None" not in out
    assert " 0" not in out
    assert "no status line" in out


def test_render_dns_omits_timing_parenthetical_when_absent():
    trace = full_trace()
    trace["dns"]["timing_ms"] = {"cold": None, "warm": None}
    out = capture(render.render_dns, trace)
    assert "None" not in out
    assert "ms cold" not in out
    assert "ms warm" not in out


def test_render_dns_resolver_footer_builds_from_present_parts():
    trace = full_trace()
    trace["dns"]["resolver"] = {"servers": None, "source": None}
    trace["dns"]["dnssec"] = None
    out = capture(render.render_dns, trace)
    assert "None" not in out
    assert "resolved via unknown" in out


def test_render_tcp_client_server_line_guards_missing_addresses():
    trace = full_trace()
    trace["tcp"]["local"] = None
    trace["tcp"]["chosen"] = None
    trace["tcp"]["winner_family"] = None
    out = capture(render.render_tcp, trace)
    assert "None" not in out


def test_render_tls_handshake_row_guards_missing_duration():
    trace = full_trace()
    trace["tls"]["handshake_ms"] = None
    out = capture(render.render_tls, trace)
    assert "None" not in out


def test_render_tls_cert_row_shows_marker_when_no_fields_parsed():
    trace = full_trace()
    trace["tls"]["chain"] = [{"subject_cn": None, "issuer_cn": None,
                              "key": None, "days_left": None, "sans": None}]
    out = capture(render.render_tls, trace)
    assert "None" not in out
    assert "Cert 0" in out
    assert "no fields parsed" in out


def test_render_http_body_row_guards_a_partial_compression_combo_ratio_missing():
    # I1: the standing guard below sets encoding=None AND ratio=None together,
    # which never opens the `if final.get("encoding")` branch at all -- the
    # partial combination (encoding present, its companion ratio absent, e.g.
    # a failed inflate) is the shape that actually reaches the buggy code.
    trace = full_trace()
    trace["http"]["final"].update(encoding="gzip", ratio=None,
                                  wire_bytes=14000, decoded_bytes=None)
    out = capture(render.render_http, trace)
    assert "None" not in out
    assert "gzip" in out


def test_render_http_body_row_guards_a_partial_compression_combo_wire_bytes_missing():
    trace = full_trace()
    trace["http"]["final"].update(encoding="gzip", ratio=4.36,
                                  wire_bytes=None, decoded_bytes=61000)
    out = capture(render.render_http, trace)
    assert "None" not in out
    assert "61000" in out


def test_render_tls_cert_row_guards_a_key_with_a_type_but_no_bit_size():
    # Ed25519PublicKey has no key_size attribute in cryptography's model, so
    # key.type is present while key.bits is legitimately None -- the old bare
    # f"{type}{bits}" produced the literal text "Ed25519PublicKeyNone".
    trace = full_trace()
    trace["tls"]["chain"] = [{"subject_cn": "example.com", "issuer_cn": "R3",
                              "key": {"type": "Ed25519PublicKey", "bits": None},
                              "days_left": 80, "sans": []}]
    out = capture(render.render_tls, trace)
    assert "None" not in out
    assert "Ed25519PublicKey" in out


def test_render_dns_delegation_hop_shows_the_error_instead_of_a_bare_arrow():
    trace = full_trace()
    trace["dns"]["delegation"] = [
        {"level": "root", "server": "198.41.0.4", "error": "timed out"}]
    out = capture(render.render_dns, trace)
    assert "timed out" in out
    assert "None" not in out


def test_render_trace_never_prints_none_with_every_optional_subfield_absent():
    # The standing guard: every optional sub-field set to None at once, across
    # every section, with each section still observed. No literal "None" may
    # appear anywhere in the rendered output.
    trace = full_trace()
    # nat=False here (not None) matches the real collector's own invariant:
    # nat is computed as bool(local_ip and public_ip and ...), so a trace can
    # never carry nat=True alongside an absent local_ip/public_ip.
    trace["local"].update(link=None, mtu=None, local_ip=None, local_mac=None,
                          gateway_mac=None, public_ip=None, nat=False)
    trace["dns"].update(dnssec=None, delegation=None, alpn_advertised=None,
                        ech=None, timing_ms=None)
    trace["dns"]["resolver"] = {"servers": None, "source": None}
    trace["tcp"].update(winner_family=None, local=None, chosen=None,
                        kernel={"rtt_ms": None, "mss": None,
                                "retransmits": None, "source": None})
    trace["tls"].update(version=None, cipher=None, alpn=None, handshake_ms=None,
                        chain=[{"subject_cn": None, "issuer_cn": None, "key": None,
                                "days_left": None, "sans": None}],
                        trust_root=None, resumption=None)
    trace["http"]["final"].update(protocol=None, status=None, reason=None,
                                  ttfb_ms=None, total_ms=None, encoding=None,
                                  ratio=None, content_type=None)
    trace["http"].update(cache={"state": None, "age": None, "header": None,
                                "directives": None}, cdn=None)
    trace["path"].update(hops=[], asn_path=None, path_mtu=None)
    trace["osi"] = schema.build_osi(trace)
    out = capture(render.render_trace, trace)
    assert "None" not in out
