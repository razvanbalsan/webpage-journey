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


def test_render_ladder_prints_this_hosts_commands():
    out = capture(render.render_ladder, full_trace())
    assert "ping 93.184.216.34" in out
    assert "nc -vz example.com 443" in out


def test_render_trace_survives_a_fully_unobserved_document():
    trace = schema.new_trace(
        target={"input": "x", "host": "x.test", "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.0.0", generated_at="t", capabilities={}, redacted=False)
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


def test_render_http_says_truncated_when_redirect_limit_reached():
    trace = full_trace()
    trace["http"]["hops"] = [
        {"status": 301, "url": "https://example.com/a", "location": "https://example.com/b"},
        {"status": 302, "url": "https://example.com/b", "location": "https://example.com/c"},
    ]
    trace["http"]["redirect_limit_reached"] = True
    out = capture(render.render_http, trace)
    assert "truncated" in out.lower()


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
