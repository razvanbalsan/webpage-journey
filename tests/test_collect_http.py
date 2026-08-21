import gzip

import pytest

from tests.test_transport_h1 import FakeSocket as FakeH1Socket
from tests.test_transport_h2 import FakeTLSSocket
from wj import capabilities
from wj.collect import http as http_collect
from wj.context import Context
from wj.transport import h1
from wj.transport import h2 as h2_transport


def make_ctx():
    caps = capabilities.Capabilities(libs={"h2": True}, tools={},
                                     privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=5.0, deadline=1e9, caps=caps, results={})


def _decoded_headers(headers):
    def _s(v):
        return v.decode() if isinstance(v, bytes) else v
    return {_s(k): _s(v) for k, v in headers}


RAW_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Encoding: gzip\r\n"
    b"Cache-Control: max-age=300\r\n"
    b"\r\n"
)


def test_parse_response_splits_status_headers_and_body():
    raw = RAW_200 + b"BODYBYTES"
    parsed = h1.parse_response(raw)
    assert parsed["protocol"] == "HTTP/1.1"
    assert parsed["status"] == 200
    assert parsed["reason"] == "OK"
    assert ("Content-Type", "text/html; charset=utf-8") in parsed["headers"]
    assert parsed["body"] == b"BODYBYTES"


def test_parse_response_survives_a_truncated_status_line():
    parsed = h1.parse_response(b"")
    assert parsed["status"] is None
    assert parsed["headers"] == []


def test_parse_response_reports_reason_as_absent_not_empty_string():
    parsed = h1.parse_response(b"HTTP/1.1 200\r\n\r\n")
    assert parsed["status"] == 200
    assert parsed["reason"] is None


def test_header_value_is_case_insensitive():
    headers = [("Content-Type", "text/html")]
    assert http_collect.header_value(headers, "content-type") == "text/html"
    assert http_collect.header_value(headers, "missing") is None


def test_dechunk_reassembles_chunked_body():
    chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    assert h1.dechunk(chunked) == b"hello world"


def test_decode_body_inflates_gzip_and_reports_encoding():
    payload = b"<html>" + b"x" * 500 + b"</html>"
    headers = [("Content-Encoding", "gzip")]
    decoded, encoding = http_collect.decode_body(headers, gzip.compress(payload))
    assert decoded == payload
    assert encoding == "gzip"


def test_decode_body_passes_plain_bodies_through():
    decoded, encoding = http_collect.decode_body([], b"plain")
    assert decoded == b"plain"
    assert encoding is None


def test_decode_body_refuses_a_still_chunked_body_instead_of_guessing():
    # decode_body's contract is that Transfer-Encoding is always already gone
    # by the time it sees headers (h1.parse_response strips it after
    # dechunking). A caller that skips that step is a programming error, and
    # decoding the still-chunked bytes as if they were content would silently
    # produce a plausible-looking but wrong value -- exactly the class of
    # fabricated measurement this project forbids. Fail loudly instead.
    headers = [("Transfer-Encoding", "chunked")]
    with pytest.raises(ValueError):
        http_collect.decode_body(headers, b"5\r\nhello\r\n0\r\n\r\n")


def test_a_chunked_gzip_body_round_trips_through_parse_then_decode():
    payload = b"y" * 40
    blob = gzip.compress(payload)
    chunked = b"%x\r\n" % len(blob) + blob + b"\r\n0\r\n\r\n"
    raw = (b"HTTP/1.1 200 OK\r\n"
           b"Transfer-Encoding: chunked\r\n"
           b"Content-Encoding: gzip\r\n"
           b"\r\n") + chunked

    parsed = h1.parse_response(raw)
    decoded, encoding = http_collect.decode_body(parsed["headers"], parsed["body"])
    assert decoded == payload
    assert encoding == "gzip"


def test_decode_body_a_failed_gzip_inflate_returns_none_not_the_raw_bytes():
    # I4: returning the raw (still-compressed) bytes under the "gzip" label
    # made decoded == wire and produced a ~1.0 "compression ratio" that read
    # as a measurement instead of a decode failure.
    headers = [("Content-Encoding", "gzip")]
    decoded, encoding = http_collect.decode_body(headers, b"not actually gzip")
    assert decoded is None
    assert encoding == "gzip"


def test_decode_body_a_failed_deflate_inflate_returns_none():
    headers = [("Content-Encoding", "deflate")]
    decoded, encoding = http_collect.decode_body(headers, b"not actually deflate")
    assert decoded is None
    assert encoding == "deflate"


def test_parse_cookies_reads_flags():
    headers = [("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"),
               ("Set-Cookie", "tracking=1; Path=/")]
    cookies = http_collect.parse_cookies(headers)
    assert cookies[0] == {"name": "session", "secure": True,
                          "httponly": True, "samesite": "Lax"}
    assert cookies[1] == {"name": "tracking", "secure": False,
                          "httponly": False, "samesite": None}


def test_grade_security_full_house_scores_a():
    headers = [
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    ]
    result = http_collect.grade_security(headers, "https")
    assert result["grade"] == "A"
    assert result["missing"] == []


def test_grade_security_names_what_is_missing():
    result = http_collect.grade_security([("X-Content-Type-Options", "nosniff")], "https")
    assert result["grade"] == "F"
    assert "Content-Security-Policy" in result["missing"]
    assert "X-Content-Type-Options" not in result["missing"]


def test_cache_state_reads_cdn_hit_and_age():
    headers = [("cf-cache-status", "HIT"), ("Age", "412"),
               ("Cache-Control", "max-age=300")]
    state = http_collect.cache_state(headers)
    assert state["state"] == "HIT"
    assert state["age"] == 412
    assert state["header"] == "cf-cache-status"
    assert state["directives"] == "max-age=300"


def test_cache_state_when_nothing_is_advertised():
    state = http_collect.cache_state([])
    assert state["state"] is None
    assert state["age"] is None


def test_detect_cdn_from_signature_headers():
    assert http_collect.detect_cdn([("cf-ray", "8a2b")]) == "Cloudflare"
    assert http_collect.detect_cdn([("x-amz-cf-id", "abc")]) == "CloudFront"
    assert http_collect.detect_cdn([("x-served-by", "cache-fra-1"),
                                    ("x-cache", "HIT")]) == "Fastly"
    assert http_collect.detect_cdn([("server", "nginx")]) is None


def test_collect_follows_a_redirect_chain(monkeypatch):
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    pages = {
        "https://example.com/": {
            "protocol": "HTTP/1.1", "status": 301, "reason": "Moved Permanently",
            "headers": [("Location", "https://www.example.com/")], "body": b"",
            "ttfb_ms": 40.0, "total_ms": 41.0, "wire_bytes": 200},
        "https://www.example.com/": {
            "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
            "headers": [("Content-Type", "text/html")], "body": b"<html></html>",
            "ttfb_ms": 60.0, "total_ms": 70.0, "wire_bytes": 13},
    }

    section = http_collect.collect(ctx, fetch=lambda url, sock: pages[url])
    assert section["observed"] is True
    assert section["redirect_limit_reached"] is False
    assert len(section["hops"]) == 1
    assert section["hops"][0]["status"] == 301
    assert section["final"]["status"] == 200
    assert section["final"]["url"] == "https://www.example.com/"
    assert section["final"]["decoded_bytes"] == 13


def test_collect_a_failed_inflate_leaves_decoded_bytes_and_ratio_absent():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    def fetch(url, sock):
        return {"protocol": "HTTP/1.1", "status": 200, "reason": "OK",
                "headers": [("Content-Encoding", "gzip")], "body": b"not really gzip",
                "ttfb_ms": 1.0, "total_ms": 2.0, "wire_bytes": 15}

    section = http_collect.collect(ctx, fetch=fetch)
    assert section["final"]["encoding"] == "gzip"
    assert section["final"]["wire_bytes"] == 15
    assert section["final"]["decoded_bytes"] is None
    assert section["final"]["ratio"] is None


def test_collect_stops_at_the_redirect_limit():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    def always_redirect(url, sock):
        return {"protocol": "HTTP/1.1", "status": 302, "reason": "Found",
                "headers": [("Location", "https://example.com/next")], "body": b"",
                "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 10}

    section = http_collect.collect(ctx, fetch=always_redirect)
    assert len(section["hops"]) <= http_collect.MAX_REDIRECTS
    assert section["redirect_limit_reached"] is True


def test_final_url_names_the_hop_that_was_actually_fetched():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    seen = []

    def walking_redirect(url, sock):
        seen.append(url)
        return {"protocol": "HTTP/1.1", "status": 302, "reason": "Found",
                "headers": [("Location", f"https://example.com/hop{len(seen)}")],
                "body": b"", "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 10}

    section = http_collect.collect(ctx, fetch=walking_redirect)
    assert section["final"]["url"] == seen[-1]
    assert section["redirect_limit_reached"] is True


def test_build_request_records_the_line_and_headers_it_will_send():
    req = h1.build_request("https://example.com/dashboard?q=1")
    assert req["method"] == "GET"
    assert req["target"] == "/dashboard?q=1"
    assert req["http_version"] == "HTTP/1.1"
    assert req["headers"][0] == ("Host", "example.com")
    names = [k for k, _ in req["headers"]]
    assert names == ["Host", "User-Agent", "Accept-Encoding", "Accept", "Connection"]


def test_request_bytes_round_trips_through_parse_response_shape():
    # The bytes build_request/request_bytes produce must be a valid HTTP/1.1
    # request-message: a request line followed by CRLF-separated headers and a
    # blank line. parse_response only parses responses, so assert on the raw form.
    raw = h1.request_bytes(h1.build_request("https://example.com/"))
    assert raw.startswith(b"GET / HTTP/1.1\r\n")
    assert raw.endswith(b"\r\n\r\n")
    assert b"Host: example.com\r\n" in raw


def test_collect_records_the_request_the_real_h1_transport_actually_sent():
    # Driven through the REAL h1 transport, not an injected stub: the point of
    # final.request is that it is what went on the wire, so a stub that returns
    # a "request" of its own choosing would prove nothing about the collector.
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    sock = FakeH1Socket([RAW_200 + b"hi"])
    ctx.results["tls"] = {"observed": True, "_socket": sock}

    section = http_collect.collect(ctx)
    request = section["final"]["request"]
    assert request["method"] == "GET"
    assert request["http_version"] == "HTTP/1.1"
    assert ("Host", "example.com") in request["headers"]
    assert any(k == "User-Agent" for k, _ in request["headers"])
    # What was recorded is what the socket actually received.
    assert sock.sent.startswith(
        f"{request['method']} {request['target']} {request['http_version']}".encode())


def test_collect_does_not_fabricate_a_request_no_transport_reported():
    # The removed `response.get("request") or h1.build_request(fetched_url)`
    # fallback could only ever publish an HTTP/1.1 request that was never sent
    # -- on an h2 trace it would have invented a wire format the connection
    # does not even speak. Both transports always set "request"; if one ever
    # stops, the field must go absent, not get filled in with a plausible
    # reconstruction.
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    def fetch(url, sock):
        return {"protocol": "HTTP/1.1", "status": 200, "reason": "OK",
                "headers": [("Content-Type", "text/html")], "body": b"hi",
                "ttfb_ms": 1.0, "total_ms": 2.0, "wire_bytes": 2}

    section = http_collect.collect(ctx, fetch=fetch)
    assert section["final"]["request"] is None


def test_both_transports_always_report_the_request_they_sent():
    # The premise the deleted fallback rested on, checked directly rather than
    # assumed: neither transport can leave "request" unset, so the collector
    # never has a real occasion to reconstruct one.
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={"h2": True}, tools={},
                                     privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})

    h1_response = h1.fetcher(ctx)("https://example.com/",
                                  FakeH1Socket([RAW_200 + b"hi"]))
    assert h1_response["request"]["http_version"] == "HTTP/1.1"

    h2_sock = FakeTLSSocket([(":status", "200"), ("content-type", "text/html")])
    h2_response = h2_transport.fetcher(ctx)("https://example.com/", h2_sock)
    assert h2_response["request"]["http_version"] == "HTTP/2"
    assert (":authority", "example.com") in h2_response["request"]["headers"]


def test_collect_reports_content_type_as_absent_not_empty_string():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    def fetch(url, sock):
        return {"protocol": "HTTP/1.1", "status": 200, "reason": "OK",
                "headers": [], "body": b"hi", "ttfb_ms": 1.0, "total_ms": 2.0, "wire_bytes": 2}

    section = http_collect.collect(ctx, fetch=fetch)
    assert section["final"]["content_type"] is None


def test_transport_follows_what_alpn_actually_selected():
    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": object()}
    module, protocol = http_collect.transport_for(ctx)
    assert protocol == "h2"
    assert module is __import__("wj.transport.h2", fromlist=["h2"])


def test_transport_falls_to_http1_when_alpn_selected_nothing():
    # A server that does no ALPN at all leaves selected_alpn_protocol() None.
    # HTTP/1.1 is the correct reading of that, not a guess.
    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": None, "_socket": object()}
    _module, protocol = http_collect.transport_for(ctx)
    assert protocol == "http/1.1"


def test_negotiation_chosen_is_filled_in_from_the_handshake():
    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": object()}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2", "http/1.1"],
                                  "chosen": None, "attempted": []}

    http_collect.collect(ctx, fetch=lambda url, sock: {
        "protocol": "HTTP/2", "status": 200, "reason": None,
        "headers": [("content-type", "text/html")], "body": b"x",
        "ttfb_ms": 5.0, "total_ms": 6.0, "wire_bytes": 1,
        "stream_id": 1, "header_bytes": {"wire": 30, "decoded": 90}})

    assert ctx.results["negotiation"]["chosen"] == "h2"


def test_h2_hops_report_connection_reuse():
    # HTTP/1.1 sends Connection: close, so every hop is a new connection.
    # HTTP/2 reuses one, and the trace should say so -- as reported by the
    # transport itself (connection_reused in the response dict), not
    # inferred by the collector from the protocol name and hop count.
    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": object()}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2"], "chosen": None,
                                  "attempted": []}
    pages = {
        "https://example.com/": {
            "protocol": "HTTP/2", "status": 301, "reason": None,
            "headers": [("location", "https://example.com/next")], "body": b"",
            "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0,
            "stream_id": 1, "header_bytes": {"wire": 20, "decoded": 60},
            "connection_reused": False},
        "https://example.com/next": {
            "protocol": "HTTP/2", "status": 200, "reason": None,
            "headers": [("content-type", "text/html")], "body": b"ok",
            "ttfb_ms": 2.0, "total_ms": 2.0, "wire_bytes": 2,
            "stream_id": 3, "header_bytes": {"wire": 22, "decoded": 66},
            "connection_reused": True},
    }
    section = http_collect.collect(ctx, fetch=lambda url, sock: pages[url])

    assert section["hops"][0]["connection_reused"] is False   # the first hop opened it
    assert section["hops"][0]["stream_id"] == 1
    assert section["final"]["header_bytes"]["wire"] == 22


def test_h2_redirect_hops_keep_the_same_connection_object():
    # connection_reused: True is only honest if collect() actually hands the
    # transport the same socket on the next hop -- setting sock = None
    # unconditionally (the pre-Task-4 behaviour, correct for HTTP/1.1's
    # Connection: close) would force h2.fetcher() to open a fresh one, making
    # the flag a lie. Assert on the sock argument fetch() actually receives,
    # not just the label collect() attaches to the hop.
    ctx = make_ctx()
    sentinel_socket = object()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": sentinel_socket}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2"], "chosen": None,
                                  "attempted": []}
    pages = {
        "https://example.com/": {
            "protocol": "HTTP/2", "status": 301, "reason": None,
            "headers": [("location", "https://example.com/next")], "body": b"",
            "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0,
            "stream_id": 1, "header_bytes": {"wire": 20, "decoded": 60}},
        "https://example.com/next": {
            "protocol": "HTTP/2", "status": 200, "reason": None,
            "headers": [("content-type", "text/html")], "body": b"ok",
            "ttfb_ms": 2.0, "total_ms": 2.0, "wire_bytes": 2,
            "stream_id": 3, "header_bytes": {"wire": 22, "decoded": 66}},
    }
    seen_socks = []

    def fetch(url, sock):
        seen_socks.append(sock)
        return pages[url]

    http_collect.collect(ctx, fetch=fetch)

    assert seen_socks == [sentinel_socket, sentinel_socket]


def test_http1_redirect_hops_open_a_fresh_connection():
    ctx = make_ctx()
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "alpn": None, "_socket": object()}
    pages = {
        "https://example.com/": {
            "protocol": "HTTP/1.1", "status": 301, "reason": "Moved Permanently",
            "headers": [("Location", "https://example.com/next")], "body": b"",
            "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0},
        "https://example.com/next": {
            "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
            "headers": [("content-type", "text/html")], "body": b"ok",
            "ttfb_ms": 2.0, "total_ms": 2.0, "wire_bytes": 2},
    }
    seen_socks = []

    def fetch(url, sock):
        seen_socks.append(sock)
        return pages[url]

    http_collect.collect(ctx, fetch=fetch)

    assert seen_socks[0] is not None
    assert seen_socks[1] is None


def test_connection_reused_is_copied_from_the_response_not_inferred():
    # The collector must not compute its own opinion of reuse from the
    # protocol name and hop count -- it copies whatever the transport
    # reported. A stub that (implausibly, but that's the point) claims
    # reuse under http/1.1 proves nothing here overrides it.
    ctx = make_ctx()
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "alpn": None, "_socket": object()}

    def fetch(url, sock):
        return {"protocol": "HTTP/1.1", "status": 301, "reason": "Moved Permanently",
                "headers": [("Location", "https://example.com/next")], "body": b"",
                "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0,
                "connection_reused": True} if url.endswith("/") else {
                "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
                "headers": [("content-type", "text/html")], "body": b"ok",
                "ttfb_ms": 2.0, "total_ms": 2.0, "wire_bytes": 2}

    section = http_collect.collect(ctx, fetch=fetch)

    assert section["hops"][0]["connection_reused"] is True


def test_connection_reused_is_absent_not_false_when_the_transport_does_not_report_it():
    ctx = make_ctx()
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": True, "alpn": None, "_socket": object()}

    def fetch(url, sock):
        return {"protocol": "HTTP/1.1", "status": 301, "reason": "Moved Permanently",
                "headers": [("Location", "https://example.com/next")], "body": b"",
                "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0} if url.endswith("/") else {
                "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
                "headers": [("content-type", "text/html")], "body": b"ok",
                "ttfb_ms": 2.0, "total_ms": 2.0, "wire_bytes": 2}

    section = http_collect.collect(ctx, fetch=fetch)

    assert section["hops"][0]["connection_reused"] is None


def test_collect_refuses_the_dead_socket_after_a_failed_handshake():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["tls"] = {"observed": False, "why_not": "TLS handshake failed: certificate expired"}

    section = http_collect.collect(ctx, fetch=lambda url, sock: pytest.fail(
        "must not attempt a request after a failed handshake"))
    assert section["observed"] is False
    assert "certificate expired" in section["why_not"]


def test_a_negotiated_protocol_this_build_cannot_speak_names_the_protocol_not_a_timeout():
    # Before transport selection existed, this case always fell back to the
    # h1 transport regardless of what ALPN actually chose -- an h2-accepting
    # host with no h2 library installed made HTTP/1.1 bytes go out over what
    # is now an h2-only connection, got no valid HTTP/1.1 response back, and
    # the caller saw "no response received before the timeout": a real
    # explanation for a completely different cause. The server agreed to
    # speak h2; this build cannot; that is what why_not must say, not "timeout".
    caps = capabilities.Capabilities(libs={"h2": False}, tools={},
                                     privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": object()}

    section = http_collect.collect(ctx, fetch=None)

    assert section["observed"] is False
    assert "h2" in section["why_not"]
    assert "timeout" not in section["why_not"]


def test_chosen_is_recorded_even_when_the_transport_then_fails_to_load():
    # The handshake measured a real choice; a transport that fails to load
    # afterwards is a separate, later fact. Discarding the measurement
    # because the later step failed would be the mirror image of fabricating
    # one -- the trace should say both what was negotiated AND that no
    # transport could be loaded for it.
    caps = capabilities.Capabilities(libs={"h2": False}, tools={},
                                     privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": object()}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2"], "chosen": None,
                                  "attempted": []}

    section = http_collect.collect(ctx, fetch=None)

    assert section["observed"] is False
    assert ctx.results["negotiation"]["chosen"] == "h2"


def test_an_alpn_protocol_with_no_transport_module_names_it_not_a_timeout():
    # h3 (or any future protocol negotiate.py might one day offer) has no
    # entry in TRANSPORTS at all -- distinct from TransportUnavailable (a
    # transport exists but this build can't use it, e.g. a missing library).
    # transport_for()'s own fallback-to-http/1.1 exists for the "ALPN
    # selected nothing" case; silently reusing it here would write HTTP/1.1
    # bytes over a connection the server agreed to speak h3 over, and would
    # report chosen: "http/1.1" -- a protocol nobody chose.
    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h3", "_socket": object()}
    ctx.results["negotiation"] = {"observed": True, "advertised": ["h3"],
                                  "offered": ["h2", "http/1.1"], "unavailable": [],
                                  "chosen": None, "attempted": []}

    section = http_collect.collect(ctx, fetch=lambda url, sock: pytest.fail(
        "must not attempt a request over a protocol this build has no transport for"))

    assert section["observed"] is False
    assert "h3" in section["why_not"]
    assert "timeout" not in section["why_not"]

    # The handshake MEASURED this selection; the missing transport is a
    # separate, later fact. Discarded here, the page printed "Negotiated:
    # nothing (ALPN selected no protocol)" three rows under its own measured
    # "ALPN: h3" -- a false negative wearing a measured badge, not a gap.
    # (Reachable in the wild: OpenSSL does not enforce that the server's
    # selected ALPN token came from the client's list.)
    assert ctx.results["negotiation"]["chosen"] == "h3"


def test_negotiation_chosen_stays_none_for_plain_http():
    # transport_for()'s protocol is a fallback ("http/1.1" whenever ALPN
    # reported nothing), not a negotiated choice -- ALPN does not even apply
    # without TLS. chosen must stay unmeasured, not silently inherit the
    # fallback.
    caps = capabilities.Capabilities(libs={"h2": True}, tools={},
                                     privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="http", port=80, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}
    ctx.results["negotiation"] = {"observed": True, "advertised": [], "offered": [],
                                  "signal": "no TLS — ALPN does not apply",
                                  "unavailable": [], "chosen": None, "attempted": []}

    http_collect.collect(ctx, fetch=lambda url, sock: {
        "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
        "headers": [], "body": b"", "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0})

    assert ctx.results["negotiation"]["chosen"] is None


def test_negotiation_chosen_stays_none_when_alpn_selected_nothing():
    # TLS ran but the server did no ALPN at all. transport_for() still picks
    # h1 to actually speak (the correct reading of "nothing selected"), but
    # that is this tool's own fallback decision, not a fact about what the
    # server chose -- chosen must not borrow it.
    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": None, "_socket": object()}
    ctx.results["negotiation"] = {"observed": True, "advertised": [], "offered": ["http/1.1"],
                                  "signal": "no HTTPS record",
                                  "unavailable": [], "chosen": None, "attempted": []}

    http_collect.collect(ctx, fetch=lambda url, sock: {
        "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
        "headers": [], "body": b"", "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 0})

    assert ctx.results["negotiation"]["chosen"] is None


def test_collect_opens_a_fresh_connection_for_a_cross_origin_h2_redirect(monkeypatch):
    # Critical regression probe: a redirect that leaves the origin must not
    # be sent over the origin's own connection -- that connection is a TLS
    # session established with, and authenticated to, a DIFFERENT host. Real
    # h2 framing on both ends (via the real server-side h2.connection used
    # throughout tests/test_transport_h2.py), no stubbed fetch: this is the
    # collector driven through the real transport, not through a lambda.
    origin_sock = FakeTLSSocket(
        [(":status", "301"), ("location", "https://totally-other-host.net/landing")])
    other_sock = FakeTLSSocket([(":status", "200")], body=b"landing page")
    monkeypatch.setattr(h2_transport, "open_connection", lambda split, ctx: other_sock)

    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": origin_sock}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2"], "chosen": None,
                                  "attempted": []}

    section = http_collect.collect(ctx, fetch=None)

    # Exactly one request physically reached each connection -- the second
    # request did NOT go out over example.com's socket.
    assert len(origin_sock.requests_seen) == 1
    assert _decoded_headers(origin_sock.requests_seen[0])[":authority"] == "example.com"
    assert len(other_sock.requests_seen) == 1
    assert _decoded_headers(other_sock.requests_seen[0])[":authority"] == "totally-other-host.net"

    assert section["final"]["url"] == "https://totally-other-host.net/landing"
    assert section["final"]["status"] == 200
    assert section["hops"][0]["connection_reused"] is False
    assert origin_sock.closed is False   # belongs to the TLS collector, not this call
    assert other_sock.closed is True     # opened and closed within this one redirect hop


def test_collect_reuses_the_real_h2_connection_for_a_same_origin_redirect():
    # The other side of the same fix: a same-origin redirect must still
    # reuse the one connection, real h2 framing on both ends.
    origin_sock = FakeTLSSocket(
        [(":status", "301"), ("location", "https://example.com/next")])

    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": origin_sock}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2"], "chosen": None,
                                  "attempted": []}

    call_count = {"n": 0}
    real_respond = origin_sock._respond

    def _respond(stream_id):
        call_count["n"] += 1
        if call_count["n"] == 1:
            real_respond(stream_id)
        else:
            origin_sock._response_headers = [(":status", "200")]
            origin_sock._body = b"ok"
            real_respond(stream_id)

    origin_sock._respond = _respond

    section = http_collect.collect(ctx, fetch=None)

    assert len(origin_sock.requests_seen) == 2
    assert section["final"]["url"] == "https://example.com/next"
    assert section["final"]["status"] == 200
    assert section["hops"][0]["connection_reused"] is False   # the first request opened it


def test_collect_falls_back_to_h1_for_a_cleartext_redirect_hop_under_h2(monkeypatch):
    # Important-1 regression probe: an h2 origin redirecting to a plain
    # http:// target must not hand that hop to the h2 transport at all --
    # HTTP/2 over cleartext needs "prior knowledge" this tool has no way to
    # acquire (ALPN cannot run without TLS). Driven against a realistic
    # HTTP/1.1-only plain socket: if h2 were still selected for this hop, it
    # would burn the whole timeout budget and report a misleading "no
    # response received" instead of the real answer below.
    origin_sock = FakeTLSSocket(
        [(":status", "301"), ("location", "http://plain.example.com/landing")])
    plain_sock = FakeH1Socket(
        [b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello"])
    monkeypatch.setattr(h1, "open_connection", lambda split, ctx: plain_sock)

    ctx = make_ctx()
    ctx.results["tls"] = {"observed": True, "alpn": "h2", "_socket": origin_sock}
    ctx.results["negotiation"] = {"observed": True, "offered": ["h2"], "chosen": None,
                                  "attempted": []}

    section = http_collect.collect(ctx, fetch=None)

    assert len(origin_sock.requests_seen) == 1   # the cleartext hop never went to h2
    assert section["observed"] is True
    assert section["final"]["url"] == "http://plain.example.com/landing"
    assert section["final"]["protocol"] == "HTTP/1.1"   # honestly reports which transport served it
    assert section["final"]["status"] == 200
    assert plain_sock.sent.startswith(b"GET /landing HTTP/1.1\r\n")
