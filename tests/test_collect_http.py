import gzip

import pytest

from wj.collect import http as http_collect
from wj.transport import h1

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


def test_collect_records_the_request_that_was_sent():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tls"] = {"observed": True, "_socket": object()}

    # An injected fetch (as in these tests) returns no "request" key -- collect
    # must reconstruct the request it describes from the final fetched URL.
    def fetch(url, sock):
        return {"protocol": "HTTP/1.1", "status": 200, "reason": "OK",
                "headers": [("Content-Type", "text/html")], "body": b"hi",
                "ttfb_ms": 1.0, "total_ms": 2.0, "wire_bytes": 2}

    section = http_collect.collect(ctx, fetch=fetch)
    request = section["final"]["request"]
    assert request["method"] == "GET"
    assert ("Host", "example.com") in request["headers"]
    assert any(k == "User-Agent" for k, _ in request["headers"])


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
