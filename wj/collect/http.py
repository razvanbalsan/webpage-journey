"""Layer 7: the request, every redirect it took, and what the response tells you."""

import gzip
import zlib
from urllib.parse import urljoin, urlsplit

from wj.schema import observed, unobserved
from wj.transport import TRANSPORTS, h1
from wj.transport.h2 import TransportUnavailable

MAX_REDIRECTS = 10

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
)

GRADE_THRESHOLDS = ((6, "A"), (5, "B"), (4, "C"), (3, "D"), (2, "E"))

CDN_SIGNATURES = (
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "CloudFront"),
    ("x-served-by", "Fastly"),
    ("x-akamai-transformed", "Akamai"),
    ("x-vercel-id", "Vercel"),
)

CACHE_HEADERS = ("cf-cache-status", "x-cache", "x-drupal-cache", "x-vercel-cache")


def header_value(headers, name):
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None


def decode_body(headers, body):
    """Undo Content-Encoding (compression). Transfer-Encoding (framing) is the
    transport's concern: h1.parse_response() has already dechunked the body and
    dropped the header by the time it reaches here, and HTTP/2 has no such
    header at all.
    """
    # If Transfer-Encoding: chunked is still present, the caller skipped the
    # transport's dechunking step -- decoding these bytes as the body would
    # silently produce a plausible-looking but wrong value (still-chunked
    # framing decompressed or passed through as if it were content), with no
    # absence marker to show it happened. That is a programming error in the
    # caller, not a measurement to report, so this fails loudly instead of
    # guessing.
    if (header_value(headers, "transfer-encoding") or "").lower() == "chunked":
        raise ValueError(
            "decode_body received a still-chunked body -- the caller must "
            "dechunk (see wj.transport.h1.parse_response) before calling this")

    # A decompression failure returns None for the decoded body, not the raw
    # (still-compressed) bytes under the same encoding label -- returning the
    # raw bytes made decoded == wire and produced a ~1.0 "compression ratio"
    # that looked like a measurement instead of a decode failure. `encoding`
    # itself is still reported: the header really did say so, and it is a
    # separate fact from whether this tool could act on it.
    encoding = (header_value(headers, "content-encoding") or "").lower() or None
    if encoding == "gzip":
        try:
            return gzip.decompress(body), "gzip"
        except OSError:
            return None, "gzip"
    if encoding == "deflate":
        try:
            return zlib.decompress(body), "deflate"
        except zlib.error:
            return None, "deflate"
    if encoding == "br":
        try:
            import brotli
            return brotli.decompress(body), "br"
        except Exception:
            return None, "br"
    return body, encoding


def parse_cookies(headers):
    cookies = []
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in value.split(";")]
        name = parts[0].split("=", 1)[0] if parts else ""
        flags = [p.lower() for p in parts[1:]]
        samesite = None
        for part in parts[1:]:
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1]
        cookies.append({"name": name,
                        "secure": "secure" in flags,
                        "httponly": "httponly" in flags,
                        "samesite": samesite})
    return cookies


def grade_security(headers, scheme):
    present = {}
    missing = []
    for name in SECURITY_HEADERS:
        value = header_value(headers, name)
        if value:
            present[name] = value
        else:
            missing.append(name)

    score = len(present)
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return {"grade": grade, "present": present, "missing": missing,
            "cookies": parse_cookies(headers), "scheme": scheme}


def cache_state(headers):
    state = header_name = None
    for name in CACHE_HEADERS:
        value = header_value(headers, name)
        if value:
            state = value.split()[0].upper()
            header_name = name
            break

    age = header_value(headers, "age")
    try:
        age = int(age) if age is not None else None
    except ValueError:
        age = None

    return {"state": state, "age": age, "header": header_name,
            "directives": header_value(headers, "cache-control")}


def detect_cdn(headers):
    for name, cdn in CDN_SIGNATURES:
        if header_value(headers, name):
            return cdn
    server = (header_value(headers, "server") or "").lower()
    if "cloudflare" in server:
        return "Cloudflare"
    return None


def transport_for(ctx):
    """The transport for the protocol ALPN actually selected.

    The server chooses during the handshake; we follow. A server that does no
    ALPN leaves this None, and HTTP/1.1 is the correct reading of that rather
    than a guess.
    """
    alpn = (ctx.results.get("tls", {}) or {}).get("alpn")
    protocol = alpn if alpn in TRANSPORTS else "http/1.1"
    return TRANSPORTS[protocol], protocol


def collect(ctx, fetch=None):
    tls = ctx.results.get("tls", {})
    tcp = ctx.results.get("tcp", {})

    if tls.get("observed"):
        sock = tls.get("_socket")
    elif ctx.scheme == "https":
        # TLS was attempted for this scheme and did not succeed. The TCP socket was
        # detached by wrap_socket() and is a dead descriptor — do not reach for it.
        return unobserved(f"no encrypted channel: {tls.get('why_not', 'TLS did not complete')}")
    else:
        sock = tcp.get("_socket")

    if sock is None:
        return unobserved("no connection to send a request over")

    alpn = tls.get("alpn")
    if alpn is not None and alpn not in TRANSPORTS:
        # A protocol the server actually selected but this build has no
        # transport module for at all (h3, deferred to Phase 2) -- distinct
        # from TransportUnavailable below, where the module exists but this
        # build can't use it (e.g. a missing library). transport_for()'s own
        # fallback to HTTP/1.1 exists for "ALPN selected nothing"; silently
        # reusing it here would write the wrong protocol's bytes over a
        # connection the server agreed to speak something else over, and
        # would report a chosen protocol nobody chose.
        return unobserved(f"negotiated {alpn} but this build has no transport for it")

    module, protocol = transport_for(ctx)

    negotiation = ctx.results.get("negotiation")
    if alpn and isinstance(negotiation, dict) and negotiation.get("observed"):
        # `alpn`, not `protocol`: protocol is transport_for()'s fallback for
        # when ALPN reported nothing, and a fallback is not a negotiated
        # choice -- they coincide only when the server explicitly selected
        # http/1.1 over ALPN. Recorded before the fetcher is even built: the
        # handshake already measured this, and a transport that then fails
        # to load (below) is a separate fact -- discarding a measurement
        # because a later step failed would be the mirror image of
        # fabricating one.
        negotiation["chosen"] = alpn

    if fetch is None:
        try:
            fetch = module.fetcher(ctx)
        except TransportUnavailable as exc:
            # ALPN selected a protocol this build cannot frame. That is an error,
            # not a fallback: the server agreed to speak it. Retrying on HTTP/1.1
            # and reporting success would hide a real defect.
            return unobserved(f"negotiated {protocol} but cannot speak it: {exc}")
        # HTTP/2 over cleartext needs "prior knowledge" this tool has no way
        # to acquire -- ALPN cannot run without TLS, so nothing ever confirms
        # a plain http:// hop actually speaks h2. transport_for() is decided
        # once, from the origin's own handshake, and stays fixed for the
        # whole redirect chain; without this, a redirect to a plain http://
        # target would still be handed to the h2 transport, which (verified
        # against a realistic HTTP/1.1-only port-80 server) just burns the
        # timeout budget and reports a misleading "no response received"
        # instead of an answer. Keep h1's fetcher on hand to use for any hop
        # whose own URL is not https, regardless of what the origin
        # negotiated -- each hop's own response.get("protocol") (already
        # recorded per hop below) then honestly reports which transport
        # actually served it, so no new field is needed to carry the switch.
        cleartext_fetch = h1.fetcher(ctx) if protocol != "http/1.1" else fetch
    else:
        cleartext_fetch = fetch

    url = f"{ctx.scheme}://{ctx.host}{ctx.path}"
    hops = []
    response = None
    fetched_url = url
    limit_reached = True  # cleared by the break below once a non-redirect response lands

    for _ in range(MAX_REDIRECTS):
        active_fetch = fetch if urlsplit(url).scheme == "https" else cleartext_fetch
        try:
            response = active_fetch(url, sock)
        except OSError as exc:
            section = unobserved(f"request failed: {exc}")
            section["hops"] = hops
            return section

        fetched_url = url  # this is the URL these measurements describe

        status = response.get("status")
        location = header_value(response["headers"], "location")
        if status is None:
            section = unobserved("no response received before the timeout")
            section["hops"] = hops
            return section

        if 300 <= status < 400 and location:
            next_url = urljoin(url, location)
            target = urlsplit(next_url)
            same_origin = (target.scheme == ctx.scheme and target.hostname == ctx.host
                          and (target.port or h1.DEFAULT_PORTS.get(target.scheme, 443)) == ctx.port)
            hops.append({"url": url, "status": status,
                         "location": next_url,
                         "protocol": response.get("protocol"),
                         "ttfb_ms": response.get("ttfb_ms"),
                         "connection_reused": response.get("connection_reused"),
                         "stream_id": response.get("stream_id")})
            url = next_url
            if protocol == "http/1.1" or not same_origin:
                # A redirect that leaves the origin must not go out over the
                # origin's own connection -- that socket is a TLS session
                # established with, and authenticated to, a DIFFERENT host.
                # fetch() opens a fresh, guarded connection for the next hop.
                sock = None
            continue
        limit_reached = False
        break

    decoded, encoding = decode_body(response["headers"], response["body"])
    wire = response.get("wire_bytes") or len(response["body"])
    ratio = round(len(decoded) / wire, 2) if wire and encoding and decoded is not None else None
    decoded_bytes = len(decoded) if decoded is not None else None
    raw_content_type = header_value(response["headers"], "content-type")
    content_type = raw_content_type.split(";")[0].strip() if raw_content_type else None

    return observed(
        hops=hops,
        redirect_limit_reached=limit_reached,
        final={"url": fetched_url, "status": response["status"], "reason": response.get("reason"),
               "protocol": response.get("protocol"), "headers": response["headers"],
               "request": response.get("request") or h1.build_request(fetched_url),
               "ttfb_ms": response.get("ttfb_ms"), "total_ms": response.get("total_ms"),
               "wire_bytes": wire, "decoded_bytes": decoded_bytes,
               "encoding": encoding, "ratio": ratio, "content_type": content_type,
               "header_bytes": response.get("header_bytes"),
               "connection_reused": response.get("connection_reused")},
        cache=cache_state(response["headers"]),
        cdn=detect_cdn(response["headers"]),
        security=grade_security(response["headers"], ctx.scheme),
        conditional={"tested": False},
    )
