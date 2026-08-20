"""Layer 7: the request, every redirect it took, and what the response tells you."""

import gzip
import time
import zlib
from urllib.parse import urljoin, urlsplit

from wj.schema import observed, unobserved

MAX_REDIRECTS = 10
DEFAULT_PORTS = {"http": 80, "https": 443}

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


def parse_response(raw):
    blob, _, body = raw.partition(b"\r\n\r\n")
    lines = blob.decode("latin-1", errors="replace").split("\r\n")
    protocol = status = reason = None
    if lines and lines[0]:
        parts = lines[0].split(" ", 2)
        protocol = parts[0] if parts else None
        if len(parts) > 1:
            try:
                status = int(parts[1])
            except ValueError:
                status = None
        reason = parts[2] if len(parts) > 2 else None

    headers = []
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers.append((key.strip(), value.strip()))

    return {"protocol": protocol, "status": status, "reason": reason,
            "headers": headers, "body": body}


def dechunk(body):
    out = bytearray()
    rest = body
    while rest:
        size_line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        rest = rest[size:].lstrip(b"\r\n")
    return bytes(out)


def decode_body(headers, body):
    if (header_value(headers, "transfer-encoding") or "").lower() == "chunked":
        body = dechunk(body)

    encoding = (header_value(headers, "content-encoding") or "").lower() or None
    if encoding == "gzip":
        try:
            return gzip.decompress(body), "gzip"
        except OSError:
            return body, "gzip"
    if encoding == "deflate":
        try:
            return zlib.decompress(body), "deflate"
        except zlib.error:
            return body, "deflate"
    if encoding == "br":
        try:
            import brotli
            return brotli.decompress(body), "br"
        except Exception:
            return body, "br"
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


def _open(split, ctx):
    """Open a connection for a redirect hop, matching the URL's own scheme."""
    import socket
    import ssl

    port = split.port or DEFAULT_PORTS.get(split.scheme, 443)
    sock = socket.create_connection((split.hostname, port), timeout=ctx.budget_for(ctx.timeout))
    if split.scheme == "https":
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        sock = context.wrap_socket(sock, server_hostname=split.hostname)
    return sock


def _socket_fetch(ctx):
    def fetch(url, sock):
        split = urlsplit(url)
        opened_here = sock is None
        if opened_here:
            # Each redirect hop needs a fresh connection: the first one was opened by
            # the TCP/TLS collectors and closes after this response (Connection: close).
            sock = _open(split, ctx)
        try:
            path = split.path or "/"
            if split.query:
                path += "?" + split.query
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {split.hostname}\r\n"
                f"User-Agent: webpage-journey/2.0\r\n"
                f"Accept-Encoding: gzip, deflate\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

            sock.settimeout(ctx.budget_for(ctx.timeout))
            started = time.perf_counter()
            sock.sendall(request)

            chunks = []
            ttfb = None
            while True:
                try:
                    data = sock.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                if ttfb is None:
                    ttfb = round((time.perf_counter() - started) * 1000, 1)
                chunks.append(data)

            raw = b"".join(chunks)
            parsed = parse_response(raw)
            parsed["ttfb_ms"] = ttfb
            parsed["total_ms"] = round((time.perf_counter() - started) * 1000, 1)
            parsed["wire_bytes"] = len(parsed["body"])
            return parsed
        finally:
            # Only close what this call opened. The first hop's socket belongs to
            # the TLS/TCP collector and is closed later by the orchestrator.
            if opened_here:
                sock.close()

    return fetch


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

    fetch = fetch or _socket_fetch(ctx)

    url = f"{ctx.scheme}://{ctx.host}{ctx.path}"
    hops = []
    response = None
    fetched_url = url
    limit_reached = True  # cleared by the break below once a non-redirect response lands

    for _ in range(MAX_REDIRECTS):
        try:
            response = fetch(url, sock)
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
            hops.append({"url": url, "status": status,
                         "location": urljoin(url, location),
                         "protocol": response.get("protocol"),
                         "ttfb_ms": response.get("ttfb_ms")})
            url = urljoin(url, location)
            sock = None  # fetch opens a fresh connection for the next hop
            continue
        limit_reached = False
        break

    decoded, encoding = decode_body(response["headers"], response["body"])
    wire = response.get("wire_bytes") or len(response["body"])
    ratio = round(len(decoded) / wire, 2) if wire and encoding else None
    raw_content_type = header_value(response["headers"], "content-type")
    content_type = raw_content_type.split(";")[0].strip() if raw_content_type else None

    return observed(
        hops=hops,
        redirect_limit_reached=limit_reached,
        final={"url": fetched_url, "status": response["status"], "reason": response.get("reason"),
               "protocol": response.get("protocol"), "headers": response["headers"],
               "ttfb_ms": response.get("ttfb_ms"), "total_ms": response.get("total_ms"),
               "wire_bytes": wire, "decoded_bytes": len(decoded),
               "encoding": encoding, "ratio": ratio, "content_type": content_type},
        cache=cache_state(response["headers"]),
        cdn=detect_cdn(response["headers"]),
        security=grade_security(response["headers"], ctx.scheme),
        conditional={"tested": False},
    )
