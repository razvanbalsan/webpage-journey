"""HTTP/1.1 wire protocol: build the request bytes, speak them over a socket,
parse the response bytes back into structured data. Interpretation of what
the response means belongs to wj/collect/http.py, not here.
"""

import time
from urllib.parse import urlsplit

from wj.collect.tls import alpn_for

DEFAULT_PORTS = {"http": 80, "https": 443}

# The fixed headers this tool sends on every hop. Kept as data (not baked into
# an f-string) so the exact set that went out can be recorded on the trace and
# shown back to the user, rather than reconstructed by eye from the source.
REQUEST_HEADERS = (
    ("User-Agent", "webpage-journey/2.0"),
    ("Accept-Encoding", "gzip, deflate"),
    ("Accept", "*/*"),
    ("Connection", "close"),
)


def build_request(url):
    """The request line and headers this tool sends for one hop.

    Returned as structured data so collect() can record exactly what was sent
    on the final hop and the renderer can print it verbatim. Host comes first,
    as it does on the wire.
    """
    split = urlsplit(url)
    target = split.path or "/"
    if split.query:
        target += "?" + split.query
    headers = [("Host", split.hostname or "")] + list(REQUEST_HEADERS)
    return {"method": "GET", "target": target,
            "http_version": "HTTP/1.1", "headers": headers}


def request_bytes(request):
    """Serialise a build_request() dict to the raw bytes put on the socket."""
    lines = [f"{request['method']} {request['target']} {request['http_version']}"]
    lines += [f"{key}: {value}" for key, value in request["headers"]]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _header(headers, name):
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None


def header_value_absent_after_dechunk(headers):
    """True when no transfer-encoding header survives — used by the tests to pin
    that framing metadata is removed along with the framing itself."""
    return _header(headers, "transfer-encoding") is None


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

    if (_header(headers, "transfer-encoding") or "").lower() == "chunked":
        body = dechunk(body)
        # The header described framing we have now removed. Leaving it would tell
        # decode_body — and every reader of the trace — that the body is still
        # chunked, which it is not.
        headers = [(k, v) for k, v in headers if k.lower() != "transfer-encoding"]

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


def open_connection(split, ctx):
    """Open a connection for a redirect hop, matching the URL's own scheme."""
    import socket
    import ssl

    port = split.port or DEFAULT_PORTS.get(split.scheme, 443)
    sock = socket.create_connection((split.hostname, port), timeout=ctx.budget_for(ctx.timeout))
    if split.scheme == "https":
        context = ssl.create_default_context()
        context.set_alpn_protocols(alpn_for(ctx))
        sock = context.wrap_socket(sock, server_hostname=split.hostname)
    return sock


def fetcher(ctx):
    def fetch(url, sock):
        split = urlsplit(url)
        opened_here = sock is None
        if opened_here:
            # Each redirect hop needs a fresh connection: the first one was opened by
            # the TCP/TLS collectors and closes after this response (Connection: close).
            sock = open_connection(split, ctx)
        try:
            request = build_request(url)

            sock.settimeout(ctx.budget_for(ctx.timeout))
            started = time.perf_counter()
            sock.sendall(request_bytes(request))

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
            parsed["request"] = request
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
