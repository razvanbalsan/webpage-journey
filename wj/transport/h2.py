"""HTTP/2 framing over the TLS socket the TLS collector already opened.

The h2 library is sans-IO: it turns events into bytes and bytes into events,
and never touches a socket. That is why this transport can keep the socket we
measured — the kernel TCP_INFO readings and the timed TLS handshake stay
valid, which they would not if a client library owned the connection.
"""

import time

from wj.transport.h1 import build_request

# HTTP/2 frame types that carry header block fragments (RFC 7540 §6.2, §6.10).
# PUSH_PROMISE (5) is excluded: this client never accepts server push, so a
# PUSH_PROMISE frame should not appear, and counting it would misattribute
# bytes to the response headers we asked for.
_HEADER_FRAME_TYPES = (1, 9)  # HEADERS, CONTINUATION


class TransportUnavailable(Exception):
    """Raised when this build cannot speak the protocol it was asked for."""


def _connection_state(sock):
    """One h2 connection per socket, so a reused socket continues its stream
    numbering instead of restarting at 1."""
    state = getattr(sock, "_wj_h2", None)
    if state is None:
        import h2.config
        import h2.connection

        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        state = {"conn": conn}
        setattr(sock, "_wj_h2", state)
    return state


def _consume_header_frames(buf):
    """Walk as many complete HTTP/2 frames as `buf` holds, summing the payload
    lengths of HEADERS/CONTINUATION frames, and return (bytes_counted, tail).

    Each frame starts with a 9-byte header: a 3-byte big-endian payload
    length followed by a 1-byte frame type (RFC 7540 §4.1). recv() returns
    whatever the kernel had buffered, not frame-aligned data, so a frame can
    be split across two reads; `tail` is the incomplete remainder to
    prepend to the next chunk rather than misparse now. This is the exact
    number of HPACK-compressed bytes the response headers cost on the wire —
    not an estimate, a count of the frames that actually arrived.
    """
    total = 0
    i = 0
    while i + 9 <= len(buf):
        length = int.from_bytes(buf[i:i + 3], "big")
        frame_type = buf[i + 3]
        if i + 9 + length > len(buf):
            break
        if frame_type in _HEADER_FRAME_TYPES:
            total += length
        i += 9 + length
    return total, buf[i:]


def _decoded_header_size(headers):
    """Bytes these headers would occupy uncompressed, as HTTP/1.1 would send
    them: "name: value\\r\\n" per header. This is the real comparison point
    HPACK is measured against — not a guess, the cost of the same, already-
    decoded header list under the other protocol's framing."""
    return sum(len(name) + 2 + len(value) + 2 for name, value in headers)


def fetcher(ctx):
    if not ctx.caps.has_lib("h2"):
        raise TransportUnavailable("the h2 library is not installed")

    import h2.events

    def fetch(url, sock):
        state = _connection_state(sock)
        conn = state["conn"]

        request = build_request(url)
        headers = [(":method", request["method"]),
                   (":path", request["target"]),
                   (":scheme", "https"),
                   (":authority", dict(request["headers"]).get("Host", ""))]
        headers += [(k.lower(), v) for k, v in request["headers"]
                    if k.lower() != "host"]

        stream_id = conn.get_next_available_stream_id()
        sock.settimeout(ctx.budget_for(ctx.timeout))
        started = time.perf_counter()

        conn.send_headers(stream_id, headers, end_stream=True)
        sock.sendall(conn.data_to_send())

        response_headers = []
        body = bytearray()
        header_wire_bytes = 0
        frame_tail = b""
        ttfb = None
        done = False

        while not done:
            try:
                data = sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            counted, frame_tail = _consume_header_frames(frame_tail + data)
            header_wire_bytes += counted
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
                    if ttfb is None:
                        ttfb = round((time.perf_counter() - started) * 1000, 1)
                    response_headers = list(event.headers)
                elif isinstance(event, h2.events.DataReceived) and event.stream_id == stream_id:
                    body += event.data
                    conn.acknowledge_received_data(len(event.data), event.stream_id)
                elif isinstance(event, h2.events.StreamEnded) and event.stream_id == stream_id:
                    done = True
            pending = conn.data_to_send()
            if pending:
                sock.sendall(pending)

        decoded = _decode_headers(response_headers)
        return {
            "protocol": "HTTP/2",
            "status": decoded["status"],
            "reason": None,          # HTTP/2 has no reason phrase; absent, not ""
            "headers": decoded["headers"],
            "body": bytes(body),
            "ttfb_ms": ttfb,
            "total_ms": round((time.perf_counter() - started) * 1000, 1),
            "wire_bytes": len(body),
            "stream_id": stream_id,
            "header_bytes": {"wire": header_wire_bytes,
                             "decoded": _decoded_header_size(decoded["headers"])},
        }

    return fetch


def _decode_headers(raw_headers):
    """Split h2's pseudo-headers from real ones.

    :status carries the status code; it is not a header a reader should see
    listed beside content-type, and it must not reach the security grader.
    """
    status = None
    headers = []
    for name, value in raw_headers:
        name = name.decode() if isinstance(name, bytes) else name
        value = value.decode() if isinstance(value, bytes) else value
        if name == ":status":
            status = int(value)
        elif not name.startswith(":"):
            headers.append((name, value))
    return {"status": status, "headers": headers}
