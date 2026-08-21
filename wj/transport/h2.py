"""HTTP/2 framing over the TLS socket the TLS collector already opened.

The h2 library is sans-IO: it turns events into bytes and bytes into events,
and never touches a socket. That is why this transport can keep the socket we
measured — the kernel TCP_INFO readings and the timed TLS handshake stay
valid, which they would not if a client library owned the connection.
"""

import time
from urllib.parse import urlsplit

from wj.transport.h1 import build_request, open_connection

# HTTP/2 frame types this module cares about (RFC 7540 §6.1, §6.2, §6.10).
_DATA_FRAME_TYPE = 0
_HEADER_FRAME_TYPES = (1, 9)  # HEADERS, CONTINUATION


class TransportUnavailable(Exception):
    """Raised when this build cannot speak the protocol it was asked for."""


def _connection_state(sock):
    """One h2 connection per socket, so a reused socket continues its stream
    numbering instead of restarting at 1, and so the raw-byte tail used for
    HPACK wire-size measurement (see _consume_header_frames) survives across
    fetch() calls on the same connection — a frame boundary lines up with a
    recv() call boundary no more reliably than it lines up with a fetch()
    call boundary."""
    state = getattr(sock, "_wj_h2", None)
    if state is None:
        import h2.config
        import h2.connection
        import h2.settings

        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        # This tool asked for one resource and means to measure the response
        # to that one request — not whatever else a server decides to send
        # unprompted. update_settings() (rather than mutating local_settings
        # before initiate_connection(), which the initial SETTINGS frame
        # ignores) queues a real SETTINGS frame telling a compliant server
        # not to push; that keeps a pushed stream from ever arriving, rather
        # than relying on this module to filter one back out.
        conn.update_settings({h2.settings.SettingCodes.ENABLE_PUSH: 0})
        sock.sendall(conn.data_to_send())
        state = {"conn": conn, "frame_tail": b""}
        setattr(sock, "_wj_h2", state)
    return state


def _consume_header_frames(buf, stream_id, headers_done):
    """Walk as many complete HTTP/2 frames as `buf` holds, summing the payload
    lengths of HEADERS/CONTINUATION frames that belong to `stream_id`, and
    return (bytes_counted, tail, headers_done).

    Each frame starts with a 9-byte header: a 3-byte big-endian payload
    length, a 1-byte type, a 1-byte flags field, then a 4-byte stream id
    whose top bit is reserved and must be masked off (RFC 7540 §4.1). recv()
    returns whatever the kernel had buffered, not frame-aligned data, so a
    frame can be split across two reads, or even two fetch() calls on a
    reused connection; `tail` is the incomplete remainder to prepend to the
    next chunk rather than misparse now.

    Filtering by stream id is what actually keeps another stream's HEADERS
    from being counted as this response's cost — server push is disabled
    (see _connection_state) so a compliant server should never open one, but
    filtering does not depend on the server's cooperation the way disabling
    push does. `headers_done` becomes True the first time a DATA frame for
    our stream is seen, so a trailer HEADERS block that can follow the body
    is not folded into a count that stands in for the initial response
    header list alone — the same list _decoded_header_size() covers.
    """
    total = 0
    i = 0
    while i + 9 <= len(buf):
        length = int.from_bytes(buf[i:i + 3], "big")
        frame_type = buf[i + 3]
        if i + 9 + length > len(buf):
            break
        frame_stream_id = int.from_bytes(buf[i + 5:i + 9], "big") & 0x7fffffff
        if frame_stream_id == stream_id:
            if frame_type == _DATA_FRAME_TYPE:
                headers_done = True
            elif frame_type in _HEADER_FRAME_TYPES and not headers_done:
                total += length
        i += 9 + length
    return total, buf[i:], headers_done


def _decoded_header_size(headers):
    """Bytes these headers would occupy uncompressed, as HTTP/1.1 would send
    them: "name: value\\r\\n" per header. This is the real comparison point
    HPACK is measured against — not a guess, the cost of the same, already-
    decoded header list under the other protocol's framing.

    The two numbers in header_bytes do not cover identical sets: `wire`
    (see _consume_header_frames) counts the compressed :status pseudo-header
    along with the real ones, because it cannot be separated from the HEADERS
    frame bytes that carried it, while `decoded` here counts only the real
    headers below — HTTP/1.1's status line is a different shape with no
    comparable per-header byte cost. Both numbers are real measurements of
    what they each describe; they are just not describing exactly the same
    set of bytes.
    """
    return sum(len(name) + 2 + len(value) + 2 for name, value in headers)


def parse_response(raw_headers, body=b""):
    """The h2 counterpart to h1.parse_response(): turn h2's already-framed
    event data — decoded header tuples from a ResponseReceived event, plus
    whatever body bytes DataReceived accumulated — into the same
    {protocol, status, reason, headers, body} shape h1.parse_response()
    produces from a raw byte blob. h2 has already done the framing (HPACK,
    the header/data split, stream demultiplexing) by the time these values
    exist, so unlike h1 there is no "\\r\\n\\r\\n" to split on here; this is
    the interpretation step, matching h1's role in the transport interface.
    """
    decoded = _decode_headers(raw_headers)
    return {"protocol": "HTTP/2", "status": decoded["status"],
            "reason": None,          # HTTP/2 has no reason phrase; absent, not ""
            "headers": decoded["headers"], "body": bytes(body)}


def fetcher(ctx):
    if not ctx.caps.has_lib("h2"):
        raise TransportUnavailable("the h2 library is not installed")

    import h2.events
    import h2.exceptions

    def fetch(url, sock):
        opened_here = sock is None
        if opened_here:
            # Matches h1.fetcher(): each redirect hop needs its own
            # connection, since the prior hop's socket belongs to the
            # TLS/TCP collector (first hop) or was already closed by this
            # same finally block (a later hop).
            sock = open_connection(urlsplit(url), ctx)
        try:
            state = _connection_state(sock)
            conn = state["conn"]

            request = build_request(url)
            request_headers = [(":method", request["method"]),
                               (":path", request["target"]),
                               (":scheme", "https"),
                               (":authority", dict(request["headers"]).get("Host", ""))]
            # "Host" becomes :authority above. "Connection" is an HTTP/1-only
            # concept (this multiplexed connection stays open regardless);
            # the h2 library silently strips it from what it actually
            # encodes if it is sent, so it is left out here rather than kept
            # in a "request" the response later claims was sent verbatim.
            request_headers += [(k.lower(), v) for k, v in request["headers"]
                                if k.lower() not in ("host", "connection")]

            stream_id = conn.get_next_available_stream_id()
            sock.settimeout(ctx.budget_for(ctx.timeout))
            started = time.perf_counter()

            conn.send_headers(stream_id, request_headers, end_stream=True)
            sock.sendall(conn.data_to_send())

            response_headers = []
            headers_seen = False
            headers_done = False
            body = bytearray()
            header_wire_bytes = 0
            frame_tail = state["frame_tail"]
            ttfb = None
            done = False

            while not done:
                try:
                    data = sock.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                counted, frame_tail, headers_done = _consume_header_frames(
                    frame_tail + data, stream_id, headers_done)
                header_wire_bytes += counted
                try:
                    events = conn.receive_data(data)
                except h2.exceptions.ProtocolError:
                    # A malformed or hostile peer, not a socket-level failure
                    # -- treat it the same as the OSError above: stop reading
                    # and let whatever was measured so far (possibly
                    # nothing) stand, so the caller sees an absent response
                    # rather than a traceback.
                    break
                for event in events:
                    if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
                        if ttfb is None:
                            ttfb = round((time.perf_counter() - started) * 1000, 1)
                        response_headers = list(event.headers)
                        headers_seen = True
                    elif isinstance(event, h2.events.DataReceived) and event.stream_id == stream_id:
                        body += event.data
                        conn.acknowledge_received_data(len(event.data), event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded) and event.stream_id == stream_id:
                        done = True
                pending = conn.data_to_send()
                if pending:
                    sock.sendall(pending)

            state["frame_tail"] = frame_tail

            parsed = parse_response(response_headers, body)
            parsed["request"] = {"method": request["method"], "target": request["target"],
                                 "http_version": "HTTP/2", "headers": request_headers}
            parsed["ttfb_ms"] = ttfb
            parsed["total_ms"] = round((time.perf_counter() - started) * 1000, 1)
            parsed["wire_bytes"] = len(body)
            parsed["stream_id"] = stream_id
            # A response never arrived (timeout, reset, malformed peer): no
            # header bytes were measured, so this is absent, not a measured
            # zero -- ttfb_ms already follows this same rule.
            parsed["header_bytes"] = ({"wire": header_wire_bytes,
                                       "decoded": _decoded_header_size(parsed["headers"])}
                                      if headers_seen else None)
            return parsed
        finally:
            # Only close what this call opened. The first hop's socket
            # belongs to the TLS/TCP collector and is closed later by the
            # orchestrator.
            if opened_here:
                sock.close()

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
