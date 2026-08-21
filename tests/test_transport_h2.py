import h2.config
import h2.connection
import h2.events
import h2.exceptions
import pytest

from wj import capabilities
from wj.context import Context
from wj.transport import h2 as h2_transport


class FakeTLSSocket:
    """A socket-shaped object wired to a real server-side h2 connection.

    Whatever the transport sends is fed to the server; whatever the server
    produces is handed back on recv(). No network, but real framing on both
    sides — the client is tested against an actual HTTP/2 implementation.
    """

    def __init__(self, response_headers, body=b"", chunk_size=None, ping_after_response=False):
        self.server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False))
        self.server.initiate_connection()
        self._response_headers = response_headers
        self._body = body
        self._outbox = bytearray(self.server.data_to_send())
        self.closed = False
        # When set, recv() hands back this many bytes per call instead of the
        # whole outbox at once -- used to prove frame parsing survives a real
        # TCP stream splitting a HEADERS frame across multiple reads.
        self.chunk_size = chunk_size
        # When set, the server sends an unprompted connection-level PING
        # right after the response -- used to prove the leftover raw-byte
        # tail from one fetch() call is not lost before the next fetch()
        # call on the same (reused) connection.
        self.ping_after_response = ping_after_response

    def settimeout(self, _seconds):
        pass

    def sendall(self, data):
        events = self.server.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.server.send_headers(event.stream_id, self._response_headers)
                self.server.send_data(event.stream_id, self._body, end_stream=True)
                if self.ping_after_response:
                    self.server.ping(b"12345678")
        self._outbox += self.server.data_to_send()

    def recv(self, _size):
        if not self._outbox:
            return b""
        take = self.chunk_size if self.chunk_size else len(self._outbox)
        chunk = bytes(self._outbox[:take])
        self._outbox = self._outbox[take:]
        return chunk

    def close(self):
        self.closed = True


def make_ctx():
    caps = capabilities.Capabilities(libs={"h2": True}, tools={},
                                     privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=5.0, deadline=1e9, caps=caps, results={})


def test_fetch_returns_the_normalised_shape_every_transport_returns():
    sock = FakeTLSSocket([(":status", "200"), ("content-type", "text/html")],
                         body=b"<html></html>")
    fetch = h2_transport.fetcher(make_ctx())
    response = fetch("https://example.com/", sock)

    assert response["protocol"] == "HTTP/2"
    assert response["status"] == 200
    assert ("content-type", "text/html") in response["headers"]
    assert response["body"] == b"<html></html>"
    assert response["ttfb_ms"] is not None
    assert response["wire_bytes"] == len(b"<html></html>")


def test_pseudo_headers_do_not_leak_into_the_header_list():
    # :status is how h2 carries the status code. It is not a header a reader
    # should see listed alongside content-type, and it must not reach the
    # security grader or the cookie parser.
    sock = FakeTLSSocket([(":status", "301"), ("location", "https://www.example.com/")])
    response = h2_transport.fetcher(make_ctx())("https://example.com/", sock)

    assert response["status"] == 301
    assert all(not k.startswith(":") for k, _ in response["headers"])


def test_reports_header_compression_sizes():
    # HPACK is the measurement HTTP/1.1 cannot produce: the same headers cost
    # fewer bytes on the wire. Both numbers here are genuinely measured: wire
    # is the summed payload length of the HEADERS/CONTINUATION frames that
    # actually crossed the fake socket; decoded is the HTTP/1.1-equivalent
    # cost of the same, already-decoded header list.
    sock = FakeTLSSocket([(":status", "200"), ("content-type", "text/html"),
                          ("server", "example"), ("x-padding", "z" * 200)])
    response = h2_transport.fetcher(make_ctx())("https://example.com/", sock)

    sizes = response["header_bytes"]
    assert sizes["wire"] > 0
    assert sizes["decoded"] > sizes["wire"]


def test_header_compression_size_survives_a_frame_split_across_recv_calls():
    # A real TCP stream is not frame-aligned: the HEADERS frame carrying these
    # response headers can straddle two recv() calls. Force that by handing
    # recv() back 5 bytes at a time -- far smaller than one frame -- and check
    # the wire byte count still matches what a single, unfragmented read of
    # the same bytes produces.
    headers = [(":status", "200"), ("content-type", "text/html"),
               ("server", "example"), ("x-padding", "z" * 200)]
    whole = h2_transport.fetcher(make_ctx())(
        "https://example.com/", FakeTLSSocket(headers))
    fragmented = h2_transport.fetcher(make_ctx())(
        "https://example.com/", FakeTLSSocket(headers, chunk_size=5))

    assert fragmented["header_bytes"] == whole["header_bytes"]
    assert fragmented["headers"] == whole["headers"]
    assert fragmented["header_bytes"]["wire"] > 0


def test_a_reused_connections_leftover_frame_bytes_survive_into_the_next_fetch():
    # A server can send something unprompted right after a response -- a
    # keepalive PING is a realistic example -- and recv() boundaries do not
    # respect frame edges. If the leftover, not-yet-parsed tail of bytes from
    # fetch #1 is discarded instead of carried into fetch #2 (on the same,
    # reused connection), fetch #2 starts frame-parsing at the wrong byte
    # offset and silently miscounts header_bytes["wire"] for a completely
    # unrelated reason -- not because HPACK compressed better, which is the
    # only reason it's expected to shrink on a reused connection.
    headers = [(":status", "200"), ("content-type", "text/html")]

    baseline_sock = FakeTLSSocket(headers, body=b"hi")
    baseline_fetch = h2_transport.fetcher(make_ctx())
    baseline_fetch("https://example.com/", baseline_sock)
    baseline_second = baseline_fetch("https://example.com/next", baseline_sock)

    sock = FakeTLSSocket(headers, body=b"hi", chunk_size=5, ping_after_response=True)
    fetch = h2_transport.fetcher(make_ctx())
    fetch("https://example.com/", sock)
    second = fetch("https://example.com/next", sock)

    assert second["status"] == 200
    # Same headers, same reused connection -> HPACK's dynamic table should
    # compress this second response exactly as well as it does in the
    # unfragmented, no-PING baseline. Any other value means the frame tail
    # was dropped and the byte stream misaligned.
    assert second["header_bytes"] == baseline_second["header_bytes"]


def test_pushed_streams_headers_are_not_counted_as_this_streams_wire_bytes():
    # _consume_header_frames() must not attribute another stream's HEADERS
    # bytes to this response's HPACK cost. Simulate a server that sent a
    # pushed stream's response HEADERS (stream id 2) alongside our own
    # response (stream id 1) -- the defence this asserts is the stream-id
    # filter itself, independent of whether server push is also disabled at
    # the protocol level (covered separately below).
    pushed_frame = bytes([0, 0, 50, 1, 4, 0, 0, 0, 2]) + b"x" * 50
    our_headers_frame = bytes([0, 0, 20, 1, 4, 0, 0, 0, 1]) + b"y" * 20

    counted, tail, headers_done = h2_transport._consume_header_frames(
        pushed_frame + our_headers_frame, stream_id=1, headers_done=False)

    assert counted == 20
    assert tail == b""
    assert headers_done is False


def test_server_push_is_disabled_at_the_protocol_level():
    # The fetcher tells the server not to push (ENABLE_PUSH: 0) as part of
    # establishing the connection. A compliant h2 implementation -- the same
    # one every other test in this file drives -- refuses to push once it
    # has processed that setting.
    sock = FakeTLSSocket([(":status", "200")])
    h2_transport.fetcher(make_ctx())("https://example.com/", sock)

    with pytest.raises(h2.exceptions.ProtocolError):
        sock.server.push_stream(
            stream_id=1, promised_stream_id=2,
            request_headers=[(":method", "GET"), (":authority", "example.com"),
                             (":scheme", "https"), (":path", "/style.css")])


def test_fetch_opens_and_closes_its_own_connection_when_given_none(monkeypatch):
    # Matches h1.fetcher(): wj/collect/http.py sets sock=None on every
    # redirect hop and expects the transport to open its own connection for
    # that hop, then close it -- the first hop's socket belongs to the
    # TLS/TCP collector, but later hops' sockets belong to this call.
    sock = FakeTLSSocket([(":status", "200")], body=b"redirected")
    opened = {}

    def fake_open_connection(split, ctx):
        opened["split"] = split
        opened["ctx"] = ctx
        return sock

    monkeypatch.setattr(h2_transport, "open_connection", fake_open_connection)

    response = h2_transport.fetcher(make_ctx())("https://example.com/next", None)

    assert response["status"] == 200
    assert response["body"] == b"redirected"
    assert opened["split"].hostname == "example.com"
    assert sock.closed is True


def test_a_malformed_response_is_reported_absent_not_raised():
    # conn.receive_data() can raise h2.exceptions.ProtocolError on a
    # malformed or hostile peer. That must surface as an absent response
    # (status is None, same as a timeout with nothing received), not an
    # exception that aborts the whole run.
    #
    # A HEADERS frame (type 1) is only valid with a nonzero stream id; this
    # one -- length 0, END_HEADERS set, stream id 0 -- is rejected by h2 on
    # the very first byte it can act on, unlike arbitrary noise, which h2
    # buffers for a long time hoping more bytes complete a plausible frame.
    invalid_frame = bytes([0, 0, 0, 1, 0x4, 0, 0, 0, 0])

    class BrokenSocket:
        def settimeout(self, _seconds):
            pass

        def sendall(self, _data):
            pass

        def recv(self, _size):
            return invalid_frame

        def close(self):
            pass

    response = h2_transport.fetcher(make_ctx())("https://example.com/", BrokenSocket())
    assert response["status"] is None
    assert response["header_bytes"] is None


def test_header_bytes_is_absent_when_no_response_arrives():
    class SilentSocket:
        def settimeout(self, _seconds):
            pass

        def sendall(self, _data):
            pass

        def recv(self, _size):
            return b""

        def close(self):
            pass

    response = h2_transport.fetcher(make_ctx())("https://example.com/", SilentSocket())
    assert response["status"] is None
    assert response["header_bytes"] is None
    assert response["ttfb_ms"] is None


def test_response_dict_carries_the_request_that_was_actually_sent():
    # h1.build_request()'s own docstring says this exists so the exact set
    # that went out can be recorded, not reconstructed by eye -- the h1
    # shape (Connection: close, no pseudo-headers) is not what h2 sent.
    sock = FakeTLSSocket([(":status", "200")])
    response = h2_transport.fetcher(make_ctx())("https://example.com/", sock)

    sent = dict(response["request"]["headers"])
    assert sent[":method"] == "GET"
    assert sent[":path"] == "/"
    assert sent[":scheme"] == "https"
    assert sent[":authority"] == "example.com"
    assert "connection" not in sent


def test_reports_the_stream_id():
    sock = FakeTLSSocket([(":status", "200")])
    response = h2_transport.fetcher(make_ctx())("https://example.com/", sock)
    assert response["stream_id"] == 1


def test_a_reused_connection_gets_the_next_odd_stream_id():
    sock = FakeTLSSocket([(":status", "200")])
    fetch = h2_transport.fetcher(make_ctx())
    first = fetch("https://example.com/", sock)
    second = fetch("https://example.com/next", sock)
    assert first["stream_id"] == 1
    assert second["stream_id"] == 3


def test_missing_h2_library_is_reported_not_crashed():
    caps = capabilities.Capabilities(libs={"h2": False}, tools={},
                                     privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    with pytest.raises(h2_transport.TransportUnavailable):
        h2_transport.fetcher(ctx)
