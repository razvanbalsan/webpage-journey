import h2.config
import h2.connection
import h2.events
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

    def __init__(self, response_headers, body=b"", trailing_close=True, chunk_size=None):
        self.server = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False))
        self.server.initiate_connection()
        self._response_headers = response_headers
        self._body = body
        self._trailing_close = trailing_close
        self._outbox = bytearray(self.server.data_to_send())
        self.closed = False
        # When set, recv() hands back this many bytes per call instead of the
        # whole outbox at once -- used to prove frame parsing survives a real
        # TCP stream splitting a HEADERS frame across multiple reads.
        self.chunk_size = chunk_size

    def settimeout(self, _seconds):
        pass

    def sendall(self, data):
        events = self.server.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.server.send_headers(event.stream_id, self._response_headers)
                self.server.send_data(event.stream_id, self._body, end_stream=True)
        self._outbox += self.server.data_to_send()

    def recv(self, _size):
        if not self._outbox:
            return b"" if self._trailing_close else b""
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
