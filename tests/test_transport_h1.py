from wj import capabilities
from wj.context import Context
from wj.transport import h1


class FakeSocket:
    """A socket whose recv() hands back pre-split pieces, one per call, then an
    empty bytes to signal the peer closed the connection -- exactly what a real
    HTTP/1.1 "Connection: close" response looks like to fetcher()'s read loop.
    """

    def __init__(self, pieces):
        self._pieces = list(pieces)
        self.sent = None

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.sent = data

    def recv(self, bufsize):
        if self._pieces:
            return self._pieces.pop(0)
        return b""

    def close(self):
        pass


def test_fetch_returns_a_dechunked_body_so_decode_body_never_sees_framing():
    # Transfer-encoding is framing and belongs to h1. decode_body must not have
    # to know about it, because HTTP/2 has no such header.
    payload = b"hello world"
    chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    raw = (b"HTTP/1.1 200 OK\r\n"
           b"Transfer-Encoding: chunked\r\n"
           b"\r\n") + chunked

    parsed = h1.parse_response(raw)
    assert parsed["body"] == payload
    assert h1.header_value_absent_after_dechunk(parsed["headers"]) is True


def test_parse_response_leaves_an_unchunked_body_alone():
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nBODYBYTES"
    assert h1.parse_response(raw)["body"] == b"BODYBYTES"


def test_dechunk_handles_chunk_data_containing_crlf():
    chunked = b"7\r\na\r\nb\r\nc\r\n0\r\n\r\n"
    assert h1.dechunk(chunked) == b"a\r\nb\r\nc"


def test_fetcher_dechunks_a_response_fragmented_across_recv_calls():
    # The golden fixtures never contain a chunked body (they are hand-built
    # dicts, not real wire bytes), so byte-identical fixtures prove nothing
    # about this path. This test drives the real read loop in fetcher() --
    # the same recv() loop a live socket would feed -- with recv() returning
    # the response in pieces whose boundaries deliberately land mid chunk-
    # size-line, mid chunk-data, and mid CRLF, which is what fragmentation
    # over a real TCP stream actually looks like.
    #
    # Response headers + one blank line, whole in the first piece:
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    # Chunked body for "hello world", split as:
    #   "5" | "\r\nhel"   -- splits the "5\r\n" chunk-size line mid-line
    #        "hel" | "lo\r\n" -- splits "hello" mid chunk-data
    #   "6\r\n"
    #   " world\r" | "\n0\r\n\r" | "\n" -- splits two CRLFs mid-sequence
    pieces = [head, b"5", b"\r\nhel", b"lo\r\n", b"6\r\n",
              b" world\r", b"\n0\r\n\r", b"\n"]
    assert b"".join(pieces) == head + b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    sock = FakeSocket(pieces)

    fetch = h1.fetcher(ctx)
    response = fetch("https://example.com/", sock)

    assert response["body"] == b"hello world"
    assert h1.header_value_absent_after_dechunk(response["headers"]) is True
    assert response["wire_bytes"] == len(b"hello world")
