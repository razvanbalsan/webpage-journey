from wj.transport import h1


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
