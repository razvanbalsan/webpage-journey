"""Source-level guards on webpage-journey.html.

The page is a single self-contained file with no build step and no JS test
runner in this project (and no new dependency may be added for one), so these
assert on its source text. That is enough for the class of defect they exist
to catch: a row label, and whether a measured field is read at all.
"""

import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parent.parent / "webpage-journey.html"


@pytest.fixture(scope="module")
def page():
    return PAGE.read_text()


def test_only_one_row_in_the_whole_page_is_labelled_negotiated(page):
    # I4: the Request step labelled http.final.protocol "Negotiated protocol"
    # while the TLS step showed negotiation.chosen as "Negotiated". On a chain
    # whose origin negotiates h2 and then redirects to an http:// URL (the
    # cleartext fallback in wj/collect/http.py), the TLS step read
    # "Negotiated: h2" and the Request step "Negotiated protocol: HTTP/1.1" --
    # both badged measured, flatly contradicting each other.
    labels = re.findall(r'\["(Negotiated[^"]*)"', page)
    assert labels == ["Negotiated"], labels


def test_the_request_step_labels_the_protocol_as_the_one_actually_used(page):
    # Wrong in kind even with no cleartext hop: final.protocol is the protocol
    # the FINAL RESPONSE was served over, not what ALPN selected.
    assert '["Protocol used", fact(f.protocol, "measured")]' in page
    assert '["Negotiated protocol"' not in page


def test_the_request_step_reads_the_measured_stream_id(page):
    # I6: stream_id is set by wj/transport/h2.py on every response and copied
    # onto every redirect hop, but reached no reader on the final response --
    # a redirect-free HTTP/2 trace recorded no stream id anywhere at all. The
    # Request step already teaches multiplexing in prose, so this is where it
    # belongs.
    assert "f.stream_id != null" in page
    assert '"Stream"' in page or '["Stream"' in page


def test_the_page_does_not_carry_the_retired_alpn_claim(page):
    # The claim this branch falsified, corrected here first and then in
    # wj/render.py -- guarded on both sides so neither can drift back alone.
    assert "deliberately not what this tool negotiated" not in page
