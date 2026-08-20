import socket

import pytest

from wj import capabilities
from wj.collect import tcp as tcp_collect
from wj.context import Context


@pytest.fixture
def listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    yield server.getsockname()[1]
    server.close()


def make_ctx(port):
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="localhost", scheme="https", port=port, path="/",
                  timeout=3.0, deadline=1e9, caps=caps, results={})
    ctx.results["dns"] = {"observed": True,
                          "records": {"A": [{"data": "127.0.0.1", "ttl": 60}], "AAAA": []}}
    return ctx


def test_candidates_put_ipv6_first():
    section = {"observed": True, "records": {
        "A": [{"data": "93.184.216.34", "ttl": 300}],
        "AAAA": [{"data": "2606:2800::1", "ttl": 300}]}}
    assert tcp_collect.candidates_from_dns(section) == [
        {"ip": "2606:2800::1", "family": "ipv6"},
        {"ip": "93.184.216.34", "family": "ipv4"},
    ]


def test_candidates_from_unobserved_dns_is_empty():
    assert tcp_collect.candidates_from_dns({"observed": False, "why_not": "x"}) == []


def test_connect_one_succeeds_against_a_real_listener(listening_port):
    result = tcp_collect.connect_one("127.0.0.1", "ipv4", listening_port, timeout=2.0)
    assert result["error"] is None
    assert result["connect_ms"] >= 0
    assert result["socket"] is not None
    result["socket"].close()


def test_connect_one_records_refusal_without_raising():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()

    result = tcp_collect.connect_one("127.0.0.1", "ipv4", port, timeout=2.0)
    assert result["socket"] is None
    assert result["error"]


def test_collect_reports_local_port_and_winner(listening_port):
    section = tcp_collect.collect(make_ctx(listening_port))
    assert section["observed"] is True
    assert section["chosen"]["ip"] == "127.0.0.1"
    assert section["winner_family"] == "ipv4"
    assert section["local"]["port"] > 0
    assert len(section["candidates"]) == 1
    assert section["candidates"][0]["error"] is None
    section["_socket"].close()


def test_collect_without_addresses_is_unobserved():
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=1.0, deadline=1e9, caps=caps, results={})
    ctx.results["dns"] = {"observed": False, "why_not": "did not resolve"}
    section = tcp_collect.collect(ctx)
    assert section["observed"] is False
    assert "no resolved address" in section["why_not"]


def test_candidates_carry_no_socket_key_in_exportable_output(listening_port):
    section = tcp_collect.collect(make_ctx(listening_port))
    for candidate in section["candidates"]:
        assert "socket" not in candidate
    section["_socket"].close()


def test_plausible_rtt_accepts_a_real_measurement():
    assert tcp_collect.plausible_rtt_ms(12.4) == 12.4
    assert tcp_collect.plausible_rtt_ms(0.0) == 0.0


def test_plausible_rtt_rejects_a_misread_struct_field():
    # 200000 is what a send-buffer byte counter looked like when it was
    # mistaken for a smoothed RTT.
    assert tcp_collect.plausible_rtt_ms(200000) is None
    assert tcp_collect.plausible_rtt_ms(-1) is None
    assert tcp_collect.plausible_rtt_ms(None) is None
