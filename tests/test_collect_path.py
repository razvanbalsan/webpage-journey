from pathlib import Path

import pytest

from wj import capabilities
from wj.collect import path as path_collect
from wj.context import Context

FIXTURES = Path(__file__).parent / "fixtures"


def make_ctx(has_traceroute=True, no_path=False):
    caps = capabilities.Capabilities(
        libs={"dns": True},
        tools={"traceroute": "/usr/sbin/traceroute" if has_traceroute else None},
        privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, no_path=no_path, results={})
    ctx.results["tcp"] = {"observed": True,
                          "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443}}
    return ctx


def test_parse_traceroute_darwin_reads_every_hop():
    hops = path_collect.parse_traceroute((FIXTURES / "traceroute_darwin.txt").read_text())
    assert len(hops) == 5
    assert hops[0] == {"ttl": 1, "ip": "192.168.1.1",
                       "rdns": "router.lan", "rtt_ms": 1.234}
    assert hops[4]["ip"] == "93.184.216.34"


def test_parse_traceroute_marks_unresponsive_hops():
    hops = path_collect.parse_traceroute((FIXTURES / "traceroute_darwin.txt").read_text())
    assert hops[1] == {"ttl": 2, "ip": None, "rdns": None, "rtt_ms": None}


def test_parse_traceroute_linux_gateway_alias():
    hops = path_collect.parse_traceroute((FIXTURES / "traceroute_linux.txt").read_text())
    assert hops[0]["rdns"] == "_gateway"
    assert hops[0]["ip"] == "192.168.1.1"
    assert len(hops) == 4


def test_parse_traceroute_ignores_the_banner_line():
    hops = path_collect.parse_traceroute("traceroute to example.com (1.2.3.4), 64 hops max\n")
    assert hops == []


def test_cymru_name_reverses_the_octets():
    assert path_collect.cymru_name("93.184.216.34") == "34.216.184.93.origin.asn.cymru.com"


def test_parse_cymru_txt_reads_asn_and_prefix():
    out = path_collect.parse_cymru_txt("15133 | 93.184.216.0/24 | US | arin | 2008-06-02")
    assert out == {"asn": 15133, "prefix": "93.184.216.0/24", "country": "US"}


def test_parse_cymru_txt_handles_multi_origin_answers():
    out = path_collect.parse_cymru_txt("3356 1299 | 203.0.113.0/24 | EU | ripencc | 2010-01-01")
    assert out["asn"] == 3356


def test_asn_path_collapses_repeats_and_drops_unknowns():
    hops = [{"asn": None}, {"asn": 8708}, {"asn": 8708}, {"asn": 1299}, {"asn": None}]
    assert path_collect.asn_path(hops) == [8708, 1299]


def test_collect_annotates_hops_with_asn():
    ctx = make_ctx()

    def fake_run(cmd, timeout):
        return (FIXTURES / "traceroute_darwin.txt").read_text()

    def fake_asn(ip):
        return {"asn": 13335, "prefix": "93.184.216.0/24", "country": "US"} \
            if ip == "93.184.216.34" else {"asn": None, "prefix": None, "country": None}

    section = path_collect.collect(ctx, run=fake_run, asn_lookup=fake_asn)
    assert section["observed"] is True
    assert section["source"] == "traceroute"
    assert section["hops"][4]["asn"] == 13335
    assert section["asn_path"] == [13335]


def test_collect_skipped_by_flag():
    section = path_collect.collect(make_ctx(no_path=True))
    assert section == {"observed": False, "why_not": "skipped with --no-path"}


def test_collect_without_traceroute_explains_itself():
    section = path_collect.collect(make_ctx(has_traceroute=False))
    assert section["observed"] is False
    assert "traceroute not on PATH" in section["why_not"]
