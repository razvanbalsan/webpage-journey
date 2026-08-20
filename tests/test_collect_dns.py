from pathlib import Path

import pytest

from wj import capabilities, schema
from wj.collect import dns as dns_collect
from wj.context import Context

FIXTURES = Path(__file__).parent / "fixtures"


def make_ctx(has_dnspython=True):
    caps = capabilities.Capabilities(
        libs={"dns": has_dnspython}, tools={}, privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=8.0, deadline=1e9, caps=caps, results={})


def test_parse_https_rr_extracts_alpn_and_ech():
    out = dns_collect.parse_https_rr('1 . alpn="h3,h2" ipv4hint=104.16.1.1 ech="AEX+DQ"')
    assert out == {"alpn": ["h3", "h2"], "ech": True}


def test_parse_https_rr_without_alpn_or_ech():
    assert dns_collect.parse_https_rr("1 . ipv4hint=104.16.1.1") == {"alpn": [], "ech": False}


def test_parse_resolv_conf_returns_nameservers_in_order():
    text = (FIXTURES / "resolv.conf").read_text()
    assert dns_collect.parse_resolv_conf(text) == ["192.168.1.1", "1.1.1.1"]


def test_parse_scutil_dns_deduplicates_nameservers():
    text = (FIXTURES / "scutil_dns.txt").read_text()
    assert dns_collect.parse_scutil_dns(text) == ["192.168.1.1", "1.1.1.1"]


def test_classify_dnssec():
    assert dns_collect.classify_dnssec(True, True) == "secure"
    assert dns_collect.classify_dnssec(False, True) == "insecure"
    assert dns_collect.classify_dnssec(None, True) == "unknown"


def test_walk_delegation_follows_root_to_authoritative():
    responses = {
        ("198.41.0.4", "example.com", "NS"): {
            "answer": [], "authority": ["a.gtld-servers.net"],
            "additional": {"a.gtld-servers.net": "192.5.6.30"}},
        ("192.5.6.30", "example.com", "NS"): {
            "answer": [], "authority": ["ns1.example.com"],
            "additional": {"ns1.example.com": "203.0.113.9"}},
        ("203.0.113.9", "example.com", "NS"): {
            "answer": ["ns1.example.com"], "authority": [], "additional": {}},
    }

    def query_at(server_ip, name, rtype):
        return responses[(server_ip, name, rtype)]

    walk = dns_collect.walk_delegation("example.com", query_at)
    assert [hop["level"] for hop in walk] == ["root", "tld", "authoritative"]
    assert walk[0]["referral"] == ["a.gtld-servers.net"]
    assert walk[2]["answer"] == ["ns1.example.com"]


def test_walk_delegation_stops_at_the_hop_limit():
    def loops(server_ip, name, rtype):
        return {"answer": [], "authority": ["ns.loop"], "additional": {"ns.loop": "203.0.113.1"}}

    walk = dns_collect.walk_delegation("example.com", loops)
    assert len(walk) <= 8


def test_collect_builds_records_with_ttls():
    answers = {
        "A": ([{"data": "93.184.216.34", "ttl": 300}], False),
        "AAAA": ([], False),
        "HTTPS": ([{"data": '1 . alpn="h3,h2"', "ttl": 60}], False),
    }

    def query(name, rtype):
        return answers.get(rtype, ([], False))

    section = dns_collect.collect(make_ctx(), query=query,
                                  delegation=lambda host: [], resolvers=lambda: ([], "none"))
    assert section["observed"] is True
    assert section["records"]["A"][0] == {"data": "93.184.216.34", "ttl": 300}
    assert section["records"]["AAAA"] == []
    assert section["alpn_advertised"] == ["h3", "h2"]
    assert section["dnssec"] == "insecure"
    assert set(section["records"]) == set(dns_collect.RECORD_TYPES)


def test_collect_marks_unobserved_when_nothing_resolves():
    def query(name, rtype):
        raise LookupError("NXDOMAIN")

    section = dns_collect.collect(make_ctx(), query=query,
                                  delegation=lambda host: [], resolvers=lambda: ([], "none"))
    assert section["observed"] is False
    assert "NXDOMAIN" in section["why_not"] or "did not resolve" in section["why_not"]


def test_collect_without_dnspython_says_so():
    section = dns_collect.collect(make_ctx(has_dnspython=False))
    assert section == {"observed": False, "why_not": "dnspython not installed"}


def test_collect_records_a_failed_query_separately_from_an_absent_record():
    def query(name, rtype):
        if rtype == "A":
            return [{"data": "93.184.216.34", "ttl": 300}], True
        if rtype == "CAA":
            return None, None          # query failed
        return [], False               # genuinely absent

    section = dns_collect.collect(make_ctx(), query=query,
                                  delegation=lambda host: [], resolvers=lambda: ([], "none"))
    assert section["records"]["CAA"] == []
    assert "CAA" in section["records_failed"]
    assert "MX" not in section["records_failed"]


def test_dnssec_verdict_comes_from_the_address_records_only():
    def query(name, rtype):
        if rtype == "A":
            return None, None          # the A query failed
        if rtype == "AAAA":
            return [{"data": "2606:2800::1", "ttl": 300}], False
        return [], True                # a later type reports AD — must not be used

    section = dns_collect.collect(make_ctx(), query=query,
                                  delegation=lambda host: [], resolvers=lambda: ([], "none"))
    assert section["dnssec"] == "insecure"
    assert section["records_failed"] == ["A"]
