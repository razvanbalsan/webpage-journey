import copy
import json

from wj import redact, schema


def sample_trace():
    return {
        "schema": "webpage-journey-trace/1",
        "redacted": False,
        "local": {"observed": True, "interface": "en0",
                  "local_ip": "192.168.1.23", "local_mac": "aa:bb:cc:dd:ee:ff",
                  "gateway_ip": "192.168.1.1", "gateway_mac": "11:22:33:44:55:66",
                  "public_ip": "81.180.20.7", "mtu": 1500,
                  "dhcp": {"server": "192.168.1.1", "lease_seconds": 86400,
                           "dns": ["192.168.1.1"]}},
        "dns": {"observed": True,
                "records": {"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": []},
                "records_failed": [],
                "resolver": {"servers": ["192.168.1.1", "1.1.1.1"], "source": "scutil"},
                "dnssec": "secure", "delegation": [], "alpn_advertised": [], "ech": False,
                "timing_ms": {"cold": 12.0, "warm": 1.0}},
        "tcp": {"observed": True, "local": {"ip": "192.168.1.23", "port": 54213},
                "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443}},
        "tls": {"observed": True,
                "chain": [{"subject_cn": "example.com", "days_left": 80}],
                "legacy_versions_accepted": [], "caa_match": True},
        "http": {"observed": True, "hops": [], "final": {"status": 200},
                 "security": {"grade": "A", "missing": [],
                              "cookies": [{"name": "s", "secure": True,
                                           "httponly": True, "samesite": "Lax"}]}},
        "path": {"observed": True, "hops": [
            {"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan", "rtt_ms": 1.2},
            {"ttl": 2, "ip": "93.184.216.34", "rdns": None, "rtt_ms": 12.0}]},
    }


def test_redacts_local_identifiers():
    out = redact.redact_trace(sample_trace())
    assert out["local"]["local_mac"] == redact.REDACTED
    assert out["local"]["local_ip"] == redact.REDACTED
    assert out["local"]["gateway_mac"] == redact.REDACTED
    assert out["local"]["public_ip"] == redact.REDACTED
    assert out["tcp"]["local"]["ip"] == redact.REDACTED


def test_keeps_facts_that_are_not_identifying():
    out = redact.redact_trace(sample_trace())
    assert out["local"]["interface"] == "en0"
    assert out["local"]["mtu"] == 1500
    assert out["local"]["dhcp"]["lease_seconds"] == 86400
    assert out["tcp"]["local"]["port"] == 54213
    assert out["tcp"]["chosen"]["ip"] == "93.184.216.34"


def test_redacts_private_hops_but_keeps_public_ones():
    out = redact.redact_trace(sample_trace())
    assert out["path"]["hops"][0]["ip"] == redact.REDACTED
    assert out["path"]["hops"][0]["rdns"] == redact.REDACTED
    assert out["path"]["hops"][1]["ip"] == "93.184.216.34"


def test_marks_the_document_redacted_and_does_not_mutate_the_original():
    original = sample_trace()
    snapshot = copy.deepcopy(original)
    out = redact.redact_trace(original)
    assert out["redacted"] is True
    assert original == snapshot


def test_redacting_an_unobserved_section_is_a_no_op():
    trace = {"local": {"observed": False, "why_not": "no route tool"},
             "tcp": {"observed": False, "why_not": "x"},
             "path": {"observed": False, "why_not": "x"}, "redacted": False}
    out = redact.redact_trace(trace)
    assert out["local"] == {"observed": False, "why_not": "no route tool"}


def test_redacts_a_private_dns_resolver_but_keeps_a_public_one():
    out = redact.redact_trace(sample_trace())
    assert out["dns"]["resolver"]["servers"][0] == redact.REDACTED
    assert out["dns"]["resolver"]["servers"][1] == "1.1.1.1"


def test_no_private_identifier_survives_serialisation():
    out = redact.redact_trace(sample_trace())
    blob = json.dumps(out)

    for leaked in ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                   "192.168.1.23", "192.168.1.1", "81.180.20.7"):
        assert leaked not in blob, leaked

    # Public facts are measurements worth keeping.
    assert "93.184.216.34" in blob
    assert "1.1.1.1" in blob


def test_osi_narrative_does_not_republish_what_was_just_redacted():
    # The real pipeline builds trace["osi"] from local/tcp/dns/path *before*
    # redaction runs (wj.run.orchestrate), baking raw facts into free-text
    # strings. A regression here previously let the MAC/IP addresses leak
    # back out through osi.l2/l3 even though the structured sections and
    # "redacted: true" said otherwise.
    trace = sample_trace()
    trace["target"] = {"input": "https://example.com/", "host": "example.com",
                        "scheme": "https", "port": 443, "path": "/"}
    trace["osi"] = schema.build_osi(trace)
    assert "aa:bb:cc:dd:ee:ff" in json.dumps(trace["osi"])  # sanity: fixture exercises the leak path

    out = redact.redact_trace(trace)
    blob = json.dumps(out["osi"])

    for leaked in ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                   "192.168.1.23", "192.168.1.1", "81.180.20.7"):
        assert leaked not in blob, leaked

    assert redact.REDACTED in blob
    # Public facts are still worth keeping in the narrative.
    assert "93.184.216.34" in blob


def test_a_malformed_hop_address_is_redacted_rather_than_published():
    trace = sample_trace()
    trace["path"]["hops"].append(
        {"ttl": 5, "ip": "12:34:56:78", "rdns": "weird-hop.example", "rtt_ms": 9.9})
    out = redact.redact_trace(trace)
    assert out["path"]["hops"][-1]["ip"] == redact.REDACTED
    assert "12:34:56:78" not in json.dumps(out)
