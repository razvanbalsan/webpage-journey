import copy

from wj import redact


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
        "tcp": {"observed": True, "local": {"ip": "192.168.1.23", "port": 54213},
                "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443}},
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


def test_no_mac_or_private_ip_survives_in_serialized_output():
    import json

    trace = sample_trace()
    out = redact.redact_trace(trace)
    serialized = json.dumps(out)

    # MAC addresses from the input must not survive anywhere in the output.
    assert "aa:bb:cc:dd:ee:ff" not in serialized
    assert "11:22:33:44:55:66" not in serialized

    # Private IPs (local, gateway, and the private traceroute hop) must not survive.
    assert "192.168.1.23" not in serialized
    assert "192.168.1.1" not in serialized

    # The public IP is also treated as identifying and must be redacted.
    assert "81.180.20.7" not in serialized

    # But the public tcp/path IP is not identifying and must be preserved.
    assert "93.184.216.34" in serialized
