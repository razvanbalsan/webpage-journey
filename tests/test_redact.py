import copy
import ipaddress
import json
import re

from wj import findings, redact, schema


def sample_trace():
    """A real trace document, assembled the same way orchestrate() does it.

    Built from schema.new_trace(...) with every section populated, then run
    through the real findings.analyse() and schema.build_osi() -- not a
    hand-rolled dict with only the keys a given test happens to need. Three
    leaks have now slipped through this test module because its old fixture
    had no osi/notes/timings/capabilities keys at all, so a guard checking
    "does the redacted document still contain X" never even had X to find in
    the first place. test_the_leak_fixture_populates_every_section below
    makes an incomplete fixture fail loudly instead of silently.
    """
    trace = schema.new_trace(
        target={"input": "https://example.com/", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.1.0", generated_at="2026-08-20T09:00:00+00:00",
        capabilities={"privileged": False, "can_sudo": False, "tools": ["traceroute"],
                      "libs": {"dns": True, "cryptography": True, "h2": False},
                      "installed_during_run": []},
        redacted=False)

    trace["local"] = schema.observed(
        interface="en0", link="active", mtu=1500,
        local_ip="192.168.1.23", local_mac="aa:bb:cc:dd:ee:ff",
        gateway_ip="192.168.1.1", gateway_mac="11:22:33:44:55:66",
        dhcp={"server": "192.168.1.1", "lease_seconds": 86400, "dns": ["192.168.1.1"]},
        public_ip="81.180.20.7", nat=True)

    trace["dns"] = schema.observed(
        records={"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": [],
                 "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": [], "CAA": [], "HTTPS": []},
        records_failed=[],
        resolver={"servers": ["192.168.1.1", "1.1.1.1"], "source": "scutil"},
        dnssec="secure",
        delegation=[{"level": "root", "server": "198.41.0.4",
                    "referral": ["a.gtld-servers.net"], "answer": []}],
        alpn_advertised=[], ech=False,
        timing_ms={"cold": 12.0, "warm": 1.0, "survey_ms": 30.0})

    trace["tcp"] = schema.observed(
        candidates=[{"ip": "93.184.216.34", "family": "ipv4", "connect_ms": 12.4, "error": None}],
        chosen={"ip": "93.184.216.34", "family": "ipv4", "port": 443},
        winner_family="ipv4", local={"ip": "192.168.1.23", "port": 54213},
        kernel={"rtt_ms": 12.4, "mss": 1460, "retransmits": 0, "source": "TCP_INFO"})

    trace["tls"] = schema.observed(
        version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256", alpn="http/1.1",
        handshake_ms=38.2,
        chain=[{"subject_cn": "example.com", "issuer_cn": "R3", "issuer_org": "Let's Encrypt",
                "not_before": "2026-06-01T00:00:00+00:00", "not_after": "2026-08-30T00:00:00+00:00",
                "days_left": 80, "key": {"type": "EC", "bits": 256}, "sig_algo": "ecdsa-with-SHA256",
                "sans": ["example.com"], "scts": 2, "ocsp": [], "is_ca": False}],
        trust_root="ISRG Root X1", verified=True, caa_match=True,
        resumption={"tested": False}, legacy_versions_accepted=[])

    trace["http"] = schema.observed(
        hops=[], redirect_limit_reached=False,
        final={"url": "https://example.com/", "status": 200, "reason": "OK",
               "protocol": "HTTP/1.1", "headers": [["content-type", "text/html"]],
               "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000, "decoded_bytes": 61000,
               "encoding": "gzip", "ratio": 4.36, "content_type": "text/html"},
        cache={"state": None, "age": None, "header": None, "directives": None},
        cdn=None,
        security={"grade": "A", "present": {}, "missing": [],
                 "cookies": [{"name": "s", "secure": True, "httponly": True, "samesite": "Lax"}],
                 "scheme": "https"},
        conditional={"tested": False})

    trace["path"] = schema.observed(
        source="traceroute",
        hops=[{"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan",
              "rtt_ms": 1.2, "asn": None, "prefix": None},
             {"ttl": 2, "ip": "93.184.216.34", "rdns": None,
              "rtt_ms": 12.0, "asn": 15133, "prefix": "93.184.216.0/24"}],
        asn_path=[15133], path_mtu=None)

    trace["timings"] = {"waterfall": [{"label": "DNS", "start_ms": 0.0, "end_ms": 12.0}],
                        "total_ms": 109.0}

    # Real pipeline order (wj.run.orchestrate): analyse before build_osi.
    findings.analyse(trace)
    trace["osi"] = schema.build_osi(trace)
    return trace


def test_the_leak_fixture_populates_every_section():
    # A prior version of this assertion checked set(sample_trace()) >=
    # set(schema.new_trace(...)) -- but since sample_trace() is now built
    # FROM schema.new_trace(...), that containment holds by construction and
    # can never fail, even if a newly-added section is left unpopulated (a
    # re-review proved this by monkeypatching a new section into
    # schema.SECTIONS: the key was present, carrying nothing, and the
    # assertion still passed). Checking every section is actually observed --
    # not merely present as a key -- is what makes an incomplete fixture fail
    # loudly, which is the whole point of this test.
    trace = sample_trace()
    assert all(trace[s]["observed"] for s in schema.SECTIONS)


def test_sample_trace_validates():
    assert schema.validate(sample_trace()) == []


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


LEAKED_IDENTIFIERS = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                      "192.168.1.23", "192.168.1.1", "81.180.20.7")


def test_no_private_identifier_survives_serialisation():
    unredacted_blob = json.dumps(sample_trace())
    # Assert from both directions (the standing-guard blind spot this test
    # itself used to have): first prove the UNREDACTED document actually
    # contains every identifier being checked for, so a fixture that quietly
    # stopped carrying one can never make this test pass by accident.
    for leaked in LEAKED_IDENTIFIERS:
        assert leaked in unredacted_blob, f"fixture no longer carries {leaked!r} -- test proves nothing"

    out = redact.redact_trace(sample_trace())
    blob = json.dumps(out)
    for leaked in LEAKED_IDENTIFIERS:
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
    assert "aa:bb:cc:dd:ee:ff" in json.dumps(trace["osi"])  # sanity: fixture exercises the leak path

    out = redact.redact_trace(trace)
    blob = json.dumps(out["osi"])

    for leaked in LEAKED_IDENTIFIERS:
        assert leaked not in blob, leaked

    assert redact.REDACTED in blob
    # Public facts are still worth keeping in the narrative.
    assert "93.184.216.34" in blob


def test_a_malformed_hop_address_is_redacted_rather_than_published():
    trace = sample_trace()
    trace["path"]["hops"].append(
        {"ttl": 5, "ip": "12:34:56:78", "rdns": "weird-hop.example", "rtt_ms": 9.9,
         "asn": None, "prefix": None})
    out = redact.redact_trace(trace)
    assert out["path"]["hops"][-1]["ip"] == redact.REDACTED
    assert "12:34:56:78" not in json.dumps(out)


# ---------------------------------------------------------------------------
# Structural guard: walk the redacted document recursively and fail on any
# string matching a MAC or non-global-IP pattern. Every leak found in this
# build so far (osi narrative, resolver list, path hops) was a channel nobody
# had individually enumerated a field-by-field assertion for -- this is the
# generic backstop for the next one, whatever field it turns up in.
# ---------------------------------------------------------------------------

MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Covers full 8-group form, "::"-compressed forms at any position, and bare
# "::1" -- deliberately permissive (a false-positive match that fails to
# parse as a real IP address is filtered out below by ipaddress.ip_address's
# ValueError, same as IPV4_RE already relies on for e.g. version strings).
# A re-review caught that the walker was IPv4-only, silently passing an
# IPv6 leak (link-local fe80::/10, ULA fd00::/8) straight through.
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5})?\b"
    r"|\B::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    r"|\b[0-9a-fA-F]{1,4}::\B"
)

# Explicit allowlist: values that are non-global IPs / MAC-shaped but are not
# an identifier leak (none currently -- kept empty and named so the next
# maintainer has an obvious place to add one, with a reason, rather than
# loosening the regexes above).
ALLOWED_NON_GLOBAL = frozenset()


def _iter_strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)
    elif isinstance(value, str):
        yield value


def find_leaks(document):
    """Return a list of (text, offending value) for every MAC or non-global
    IPv4/IPv6 address found anywhere in the document, recursively."""
    violations = []
    for text in _iter_strings(document):
        for mac in MAC_RE.findall(text):
            if mac not in ALLOWED_NON_GLOBAL:
                violations.append((text, mac))
        for ip in IPV4_RE.findall(text) + IPV6_RE.findall(text):
            if ip in ALLOWED_NON_GLOBAL:
                continue
            try:
                is_global = ipaddress.ip_address(ip).is_global
            except ValueError:
                continue
            if not is_global:
                violations.append((text, ip))
    return violations


def test_redacted_document_has_no_mac_or_private_ip_anywhere_structurally():
    out = redact.redact_trace(sample_trace())
    leaks = find_leaks(out)
    assert leaks == [], leaks


def test_structural_leak_walker_catches_a_ula_ipv6_address_planted_in_a_note():
    # redact.redact_trace() only ever touches the structured local/tcp/dns/path
    # fields -- it does not scrub free-text note content at all. Planting a
    # ULA IPv6 address in a note demonstrates the one channel the general
    # redaction path cannot reach, and proves the walker itself (once IPv6
    # matching exists) still catches it there.
    trace = sample_trace()
    trace["notes"].append({"severity": "info", "section": "path",
                           "text": "a hop responded from fd12:3456:789a::1"})
    out = redact.redact_trace(trace)

    leaks = find_leaks(out)
    assert any("fd12:3456:789a::1" == offender for _text, offender in leaks), leaks
