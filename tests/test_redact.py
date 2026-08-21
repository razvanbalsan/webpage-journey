import copy
import ipaddress
import json
import re

import pytest

from wj import findings, redact, schema


def sample_trace(protocol="http/1.1"):
    """A real trace document, assembled the same way orchestrate() does it.

    Built from schema.new_trace(...) with every section populated, then run
    through the real findings.analyse() and schema.build_osi() -- not a
    hand-rolled dict with only the keys a given test happens to need. Three
    leaks have now slipped through this test module because its old fixture
    had no osi/notes/timings/capabilities keys at all, so a guard checking
    "does the redacted document still contain X" never even had X to find in
    the first place. test_the_leak_fixture_populates_every_section below
    makes an incomplete fixture fail loudly instead of silently.

    `protocol="h2"` swaps in the h2 shape of the fields Task 4 added
    (negotiation.chosen, http.hops[].stream_id, http.final.header_bytes) --
    one fixture cannot coherently be both an h1 and an h2 trace (h2's own
    stream_id is an int, header_bytes a dict of ints, chosen "h2", none of
    which the http/1.1 variant ever produces), and a leak walker that only
    ever sees the empty/None h1 variant of those fields has never actually
    walked over populated instances of them.
    """
    trace = schema.new_trace(
        target={"input": "https://example.com/", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.1.0", generated_at="2026-08-20T09:00:00+00:00",
        capabilities={"privileged": False, "can_sudo": False, "tools": ["traceroute"],
                      "libs": {"dns": True, "cryptography": True},
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

    if protocol == "h2":
        trace["negotiation"] = schema.observed(
            advertised=["h2"], offered=["h2", "http/1.1"], signal="HTTPS record",
            unavailable=[], chosen="h2",
            # See the module docstring above re: attempted staying [] in
            # Phase 1 -- true for both variants, not just the h1 one.
            attempted=[])
    else:
        trace["negotiation"] = schema.observed(
            advertised=[], offered=["http/1.1"], signal="no HTTPS record",
            unavailable=[], chosen="http/1.1",
            # Phase 1 never populates this -- there is no fallback ladder yet (see
            # wj/collect/negotiate.py and Task 4's brief), so every real trace this
            # tool can currently produce carries attempted=[] structurally, the
            # same as advertised/offered/unavailable can each independently be
            # empty. Nothing here can leak an identifier because nothing here is
            # ever populated; Phase 2 is what gives this field per-attempt records
            # (see .superpowers/sdd/2026-08-21-http2-phase1/task-8-brief.md) and
            # is also what must extend this fixture once it does.
            attempted=[])

    trace["tcp"] = schema.observed(
        candidates=[{"ip": "93.184.216.34", "family": "ipv4", "connect_ms": 12.4, "error": None}],
        chosen={"ip": "93.184.216.34", "family": "ipv4", "port": 443},
        winner_family="ipv4", local={"ip": "192.168.1.23", "port": 54213},
        kernel={"rtt_ms": 12.4, "mss": 1460, "retransmits": 0, "source": "TCP_INFO"})

    trace["tls"] = schema.observed(
        version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256", alpn=protocol,
        handshake_ms=38.2,
        chain=[{"subject_cn": "example.com", "issuer_cn": "R3", "issuer_org": "Let's Encrypt",
                "not_before": "2026-06-01T00:00:00+00:00", "not_after": "2026-08-30T00:00:00+00:00",
                "days_left": 80, "key": {"type": "EC", "bits": 256}, "sig_algo": "ecdsa-with-SHA256",
                "sans": ["example.com"], "scts": 2, "ocsp": [], "is_ca": False}],
        trust_root="ISRG Root X1", verified=True, caa_match=True,
        resumption={"tested": False}, legacy_versions_accepted=[])

    if protocol == "h2":
        trace["http"] = schema.observed(
            hops=[{"url": "https://example.com/", "status": 301,
                  "location": "https://example.com/next", "protocol": "HTTP/2",
                  "ttfb_ms": 12.0, "connection_reused": False, "stream_id": 1}],
            redirect_limit_reached=False,
            final={"url": "https://example.com/next", "status": 200, "reason": None,
                   "protocol": "HTTP/2", "headers": [["content-type", "text/html"]],
                   "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000, "decoded_bytes": 61000,
                   "encoding": "gzip", "ratio": 4.36, "content_type": "text/html",
                   "header_bytes": {"wire": 812, "decoded": 1400}},
            cache={"state": None, "age": None, "header": None, "directives": None},
            cdn=None,
            security={"grade": "A", "present": {}, "missing": [],
                     "cookies": [{"name": "s", "secure": True, "httponly": True, "samesite": "Lax"}],
                     "scheme": "https"},
            conditional={"tested": False})
    else:
        trace["http"] = schema.observed(
            hops=[{"url": "http://example.com/", "status": 301,
                  "location": "https://example.com/", "protocol": "HTTP/1.1",
                  "ttfb_ms": 12.0, "connection_reused": False, "stream_id": None}],
            redirect_limit_reached=False,
            final={"url": "https://example.com/", "status": 200, "reason": "OK",
                   "protocol": "HTTP/1.1", "headers": [["content-type", "text/html"]],
                   "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000, "decoded_bytes": 61000,
                   "encoding": "gzip", "ratio": 4.36, "content_type": "text/html",
                   "header_bytes": None},
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


@pytest.mark.parametrize("protocol", ["http/1.1", "h2"])
def test_the_leak_fixture_populates_every_section(protocol):
    # A prior version of this assertion checked set(sample_trace()) >=
    # set(schema.new_trace(...)) -- but since sample_trace() is now built
    # FROM schema.new_trace(...), that containment holds by construction and
    # can never fail, even if a newly-added section is left unpopulated (a
    # re-review proved this by monkeypatching a new section into
    # schema.SECTIONS: the key was present, carrying nothing, and the
    # assertion still passed). Checking every section is actually observed --
    # not merely present as a key -- is what makes an incomplete fixture fail
    # loudly, which is the whole point of this test.
    trace = sample_trace(protocol)
    assert all(trace[s]["observed"] for s in schema.SECTIONS)


@pytest.mark.parametrize("protocol", ["http/1.1", "h2"])
def test_sample_trace_validates(protocol):
    assert schema.validate(sample_trace(protocol)) == []


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


def test_the_structural_walker_reaches_the_negotiation_section():
    # negotiation.signal is currently always one of a handful of fixed
    # strings from wj/collect/negotiate.py that never embed an identifier --
    # but adding a section is exactly when a fixture-blind leak has
    # previously gone unnoticed on this project, so this proves redact_trace
    # actually reaches into negotiation rather than skipping it entirely.
    trace = sample_trace()
    trace["negotiation"]["signal"] = "HTTPS record via 192.168.1.1"
    out = redact.redact_trace(trace)
    leaked = [s for s in _iter_strings(out) if "192.168.1.1" in s]
    assert not leaked, leaked


# Every hole a re-review found in _scrub_embedded_identifiers()
# (wj/redact.py), planted into negotiation.signal the same way the test
# above does. A prior round of this fix had no test touching the scrubber
# beyond the plain-private-IPv4 case above, which even a fail-open,
# IPv4-only, no-IPv6 implementation already passed -- "347 passed" on a
# scrubber with three open holes.
#
# Exact string equality, not a substring-absence check: an earlier version
# of this test asserted only that the full original address (e.g.
# "192.168.1.1") no longer appeared anywhere, which a PARTIAL leak sails
# straight through -- the actual regression this round fixed left
# "[redacted at export].168.1.1" behind (the leading "192" consumed by an
# over-matching IPv6 alternative, the trailing ".168.1.1" then too short to
# match _IPV4_RE at all), and "192.168.1.1" is indeed not a substring of
# that, so a not-in check on the whole address would have passed right over
# it. It is also not IPv4-shaped, so the structural walker (find_leaks,
# below) cannot see it either -- exact equality is the only check precise
# enough to catch a truncation like this.
SIGNAL_SCRUB_CASES = (
    ("operator's own public IP",
     "HTTPS record via 81.180.20.7",
     "HTTPS record via [redacted at export]"),
    ("leading-zero IPv4 (unparseable by ipaddress)",
     "HTTPS record via 192.168.01.1",
     "HTTPS record via [redacted at export]"),
    ("link-local IPv6",
     "HTTPS record via fe80::1",
     "HTTPS record via [redacted at export]"),
    ("global IPv6",
     "HTTPS record via 2001:db8::1",
     "HTTPS record via [redacted at export]"),
    ("IPv4-mapped IPv6",
     "HTTPS record via ::ffff:192.168.1.1",
     "HTTPS record via [redacted at export]:[redacted at export]"),
    ("IPv4-mapped IPv6, uppercase prefix, public octets",
     "HTTPS record via ::FFFF:81.180.20.7",
     "HTTPS record via [redacted at export]:[redacted at export]"),
    ("hyphen-separated MAC",
     "iface A4-83-E7-1B-2C-3D",
     "iface [redacted at export]"),
    ("Cisco dot-quad MAC",
     "iface a483.e71b.2c3d",
     "iface [redacted at export]"),
    # A re-review found these two uncovered: every existing IPv6 case above
    # ends in a real group (":1"), so \b fires and both passed even under
    # the pre-fix \b-anchored pattern -- neither exercises the \b ->
    # (?![0-9a-fA-F:]) half of that fix. And MAC previously ran before
    # IPv4/IPv6 (see _scrub_embedded_identifiers()'s ordering comment): its
    # exactly-2-hex-digit-group colon form consumed the first six groups of
    # this ULA, an all-two-digit-group IPv6 address, leaving the last two
    # groups -- unparseable alone, so find_leaks() can't see the residue --
    # unredacted.
    ("::-terminated IPv6",
     "HTTPS record via 2001:db8::",
     "HTTPS record via [redacted at export]"),
    ("all-two-hex-digit-group IPv6 ULA (fd00::/8, non-global)",
     "HTTPS record via fd12:34:56:78:9a:bc:de:f0",
     "HTTPS record via [redacted at export]"),
)


@pytest.mark.parametrize("label, planted, expected", SIGNAL_SCRUB_CASES)
def test_the_negotiation_signal_scrubber_closes_every_known_hole(label, planted, expected):
    trace = sample_trace()
    trace["negotiation"]["signal"] = planted
    out = redact.redact_trace(trace)
    assert out["negotiation"]["signal"] == expected, label


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


@pytest.mark.parametrize("protocol", ["http/1.1", "h2"])
def test_redacted_document_has_no_mac_or_private_ip_anywhere_structurally(protocol):
    # Walked for both variants: the h2 shape of the fields Task 4 added
    # (stream_id as an int, header_bytes as a dict of ints, chosen: "h2")
    # never reaches this walker under the http/1.1-only fixture, since those
    # fields are None/absent there -- an all-empty variant is exactly the
    # "fixture never populated the section that was leaking" pattern this
    # project has been burned by three times before.
    out = redact.redact_trace(sample_trace(protocol))
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
