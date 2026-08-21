"""Strip identifying detail from a trace before it is exported and shared."""

import copy
import ipaddress
import re

from wj import schema

REDACTED = "[redacted at export]"

LOCAL_FIELDS = ("local_ip", "local_mac", "gateway_ip", "gateway_mac", "public_ip")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Covers full 8-group form, "::"-compressed forms at any position, and bare
# "::1". The two variable-length alternations end on a negative lookahead
# for a further hex/colon character, not \b: a re-review found \b false
# NEGATIVE at the very end of an address like "2001:db8::" followed by
# whitespace -- both the trailing ":" and the whitespace are non-word
# characters, so \b never fires there and only "db8::" got matched,
# leaving "2001:" unredacted.
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5})?(?![0-9a-fA-F:])"
    r"|\B::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    r"|\b[0-9a-fA-F]{1,4}::(?![0-9a-fA-F:])"
)
# Colon (aa:bb:cc:dd:ee:ff), hyphen (aa-bb-cc-dd-ee-ff), and Cisco dot-quad
# (aaaa.bbbb.cccc) forms. _scrub_embedded_identifiers()'s docstring promises
# "any MAC address" -- colon is the only form any collector in this
# codebase actually emits today, but a re-review caught that promise being
# wider than an earlier, colon-only version of this pattern. Matching all
# three, rather than narrowing the docstring, is the right fix: this
# function exists to be a backstop for a string that does not exist yet,
# and a MAC in one of the other two forms is exactly that case.
_MAC_RE = re.compile(
    r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b"
    r"|\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b"
    r"|\b[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}\b"
)


def _identifies_operator(value):
    """True unless the address is provably public and globally routable.

    Redaction fails CLOSED: a value we cannot parse is redacted rather than
    published. This is deliberately the opposite polarity from
    collect.local.is_private(), where an unparseable address should simply
    not count toward the NAT determination.
    """
    if not value:
        return False
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return True


def _scrub_embedded_identifiers(text):
    """Replace any MAC address or IPv4/IPv6 address embedded in a string
    with REDACTED, leaving the rest of the text intact.

    Applied below to every free-text field a trace document carries: each
    section's why_not, every note's text, and negotiation.signal.

    why_not is the one that carries genuinely uncontrolled text --
    wj/run.py turns ANY collector exception into f"{type(exc).__name__}:
    {exc}", so whatever an OSError, a resolver, or a socket puts in its
    message goes straight into the document. notes[].text is assembled by
    wj/findings.py from section values. negotiation.signal is the
    defensive case: choose() only ever produces a handful of fixed
    strings, none of which embed an identifier today.

    Unlike _identifies_operator() above, this does not spare globally
    routable addresses. That distinction is right for a field like
    dns.resolver.servers, where a public resolver is a legitimate fact to
    publish on its own terms -- it is wrong for free text, which could just
    as easily embed the operator's own public_ip, a value LOCAL_FIELDS
    strips unconditionally a few lines below. Every address-shaped match is
    redacted outright: no ipaddress.ip_address() parse-and-branch here, so
    there is no ValueError path that could fail open (redact_trace's own
    rule is "fails CLOSED", per _identifies_operator's docstring above).
    """
    # Order matters, and is IPv4 -> IPv6 -> MAC, each for the same
    # consume-and-starve reason: an earlier ordering ran MAC first, and its
    # exactly-2-hex-digit-group colon form matches the first six groups of
    # any IPv6 address that happens to be written in all-two-digit-group
    # canonical short form (e.g. a ULA like "fd12:34:56:78:9a:bc:de:f0"),
    # leaving the last two groups -- unparseable on their own, so neither
    # find_leaks() nor a plain ipaddress.ip_address() check downstream can
    # see the residue -- unredacted. And IPv4 must run before IPv6 for the
    # same reason (see _IPV6_RE's comment above): an IPv4-mapped address
    # like "::ffff:192.168.1.1" needs its dotted quad claimed as one unit
    # before _IPV6_RE's own "::"-prefixed alternative gets a chance to eat
    # the leading octet as a bare hex group. _IPV6_RE's variable-length
    # alternations all require a literal "::", so running it before MAC
    # never eats into a colon-only MAC address in the same way MAC-first ate
    # into IPv6 -- a MAC's 6 groups of exactly 2 hex digits, separated by
    # single colons with no "::" anywhere, cannot satisfy any _IPV6_RE
    # alternative.
    text = _IPV4_RE.sub(REDACTED, text)
    text = _IPV6_RE.sub(REDACTED, text)
    return _MAC_RE.sub(REDACTED, text)


def redact_trace(trace):
    out = copy.deepcopy(trace)
    out["redacted"] = True

    local = out.get("local", {})
    if local.get("observed"):
        for field in LOCAL_FIELDS:
            if local.get(field):
                local[field] = REDACTED
        dhcp = local.get("dhcp") or {}
        if dhcp.get("server"):
            dhcp["server"] = REDACTED
        if dhcp.get("dns"):
            dhcp["dns"] = [REDACTED for _ in dhcp["dns"]]

    tcp = out.get("tcp", {})
    if tcp.get("observed") and tcp.get("local", {}).get("ip"):
        tcp["local"]["ip"] = REDACTED

    path = out.get("path", {})
    if path.get("observed"):
        for hop in path.get("hops", []):
            if hop.get("ip") and _identifies_operator(hop["ip"]):
                hop["ip"] = REDACTED
                if hop.get("rdns"):
                    hop["rdns"] = REDACTED

    dns = out.get("dns", {})
    if dns.get("observed"):
        resolver = dns.get("resolver") or {}
        if resolver.get("servers"):
            resolver["servers"] = [
                REDACTED if _identifies_operator(s) else s
                for s in resolver["servers"]
            ]

    negotiation = out.get("negotiation", {})
    if negotiation.get("observed") and negotiation.get("signal"):
        negotiation["signal"] = _scrub_embedded_identifiers(negotiation["signal"])

    # Free text, on the UNOBSERVED path. wj/run.py renders any collector
    # exception as f"{type(exc).__name__}: {exc}" -- arbitrary text, from a
    # socket error or a resolver, straight into the exported document. This
    # ran unscrubbed while the one field that provably cannot embed an
    # identifier (negotiation.signal, above) was the only one scrubbed at
    # all.
    for name in schema.SECTIONS:
        section = out.get(name)
        if isinstance(section, dict) and section.get("why_not"):
            section["why_not"] = _scrub_embedded_identifiers(section["why_not"])

    # Free text again: wj/findings.py builds every note from section values,
    # and a note is copied verbatim into the export and onto the page.
    for note in out.get("notes") or []:
        if isinstance(note, dict) and note.get("text"):
            note["text"] = _scrub_embedded_identifiers(note["text"])

    # The OSI narrative is assembled from the same local/tcp/dns/path facts
    # above, but as free-text strings baked in at orchestration time — before
    # any redaction ran. Rebuilding it here, from the now-redacted sections,
    # is the only way to keep it from re-publishing what was just stripped.
    if out.get("osi"):
        out["osi"] = schema.build_osi(out)

    return out
