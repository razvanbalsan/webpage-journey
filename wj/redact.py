"""Strip identifying detail from a trace before it is exported and shared."""

import copy
import ipaddress
import re

from wj import schema

REDACTED = "[redacted at export]"

LOCAL_FIELDS = ("local_ip", "local_mac", "gateway_ip", "gateway_mac", "public_ip")

_MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


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
    """Replace any MAC address or non-global IPv4 address embedded in a
    string with REDACTED, leaving the rest of the text intact.

    Used on negotiation.signal below. wj/collect/negotiate.py's choose()
    only ever produces a handful of fixed strings, none of which embed an
    identifier -- this is a defensive backstop for a future signal string
    that does, not a fix for a value seen today.
    """
    text = _MAC_RE.sub(REDACTED, text)

    def _sub(match):
        try:
            return match.group() if ipaddress.ip_address(match.group()).is_global else REDACTED
        except ValueError:
            return match.group()

    return _IPV4_RE.sub(_sub, text)


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

    # The OSI narrative is assembled from the same local/tcp/dns/path facts
    # above, but as free-text strings baked in at orchestration time — before
    # any redaction ran. Rebuilding it here, from the now-redacted sections,
    # is the only way to keep it from re-publishing what was just stripped.
    if out.get("osi"):
        out["osi"] = schema.build_osi(out)

    return out
