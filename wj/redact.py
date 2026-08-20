"""Strip identifying detail from a trace before it is exported and shared."""

import copy
import ipaddress

REDACTED = "[redacted at export]"

LOCAL_FIELDS = ("local_ip", "local_mac", "gateway_ip", "gateway_mac", "public_ip")


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

    return out
