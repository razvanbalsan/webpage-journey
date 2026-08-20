"""Strip identifying detail from a trace before it is exported and shared."""

import copy

from wj.collect.local import is_private

REDACTED = "[redacted at export]"

LOCAL_FIELDS = ("local_ip", "local_mac", "gateway_ip", "gateway_mac", "public_ip")


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
            if hop.get("ip") and is_private(hop["ip"]):
                hop["ip"] = REDACTED
                if hop.get("rdns"):
                    hop["rdns"] = REDACTED

    return out
