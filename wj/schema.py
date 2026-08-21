"""The trace document: construction, validation, and derived OSI assembly.

The single rule this module exists to enforce: every field is either measured
or absent. A section that could not be collected says so, and says why.
"""

SCHEMA = "webpage-journey-trace/1"
SCHEMA_MAJOR = 1

SECTIONS = ("local", "dns", "negotiation", "tcp", "tls", "http", "path")
SEVERITIES = ("info", "warn", "critical")


def schema_major(schema):
    """'webpage-journey-trace/1' -> 1. Raises ValueError on anything else."""
    return int(schema.rsplit("/", 1)[1])


def observed(**fields):
    return {"observed": True, **fields}


def unobserved(why_not):
    return {"observed": False, "why_not": why_not}


def join_present(parts, sep=" "):
    """Join the present parts with sep, silently dropping any that are missing.

    A missing part is None, "", or [] -- never spelled out as the literal
    string 'None'. Returns None (not "") when nothing is present, so callers
    that already treat a falsy value as "drop this row" keep working
    unchanged. This is the one primitive for every multi-part fact built in
    this module and in render.py -- no fact is ever built by hand-
    concatenating optional values with a bare +/f-string, because that is
    exactly how a missing value turns into the literal text "None" reaching
    a user.
    """
    present = [str(p) for p in parts if p not in (None, "", [])]
    return sep.join(present) if present else None


def new_trace(target, tool_version, generated_at, capabilities, redacted):
    trace = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "tool": {"name": "trace.py", "version": tool_version},
        "target": target,
        "capabilities": capabilities,
        "redacted": redacted,
        "timings": {},
        "osi": {},
        "notes": [],
    }
    for name in SECTIONS:
        trace[name] = unobserved("not collected")
    return trace


def add_note(trace, severity, section, text):
    trace["notes"].append({"severity": severity, "section": section, "text": text})


def validate(trace):
    """Return a list of human-readable problems. Empty list means the document is valid."""
    problems = []

    try:
        major = schema_major(trace.get("schema", ""))
    except (ValueError, IndexError):
        problems.append("schema: missing or unparseable")
    else:
        if major != SCHEMA_MAJOR:
            problems.append(f"schema: unsupported major version {major}")

    for key in ("generated_at", "tool", "target", "capabilities", "timings", "osi", "notes"):
        if key not in trace:
            problems.append(f"{key}: missing")

    for name in SECTIONS:
        sec = trace.get(name)
        if not isinstance(sec, dict):
            problems.append(f"{name}: missing or not an object")
            continue
        if "observed" not in sec:
            problems.append(f"{name}: missing observed flag")
        elif sec["observed"] is False and not sec.get("why_not"):
            problems.append(f"{name}: observed is false but why_not is missing")

    for i, note in enumerate(trace.get("notes", [])):
        if note.get("severity") not in SEVERITIES:
            problems.append(f"notes[{i}]: unknown severity {note.get('severity')!r}")

    return problems


def _layer(section, facts, test_command=None):
    if not section.get("observed"):
        return {"observed": False, "facts": [],
                "why_not": section.get("why_not", "not collected"),
                "test_command": test_command}
    return {"observed": True, "facts": [f for f in facts if f],
            "why_not": None, "test_command": test_command}


def build_osi(trace):
    """Map a completed trace onto the seven layers, using only measured values."""
    local = trace.get("local", {})
    dns = trace.get("dns", {})
    tcp = trace.get("tcp", {})
    tls = trace.get("tls", {})
    http = trace.get("http", {})
    path = trace.get("path", {})

    host = trace.get("target", {}).get("host", "")
    port = trace.get("target", {}).get("port", 443)
    scheme = trace.get("target", {}).get("scheme", "https")
    url = f"{scheme}://{host}{trace.get('target', {}).get('path', '/')}"
    target_ip = (tcp.get("chosen") or {}).get("ip")

    l1_facts = [
        f"interface {local.get('interface')}" if local.get("interface") else None,
        f"link {local.get('link')}" if local.get("link") else None,
        f"MTU {local.get('mtu')}" if local.get("mtu") else None,
    ]

    l2_facts = [
        f"your MAC {local.get('local_mac')}" if local.get("local_mac") else None,
        f"→ gateway MAC {local.get('gateway_mac')} ({local.get('gateway_ip')})"
        if local.get("gateway_mac") and local.get("gateway_ip") else None,
        "every frame to this server is addressed to your router, not to the server",
    ]

    l3_facts = []
    if local.get("local_ip") and target_ip:
        l3_facts.append(f"{local['local_ip']} → {target_ip}")
    if local.get("nat") and local.get("local_ip") and local.get("public_ip"):
        l3_facts.append(f"NAT: {local['local_ip']} appears as {local['public_ip']}")
    if path.get("observed"):
        l3_facts.append(f"{len(path.get('hops', []))} hops")
        as_path = path.get("asn_path") or []
        if as_path:
            l3_facts.append(" → ".join(f"AS{n}" for n in as_path))

    kernel = tcp.get("kernel") or {}
    l4_facts = []
    if tcp.get("observed"):
        local_port = (tcp.get("local") or {}).get("port")
        if local_port is not None:
            l4_facts.append(f"TCP :{local_port} → :{port}")
        if kernel.get("rtt_ms") is not None:
            l4_facts.append(f"RTT {kernel['rtt_ms']} ms")
        if kernel.get("mss"):
            l4_facts.append(f"MSS {kernel['mss']}")
        if kernel.get("retransmits") is not None:
            l4_facts.append(f"{kernel['retransmits']} retransmits")
        if tcp.get("winner_family"):
            l4_facts.append(f"{tcp['winner_family']} won the connection race")

    l5_facts = []
    if tls.get("observed"):
        l5_facts.append("TLS session established")
        if (tls.get("resumption") or {}).get("resumed"):
            l5_facts.append("resumed from a session ticket")
    if http.get("observed"):
        hops = http.get("hops") or []
        reused = [h for h in hops if h.get("connection_reused")]
        if reused:
            l5_facts.append(
                f"{len(reused)} of {len(hops)} redirect(s) reused the previous connection")
        else:
            l5_facts.append("1 request over this connection")
            if hops:
                l5_facts.append(f"{len(hops)} redirect(s), each on a new connection")

    final = http.get("final") or {}
    l6_facts = []
    if tls.get("observed"):
        version_cipher = " · ".join(
            p for p in (tls.get("version"), tls.get("cipher")) if p)
        if version_cipher:
            l6_facts.append(version_cipher)
        if tls.get("alpn"):
            l6_facts.append(f"ALPN {tls['alpn']}")
    if final.get("encoding"):
        # wire_bytes/decoded_bytes/ratio can each independently be absent (a
        # failed inflate leaves decoded_bytes/ratio unset while wire_bytes
        # stays known) -- build the sentence from only what is present, rather
        # than spelling a missing one out as the literal text "None".
        sizes = join_present([
            f"{final['wire_bytes']} bytes" if final.get("wire_bytes") is not None else None,
            f"{final['decoded_bytes']} bytes" if final.get("decoded_bytes") is not None else None,
        ], sep=" → ")
        ratio_part = f"({final['ratio']}:1)" if final.get("ratio") is not None else None
        detail = join_present([sizes, ratio_part], sep=" ")
        l6_facts.append(join_present([f"{final['encoding']}:", detail], sep=" ")
                        if detail else final["encoding"])
    if final.get("content_type"):
        l6_facts.append(final["content_type"])

    negotiation = trace.get("negotiation", {})
    l7_facts = []
    if negotiation.get("observed") and negotiation.get("chosen"):
        l7_facts.append(f"negotiated {negotiation['chosen']} over ALPN")
    if http.get("observed"):
        protocol, status = final.get("protocol"), final.get("status")
        if protocol and status is not None:
            l7_facts.append(f"{protocol} → {status}")
        elif status is not None:
            l7_facts.append(f"status {status}")
        elif protocol:
            l7_facts.append(protocol)
        if http.get("hops"):
            if http.get("redirect_limit_reached"):
                l7_facts.append(
                    f"{len(http['hops'])} redirect(s) followed — chain truncated at the limit")
            else:
                l7_facts.append(f"{len(http['hops'])} redirect(s) followed")
    if dns.get("observed"):
        if target_ip:
            l7_facts.append(f"DNS: {host} → {target_ip}")
        else:
            l7_facts.append(f"DNS: {host} resolved")
        resolver = (dns.get("resolver") or {}).get("servers") or []
        if resolver:
            fact = f"resolved via {resolver[0]}"
            if dns.get("dnssec"):
                fact += f", DNSSEC {dns['dnssec']}"
            l7_facts.append(fact)
        failed = dns.get("records_failed") or []
        if failed:
            l7_facts.append(f"query failed for: {', '.join(failed)}")

    return {
        "l1": _layer(local, l1_facts, f"ifconfig {local.get('interface')}"
                     if local.get("interface") else None),
        "l2": _layer(local, l2_facts, f"arp -n {local.get('gateway_ip')}"
                     if local.get("gateway_ip") else None),
        "l3": _layer(tcp if not path.get("observed") else path, l3_facts,
                     f"ping {target_ip}" if target_ip else None),
        "l4": _layer(tcp, l4_facts, f"nc -vz {host} {port}"),
        "l5": _layer(tls if tls.get("observed") else http, l5_facts, None),
        "l6": _layer(tls if tls.get("observed") else http, l6_facts,
                     f"openssl s_client -connect {host}:{port} -servername {host}"),
        "l7": _layer(http, l7_facts, f"curl -sSI {url}"),
    }
