"""Layer 3: the hops between you and the destination, and whose networks they belong to."""

import re
import subprocess

from wj.schema import observed, unobserved

HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
ADDR_RE = re.compile(r"([\w.\-]+)\s+\(([\d.:a-fA-F]+)\)")
BARE_IP_RE = re.compile(r"^([\d.]+|[0-9a-fA-F:]+)\s")
RTT_RE = re.compile(r"([\d.]+)\s*ms")


def parse_traceroute(text):
    """Parse traceroute output from either macOS or Linux into ordered hops."""
    hops = []
    for line in text.splitlines():
        if line.lower().startswith("traceroute"):
            continue
        match = HOP_RE.match(line)
        if not match:
            continue

        ttl = int(match.group(1))
        rest = match.group(2).strip()

        if rest.startswith("*"):
            hops.append({"ttl": ttl, "ip": None, "rdns": None, "rtt_ms": None})
            continue

        addr = ADDR_RE.search(rest)
        if addr:
            rdns, ip = addr.group(1), addr.group(2)
            if rdns == ip:
                rdns = None
        else:
            bare = BARE_IP_RE.match(rest)
            if not bare:
                continue
            ip, rdns = bare.group(1), None

        rtt = RTT_RE.search(rest)
        hops.append({"ttl": ttl, "ip": ip, "rdns": rdns,
                     "rtt_ms": float(rtt.group(1)) if rtt else None})

    return hops


def cymru_name(ip):
    return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"


def parse_cymru_txt(value):
    parts = [p.strip() for p in value.strip('"').split("|")]
    asn = None
    if parts and parts[0]:
        try:
            asn = int(parts[0].split()[0])
        except (ValueError, IndexError):
            asn = None
    return {"asn": asn,
            "prefix": parts[1] if len(parts) > 1 else None,
            "country": parts[2] if len(parts) > 2 else None}


def asn_path(hops):
    out = []
    for hop in hops:
        asn = hop.get("asn")
        if asn and (not out or out[-1] != asn):
            out.append(asn)
    return out


def _dns_asn_lookup(ctx):
    def lookup(ip):
        if ":" in ip:  # Cymru's IPv6 origin zone uses a different nibble format
            return {"asn": None, "prefix": None, "country": None}
        try:
            import dns.resolver
            answer = dns.resolver.resolve(cymru_name(ip), "TXT", lifetime=3.0)
            return parse_cymru_txt(str(answer[0]))
        except Exception:
            return {"asn": None, "prefix": None, "country": None}

    return lookup


def _run_traceroute(ctx):
    def run(cmd, timeout):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout

    return run


def collect(ctx, run=None, asn_lookup=None):
    if ctx.no_path:
        return unobserved("skipped with --no-path")

    tcp = ctx.results.get("tcp", {})
    target_ip = (tcp.get("chosen") or {}).get("ip")
    if not target_ip:
        return unobserved("no destination address to trace towards")

    if not ctx.caps.has_tool("traceroute"):
        return unobserved("traceroute not on PATH")

    run = run or _run_traceroute(ctx)
    asn_lookup = asn_lookup or _dns_asn_lookup(ctx)

    budget = ctx.budget_for(20.0)
    cmd = ["traceroute", "-w", "1", "-q", "1", "-m", "20", target_ip]
    try:
        out = run(cmd, timeout=budget)
    except Exception as exc:
        return unobserved(f"traceroute failed: {exc}")

    hops = parse_traceroute(out)
    if not hops:
        return unobserved("traceroute returned no parseable hops")

    for hop in hops:
        if hop["ip"]:
            info = asn_lookup(hop["ip"])
            hop["asn"] = info.get("asn")
            hop["as_name"] = info.get("prefix")
        else:
            hop["asn"] = None
            hop["as_name"] = None

    return observed(source="traceroute", hops=hops,
                    asn_path=asn_path(hops), path_mtu=None)
