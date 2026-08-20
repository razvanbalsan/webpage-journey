"""Layer 7 riding on 4 and 3: what the name resolves to, and how that answer was found.

`records_failed` in the collected section lists record types whose query did not
complete (timeout, SERVFAIL, or another resolver error) -- for those types
`records[rtype]` is `[]`, but that empty list means "unknown", not "this domain
publishes no records of this type". Only a genuine NoAnswer response -- the name
exists and this record type is confirmed absent -- produces an empty list that is
not also listed in `records_failed`.
"""

import platform
import re
import subprocess
import time

from wj.schema import observed, unobserved

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS")

ROOT_SERVER_IP = "198.41.0.4"  # a.root-servers.net
MAX_DELEGATION_HOPS = 8


def parse_https_rr(value):
    """Pull ALPN protocols and ECH presence out of an HTTPS/SVCB record's text form."""
    alpn = []
    match = re.search(r'alpn="([^"]+)"', value)
    if match:
        alpn = [p.strip() for p in match.group(1).split(",") if p.strip()]
    return {"alpn": alpn, "ech": "ech=" in value}


def parse_resolv_conf(text):
    return [line.split()[1] for line in text.splitlines()
            if line.strip().startswith("nameserver") and len(line.split()) > 1]


def parse_scutil_dns(text):
    seen = []
    for match in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", text):
        ip = match.group(1)
        if ip not in seen:
            seen.append(ip)
    return seen


def classify_dnssec(ad_flag, had_answer):
    if ad_flag is None:
        return "unknown"
    if not had_answer:
        return "unknown"
    return "secure" if ad_flag else "insecure"


def system_resolvers():
    """Return (servers, source). Best effort; an empty list is a fine answer."""
    if platform.system() == "Darwin":
        try:
            out = subprocess.run(["scutil", "--dns"], capture_output=True,
                                 text=True, timeout=5).stdout
            servers = parse_scutil_dns(out)
            if servers:
                return servers, "scutil"
        except Exception:
            pass
    try:
        with open("/etc/resolv.conf") as fh:
            servers = parse_resolv_conf(fh.read())
        if servers:
            return servers, "resolv.conf"
    except OSError:
        pass
    return [], "unknown"


def walk_delegation(host, query_at, root_ip=ROOT_SERVER_IP):
    """Root -> TLD -> authoritative, following referrals by hand.

    query_at(server_ip, name, rtype) must return
    {"answer": [...], "authority": [...], "additional": {name: ip}}.
    """
    levels = ["root", "tld", "authoritative"]
    walk = []
    server = root_ip

    for hop in range(MAX_DELEGATION_HOPS):
        try:
            response = query_at(server, host, "NS")
        except Exception as exc:
            walk.append({"level": levels[min(hop, len(levels) - 1)],
                         "server": server, "error": str(exc)})
            break

        level = levels[hop] if hop < len(levels) else f"hop{hop + 1}"
        entry = {"level": level, "server": server,
                 "referral": list(response.get("authority", [])),
                 "answer": list(response.get("answer", []))}
        walk.append(entry)

        if entry["answer"]:
            break
        additional = response.get("additional", {})
        next_ip = next((additional[n] for n in entry["referral"] if n in additional), None)
        if not next_ip:
            break
        server = next_ip

    return walk


def _dnspython_query(ctx):
    import dns.flags
    import dns.resolver

    resolver = dns.resolver.Resolver()
    per_query = min(ctx.timeout, 3.0)
    resolver.timeout = per_query
    resolver.lifetime = per_query
    resolver.use_edns(0, dns.flags.DO, 4096)

    def query(name, rtype):
        try:
            answer = resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN as exc:
            raise LookupError(f"NXDOMAIN for {name}") from exc
        except dns.resolver.NoAnswer:
            return [], None          # the name exists; this record type does not
        except Exception:
            return None, None        # the query failed — that is not the same as absence
        ad = bool(answer.response.flags & dns.flags.AD)
        ttl = answer.rrset.ttl if answer.rrset is not None else 0
        return [{"data": str(r).strip('"'), "ttl": ttl} for r in answer], ad

    return query


def _dnspython_delegation(ctx):
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype

    def query_at(server_ip, name, rtype):
        message = dns.message.make_query(name, rtype)
        message.flags &= ~dns.flags.RD
        response = dns.query.udp(message, server_ip, timeout=min(ctx.timeout, 3.0))
        authority, additional = [], {}
        for rrset in response.authority:
            for item in rrset:
                authority.append(str(item).rstrip("."))
        for rrset in response.additional:
            for item in rrset:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    additional[str(rrset.name).rstrip(".")] = str(item)
        answer = [str(i).rstrip(".") for rrset in response.answer for i in rrset]
        return {"answer": answer, "authority": authority, "additional": additional}

    return lambda host: walk_delegation(host, query_at)


def collect(ctx, query=None, delegation=None, resolvers=None):
    if not ctx.caps.has_lib("dns"):
        return unobserved("dnspython not installed")

    query = query or _dnspython_query(ctx)
    delegation = delegation or _dnspython_delegation(ctx)
    resolvers = resolvers or system_resolvers

    records = {}
    failed = []
    dnssec_flag = None
    cold_start = time.perf_counter()
    try:
        for rtype in RECORD_TYPES:
            found, ad = query(ctx.host, rtype)
            if found is None:
                records[rtype] = []
                failed.append(rtype)
                continue
            records[rtype] = found
            if ad is not None and rtype in ("A", "AAAA") and dnssec_flag is None:
                dnssec_flag = ad
    except LookupError as exc:
        return unobserved(str(exc))
    cold_ms = round((time.perf_counter() - cold_start) * 1000, 1)

    if not records.get("A") and not records.get("AAAA"):
        return unobserved(f"{ctx.host} did not resolve to any address")

    warm_start = time.perf_counter()
    try:
        query(ctx.host, "A")
    except LookupError:
        pass
    warm_ms = round((time.perf_counter() - warm_start) * 1000, 1)

    https_info = {"alpn": [], "ech": False}
    if records.get("HTTPS"):
        https_info = parse_https_rr(records["HTTPS"][0]["data"])

    servers, source = resolvers()

    return observed(
        records=records,
        records_failed=failed,
        resolver={"servers": servers, "source": source},
        dnssec=classify_dnssec(dnssec_flag, True),
        delegation=delegation(ctx.host),
        alpn_advertised=https_info["alpn"],
        ech=https_info["ech"],
        timing_ms={"cold": cold_ms, "warm": warm_ms},
    )
