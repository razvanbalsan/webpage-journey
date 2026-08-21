"""Turn a completed trace into the short list of things worth acting on."""

from wj.collect.tls import grade_expiry
from wj.schema import add_note

POOR_GRADES = ("D", "E", "F")


def analyse(trace):
    # Derived data must be rebuilt, not appended to -- redact_trace learned this
    # already (it rebuilds trace["osi"] rather than trying to redact the free
    # text baked into it). Calling analyse() twice on the same trace without
    # this would duplicate every note it produces.
    trace["notes"] = []
    _analyse_dns(trace)
    _analyse_tls(trace)
    _analyse_negotiation(trace)
    _analyse_http(trace)


def _analyse_dns(trace):
    dns = trace.get("dns", {})
    if not dns.get("observed"):
        return

    if dns.get("dnssec") == "insecure":
        add_note(trace, "info", "dns",
                 "DNSSEC is not signed for this zone — answers cannot be authenticated")

    records = dns.get("records", {})
    if records.get("A") and not records.get("AAAA"):
        add_note(trace, "info", "dns",
                 "no AAAA record — this host is unreachable over IPv6-only networks")

    if "h3" not in (dns.get("alpn_advertised") or []):
        add_note(trace, "info", "dns",
                 "no HTTP/3 advertised in the HTTPS record — clients cannot use QUIC on the first connection")


def _analyse_tls(trace):
    tls = trace.get("tls", {})
    if not tls.get("observed"):
        return

    chain = tls.get("chain") or []
    if chain and chain[0].get("days_left") is not None:
        graded = grade_expiry(chain[0]["days_left"])
        if graded:
            severity, message = graded
            add_note(trace, severity, "tls", message)

    for version in tls.get("legacy_versions_accepted") or []:
        add_note(trace, "critical", "tls",
                 f"{version} is still accepted — clients can be downgraded to it")

    if tls.get("caa_match") is False:
        add_note(trace, "warn", "tls",
                 "the presented issuer is not listed in the zone's CAA records")


def _analyse_negotiation(trace):
    negotiation = trace.get("negotiation", {})
    if not negotiation.get("observed"):
        return

    advertised = list(negotiation.get("advertised") or [])
    offered = set(negotiation.get("offered") or [])
    unavailable = set(negotiation.get("unavailable") or [])

    # A protocol the host advertises that we never put on the wire. Anything we
    # offered is not a gap, whether or not the server picked it.
    gaps = [p for p in advertised if p not in offered]
    if not gaps:
        return

    missing_lib = [p for p in gaps if p in unavailable]
    unsupported = [p for p in gaps if p not in unavailable]

    if missing_lib:
        add_note(trace, "info", "negotiation",
                 f"this host advertises {', '.join(missing_lib)}, but the library "
                 f"needed to speak it is not installed — this trace used "
                 f"{negotiation.get('chosen') or 'HTTP/1.1'}")

    if unsupported:
        add_note(trace, "info", "negotiation",
                 f"this host advertises {', '.join(unsupported)}, which this tool "
                 f"does not speak — this trace used "
                 f"{negotiation.get('chosen') or 'HTTP/1.1'}")


def _analyse_http(trace):
    http = trace.get("http", {})
    if not http.get("observed"):
        return

    final = http.get("final") or {}
    if final.get("encoding") and final.get("decoded_bytes") is None:
        add_note(trace, "warn", "http",
                 f"the response advertised {final['encoding']} but this tool "
                 f"could not decompress it — decoded size and compression ratio "
                 f"are not measured")

    for hop in http.get("hops") or []:
        if str(hop.get("url", "")).startswith("http://"):
            add_note(trace, "warn", "http",
                     f"redirect hop {hop['url']} travelled in plaintext before the upgrade")

    security = http.get("security") or {}
    grade = security.get("grade")
    if grade in POOR_GRADES:
        missing = ", ".join(security.get("missing") or [])
        add_note(trace, "warn", "http",
                 f"security header grade {grade} — missing: {missing}")

    for cookie in security.get("cookies") or []:
        problems = []
        if not cookie.get("secure"):
            problems.append("Secure")
        if not cookie.get("samesite"):
            problems.append("SameSite")
        if problems:
            add_note(trace, "warn", "http",
                     f"cookie {cookie['name']} is missing {' and '.join(problems)}")
