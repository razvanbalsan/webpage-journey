"""Turn a completed trace into the short list of things worth acting on."""

from wj.collect.tls import grade_expiry
from wj.schema import add_note

POOR_GRADES = ("D", "E", "F")


def analyse(trace):
    _analyse_dns(trace)
    _analyse_tls(trace)
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

    dns = trace.get("dns", {})
    advertised = [p for p in dns.get("alpn_advertised") or [] if p != "http/1.1"]
    if advertised:
        add_note(trace, "info", "tls",
                 "this host advertises " + ", ".join(advertised) +
                 ", but this tool speaks HTTP/1.1 and negotiated http/1.1")


def _analyse_http(trace):
    http = trace.get("http", {})
    if not http.get("observed"):
        return

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
