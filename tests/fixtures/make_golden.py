"""Regenerate the golden trace documents. Deterministic — no network involved."""

import json
from pathlib import Path

from wj import capabilities, redact, schema
from wj.collect import negotiate as negotiate_collect
from wj.collect import tls as tls_collect
from wj.context import Context
from wj.run import orchestrate
from wj.transport.h2 import _decoded_header_size

OUT = Path(__file__).parent / "golden"


def ctx_for(host, tools):
    caps = capabilities.Capabilities(
        libs={"dns": True, "cryptography": True, "h2": True},
        tools=tools, privileged=False, can_sudo=False)
    return Context(host=host, scheme="https", port=443, path="/",
                   timeout=8.0, deadline=1e9, caps=caps, results={})


def collectors(cdn=True, with_path=True, with_local=True):
    def local(ctx):
        if not with_local:
            return schema.unobserved(
                "neither route nor ip is on PATH — cannot find the egress interface")
        return schema.observed(
            interface="en0", link="active", mtu=1500,
            local_ip="192.168.1.23", local_mac="aa:bb:cc:dd:ee:ff",
            gateway_ip="192.168.1.1", gateway_mac="11:22:33:44:55:66",
            dhcp={"server": "192.168.1.1", "lease_seconds": 86400,
                  "dns": ["192.168.1.1"]},
            public_ip="81.180.20.7", nat=True)

    def dns(ctx):
        return schema.observed(
            records={"A": [{"data": "104.16.132.229", "ttl": 300}],
                     "AAAA": [{"data": "2606:4700::6810:84e5", "ttl": 300}] if cdn else [],
                     "CNAME": [], "MX": [], "NS": [{"data": "ns1.example.net", "ttl": 3600}],
                     "TXT": [{"data": "v=spf1 -all", "ttl": 3600}],
                     "SOA": [], "CAA": [{"data": '0 issue "letsencrypt.org"', "ttl": 3600}],
                     "HTTPS": [{"data": '1 . alpn="h3,h2"', "ttl": 300}] if cdn else []},
            records_failed=[],
            resolver={"servers": ["1.1.1.1"], "source": "scutil"},
            dnssec="secure" if cdn else "insecure",
            delegation=[{"level": "root", "server": "198.41.0.4",
                         "referral": ["a.gtld-servers.net"], "answer": []},
                        {"level": "tld", "server": "192.5.6.30",
                         "referral": ["ns1.example.net"], "answer": []},
                        {"level": "authoritative", "server": "203.0.113.9",
                         "referral": [], "answer": ["ns1.example.net"]}],
            alpn_advertised=["h3", "h2"] if cdn else [],
            ech=False, timing_ms={"cold": 41.2, "warm": 1.1})

    def tcp(ctx):
        return schema.observed(
            candidates=[{"ip": "104.16.132.229", "family": "ipv4",
                         "connect_ms": 12.4, "error": None}],
            chosen={"ip": "104.16.132.229", "family": "ipv4", "port": 443},
            winner_family="ipv4", local={"ip": "192.168.1.23", "port": 54213},
            kernel={"rtt_ms": 12.4, "mss": 1460, "retransmits": 0, "source": "TCP_INFO"})

    def tls(ctx):
        # alpn="http/1.1" models a handshake that lands on HTTP/1.1 even
        # though dns.alpn_advertised (above) lists "h2" -- a real, legitimate
        # outcome: what a host advertises in its HTTPS record and what a
        # given handshake actually selects are two separate measurements
        # (see wj/collect/http.py's transport_for()). The http() stub below
        # propagates this alpn into negotiation.chosen the same way the real
        # collector does, rather than leaving it unmeasured, so this fixture
        # cannot silently drift back into an ALPN/negotiated contradiction.
        # For a trace that actually negotiates h2, see h2_collectors() below.
        #
        # The chain has a leaf and its issuing intermediate, matching what
        # -showcerts / get_verified_chain() actually return, so trust_root
        # (computed from chain[-1]) is populated for real.
        #
        # issuer_cn is a REAL bare CA code (verified live against letsencrypt.org's
        # own certificate on 2026-08-20: its issuer CN is a bare code like this,
        # never the CAA domain spelled out in the CN itself — the earlier
        # "R3 (letsencrypt.org)" fixture routed around C3 instead of exposing it,
        # per I8). caa_match is computed by calling the REAL caa_allows() below
        # (not hand-derived) so this fixture cannot drift from what the function
        # actually returns — see test_golden.py's fixture-fidelity test.
        if cdn:
            issuer_cn, issuer_org = "R11", "Let's Encrypt"
            intermediate_issuer_cn = "ISRG Root X1"
            leaf_ocsp, intermediate_ocsp = ["http://r11.o.lencr.org"], ["http://x1.i.lencr.org/"]
        else:
            issuer_cn, issuer_org = "DigiCert Global G2 TLS RSA SHA256 2020 CA1", "DigiCert Inc"
            intermediate_issuer_cn = "DigiCert Global Root G2"
            leaf_ocsp, intermediate_ocsp = ["http://ocsp.digicert.com"], ["http://ocsp.digicert.com"]
        caa_records = [{"data": '0 issue "letsencrypt.org"', "ttl": 3600}]
        caa_match = tls_collect.caa_allows(caa_records, issuer_cn, issuer_org)
        return schema.observed(
            version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256",
            alpn="http/1.1", handshake_ms=38.2,
            chain=[{"subject_cn": ctx.host, "issuer_cn": issuer_cn, "issuer_org": issuer_org,
                    "not_before": "2026-06-01T00:00:00+00:00",
                    "not_after": "2026-08-30T00:00:00+00:00", "days_left": 10,
                    "key": {"type": "EC", "bits": 256}, "sig_algo": "ecdsa-with-SHA256",
                    "sans": [ctx.host, f"www.{ctx.host}"], "scts": 2,
                    "ocsp": leaf_ocsp, "is_ca": False, "unmeasured": []},
                   {"subject_cn": issuer_cn, "issuer_cn": intermediate_issuer_cn, "issuer_org": None,
                    "not_before": "2024-03-13T00:00:00+00:00",
                    "not_after": "2027-03-13T00:00:00+00:00", "days_left": 205,
                    "key": {"type": "RSA", "bits": 2048}, "sig_algo": "sha256WithRSAEncryption",
                    "sans": [], "scts": 0,
                    "ocsp": intermediate_ocsp, "is_ca": True, "unmeasured": []}],
            chain_unparsed=0,
            trust_root=issuer_cn, verified=True, caa_match=caa_match,
            resumption={"tested": False}, legacy_versions_accepted=[])

    def http(ctx):
        # Requests always go out as literal HTTP/1.1 text over the socket
        # (wj/collect/http.py), so the response's own protocol string is always
        # "HTTP/1.1" — a CDN in front of the origin doesn't change that.

        # Mirrors wj/collect/http.py's own wiring: chosen is filled from the
        # handshake's ALPN result, not asserted independently -- I1 found
        # every golden carrying "chosen": null because this stub never did
        # this, contradicting the tls.alpn sitting right next to it once the
        # page rendered both.
        alpn = (ctx.results.get("tls") or {}).get("alpn")
        negotiation = ctx.results.get("negotiation")
        if alpn and isinstance(negotiation, dict) and negotiation.get("observed"):
            negotiation["chosen"] = alpn

        security = (
            {"grade": "B",
             "present": {"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                         "X-Content-Type-Options": "nosniff",
                         "Referrer-Policy": "strict-origin-when-cross-origin",
                         "Permissions-Policy": "geolocation=()",
                         "Cross-Origin-Opener-Policy": "same-origin"},
             "missing": ["Content-Security-Policy"],
             "cookies": [{"name": "session", "secure": True,
                          "httponly": True, "samesite": "Lax"}],
             "scheme": "https"}
            if cdn else
            {"grade": "F", "present": {},
             "missing": ["Strict-Transport-Security", "Content-Security-Policy",
                         "X-Content-Type-Options", "Referrer-Policy",
                         "Permissions-Policy", "Cross-Origin-Opener-Policy"],
             "cookies": [{"name": "session", "secure": True,
                          "httponly": True, "samesite": "Lax"}],
             "scheme": "https"})
        return schema.observed(
            # The redirect crosses from plain http:// (port 80) to https://
            # (port 443) -- a scheme change, so wj/collect/http.py resets the
            # socket for the next hop regardless of protocol. Both legs are
            # explicitly measured as fresh (connection_reused: False), not
            # merely absent -- an absent value reads as "not measured", not
            # as "not reused" (see build_osi's L5 derivation).
            hops=[{"url": f"http://{ctx.host}/", "status": 301,
                   "location": f"https://{ctx.host}/", "protocol": "HTTP/1.1",
                   "ttfb_ms": 40.1, "connection_reused": False, "stream_id": None}],
            redirect_limit_reached=False,
            final={"url": f"https://{ctx.host}/", "status": 200, "reason": "OK",
                   "protocol": "HTTP/1.1",
                   # decode_body() derives encoding solely from Content-Encoding
                   # (wj/collect/http.py) — this header must be present for the
                   # encoding/ratio/byte counts below to be reachable at all.
                   "headers": [["content-type", "text/html; charset=utf-8"],
                               ["content-encoding", "gzip"],
                               ["cache-control", "max-age=300"]],
                   "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000,
                   "decoded_bytes": 61000, "encoding": "gzip", "ratio": 4.36,
                   "content_type": "text/html", "connection_reused": False},
            cache={"state": "HIT", "age": 412, "header": "cf-cache-status",
                   "directives": "max-age=300"} if cdn else
                  {"state": None, "age": None, "header": None, "directives": "max-age=300"},
            cdn="Cloudflare" if cdn else None,
            security=security,
            conditional={"tested": False})

    def path_collect(ctx):
        if not with_path:
            return schema.unobserved("traceroute not on PATH")
        return schema.observed(
            source="traceroute",
            # "prefix" (not "as_name" — I3): Cymru's TXT answer is
            # "AS | BGP Prefix | CC | Registry | Allocated"; this field is the
            # announced BGP prefix, not the AS's name.
            hops=[{"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan",
                   "rtt_ms": 1.2, "asn": None, "prefix": None},
                  {"ttl": 2, "ip": None, "rdns": None, "rtt_ms": None,
                   "asn": None, "prefix": None},
                  {"ttl": 3, "ip": "203.0.113.9", "rdns": "ae-1.border.example.net",
                   "rtt_ms": 14.5, "asn": 8708, "prefix": "203.0.113.0/24"},
                  {"ttl": 4, "ip": "104.16.132.229", "rdns": None,
                   "rtt_ms": 15.0, "asn": 13335, "prefix": "104.16.0.0/12"}],
            asn_path=[8708, 13335], path_mtu=None)

    return {"local": local, "dns": dns, "negotiation": negotiate_collect.collect,
            "tcp": tcp, "tls": tls, "http": http, "path": path_collect}


def h2_collectors():
    """A host that both advertises and actually negotiates h2 (unlike
    collectors() above, where the handshake lands on http/1.1 despite the
    advertisement) -- I2: no golden fixture exercised connection_reused: true
    anywhere in hops[], because HTTP/1.1 always opens a fresh connection per
    hop (see wj/transport/h1.py). A same-origin HTTP/2 redirect chain reuses
    the one TLS connection for every hop after the first, which is exactly
    what a real h2 transport (wj/transport/h2.py) measures via _wj_h2 on the
    socket -- modelled here, not hand-waved.
    """

    def local(ctx):
        return schema.observed(
            interface="en0", link="active", mtu=1500,
            local_ip="192.168.1.23", local_mac="aa:bb:cc:dd:ee:ff",
            gateway_ip="192.168.1.1", gateway_mac="11:22:33:44:55:66",
            dhcp={"server": "192.168.1.1", "lease_seconds": 86400,
                  "dns": ["192.168.1.1"]},
            public_ip="81.180.20.7", nat=True)

    def dns(ctx):
        return schema.observed(
            records={"A": [{"data": "151.101.65.195", "ttl": 300}],
                     "AAAA": [{"data": "2a04:4e42::645", "ttl": 300}],
                     "CNAME": [], "MX": [], "NS": [{"data": "ns1.example.net", "ttl": 3600}],
                     "TXT": [{"data": "v=spf1 -all", "ttl": 3600}],
                     "SOA": [], "CAA": [{"data": '0 issue "letsencrypt.org"', "ttl": 3600}],
                     "HTTPS": [{"data": '1 . alpn="h2"', "ttl": 300}]},
            records_failed=[],
            resolver={"servers": ["1.1.1.1"], "source": "scutil"},
            dnssec="secure",
            delegation=[{"level": "root", "server": "198.41.0.4",
                         "referral": ["a.gtld-servers.net"], "answer": []},
                        {"level": "tld", "server": "192.5.6.30",
                         "referral": ["ns1.example.net"], "answer": []},
                        {"level": "authoritative", "server": "203.0.113.9",
                         "referral": [], "answer": ["ns1.example.net"]}],
            alpn_advertised=["h2"],
            ech=False, timing_ms={"cold": 39.5, "warm": 1.0})

    def tcp(ctx):
        return schema.observed(
            candidates=[{"ip": "151.101.65.195", "family": "ipv4",
                         "connect_ms": 11.8, "error": None}],
            chosen={"ip": "151.101.65.195", "family": "ipv4", "port": 443},
            winner_family="ipv4", local={"ip": "192.168.1.23", "port": 54290},
            kernel={"rtt_ms": 11.8, "mss": 1460, "retransmits": 0, "source": "TCP_INFO"})

    def tls(ctx):
        # Same real, live-verified CA identity as collectors()'s tls() above
        # (see its comment) -- alpn="h2" here is what actually lands, unlike
        # there, because caa_match is still computed by calling the real
        # caa_allows() rather than hand-derived.
        issuer_cn, issuer_org = "R11", "Let's Encrypt"
        intermediate_issuer_cn = "ISRG Root X1"
        leaf_ocsp, intermediate_ocsp = ["http://r11.o.lencr.org"], ["http://x1.i.lencr.org/"]
        caa_records = [{"data": '0 issue "letsencrypt.org"', "ttl": 3600}]
        caa_match = tls_collect.caa_allows(caa_records, issuer_cn, issuer_org)
        return schema.observed(
            version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256",
            alpn="h2", handshake_ms=35.6,
            chain=[{"subject_cn": ctx.host, "issuer_cn": issuer_cn, "issuer_org": issuer_org,
                    "not_before": "2026-07-01T00:00:00+00:00",
                    "not_after": "2026-11-01T00:00:00+00:00", "days_left": 73,
                    "key": {"type": "EC", "bits": 256}, "sig_algo": "ecdsa-with-SHA256",
                    "sans": [ctx.host], "scts": 2,
                    "ocsp": leaf_ocsp, "is_ca": False, "unmeasured": []},
                   {"subject_cn": issuer_cn, "issuer_cn": intermediate_issuer_cn, "issuer_org": None,
                    "not_before": "2024-03-13T00:00:00+00:00",
                    "not_after": "2027-03-13T00:00:00+00:00", "days_left": 205,
                    "key": {"type": "RSA", "bits": 2048}, "sig_algo": "sha256WithRSAEncryption",
                    "sans": [], "scts": 0,
                    "ocsp": intermediate_ocsp, "is_ca": True, "unmeasured": []}],
            chain_unparsed=0,
            trust_root=issuer_cn, verified=True, caa_match=caa_match,
            resumption={"tested": False}, legacy_versions_accepted=[])

    def http(ctx):
        # Same chosen-propagation wiring as collectors()'s http() stub above.
        alpn = (ctx.results.get("tls") or {}).get("alpn")
        negotiation = ctx.results.get("negotiation")
        if alpn and isinstance(negotiation, dict) and negotiation.get("observed"):
            negotiation["chosen"] = alpn

        security = {
            "grade": "A",
            "present": {"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                        "Content-Security-Policy": "default-src 'self'",
                        "X-Content-Type-Options": "nosniff",
                        "Referrer-Policy": "strict-origin-when-cross-origin",
                        "Permissions-Policy": "geolocation=()",
                        "Cross-Origin-Opener-Policy": "same-origin"},
            "missing": [],
            "cookies": [{"name": "session", "secure": True,
                         "httponly": True, "samesite": "Strict"}],
            "scheme": "https"}

        final_headers = [["content-type", "text/html; charset=utf-8"],
                         ["content-encoding", "gzip"],
                         ["cache-control", "max-age=600"]]
        # decoded is computed by calling the real _decoded_header_size()
        # against these same headers (same discipline as tls()'s caa_match
        # above), not hand-derived -- wire is this tool's own byte-cost
        # measurement of the compressed HEADERS frame, which nothing in this
        # stub can reproduce without a real HPACK encoder on a real
        # connection, so it is chosen only to be honestly smaller than
        # decoded, per wj/transport/h2.py's _decoded_header_size docstring.
        decoded_header_size = _decoded_header_size(final_headers)

        # Two same-origin redirects, all over one HTTP/2 connection: the
        # first request opens it (connection_reused: False -- it is the TLS
        # handshake's own connection, not a new one this fetch opened), and
        # every request after that reuses it (see wj/transport/h2.py's
        # _connection_state / hasattr(sock, "_wj_h2") -- exactly what h1 can
        # never report True, since every h1 hop sends Connection: close).
        # Stream ids are client-initiated and odd, incrementing by 2 per
        # request on the connection (RFC 7540 §5.1.1), matching
        # h2.connection.H2Connection.get_next_available_stream_id().
        return schema.observed(
            hops=[{"url": f"https://{ctx.host}/", "status": 301,
                   "location": f"https://{ctx.host}/en/", "protocol": "HTTP/2",
                   "ttfb_ms": 22.4, "connection_reused": False, "stream_id": 1},
                  {"url": f"https://{ctx.host}/en/", "status": 302,
                   "location": f"https://{ctx.host}/en/index.html", "protocol": "HTTP/2",
                   "ttfb_ms": 9.8, "connection_reused": True, "stream_id": 3}],
            redirect_limit_reached=False,
            final={"url": f"https://{ctx.host}/en/index.html", "status": 200, "reason": None,
                   "protocol": "HTTP/2", "headers": final_headers,
                   "ttfb_ms": 10.5, "total_ms": 26.0, "wire_bytes": 9800,
                   "decoded_bytes": 41160, "encoding": "gzip", "ratio": 4.2,
                   "content_type": "text/html",
                   "header_bytes": {"wire": 52, "decoded": decoded_header_size},
                   "connection_reused": True},
            cache={"state": None, "age": None, "header": None, "directives": "max-age=600"},
            cdn=None,
            security=security,
            conditional={"tested": False})

    def path_collect(ctx):
        return schema.observed(
            source="traceroute",
            hops=[{"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan",
                   "rtt_ms": 1.1, "asn": None, "prefix": None},
                  {"ttl": 2, "ip": "203.0.113.20", "rdns": "ae-2.border.example.net",
                   "rtt_ms": 13.0, "asn": 54113, "prefix": "203.0.113.0/24"},
                  {"ttl": 3, "ip": "151.101.65.195", "rdns": None,
                   "rtt_ms": 11.9, "asn": 54113, "prefix": "151.101.0.0/16"}],
            asn_path=[54113], path_mtu=None)

    return {"local": local, "dns": dns, "negotiation": negotiate_collect.collect,
            "tcp": tcp, "tls": tls, "http": http, "path": path_collect}


GENERATED_AT = "2026-08-20T09:31:02+00:00"  # keep the fixtures stable
TOOLS = {"traceroute": "/usr/sbin/traceroute", "route": "/sbin/route",
         "ifconfig": "/sbin/ifconfig", "arp": "/usr/sbin/arp"}


def specs():
    """name -> (ctx, collectors_map) for every golden fixture the orchestrator
    builds directly (cdn-host-redacted.json is derived from cdn-host.json's
    trace instead, via write_redacted() below, not listed here).

    The single source both __main__ and test_golden.py's regenerate-and-
    compare test build from -- I3: without this, "regenerate the fixture"
    would mean two independently hand-maintained recipes that could drift
    from each other exactly the way the fixtures once drifted from what
    wj/collect/http.py itself computes.
    """
    return {
        "cdn-host.json": (ctx_for("example.com", TOOLS), collectors()),
        "plain-host.json": (ctx_for("plain.example.net", TOOLS), collectors(cdn=False)),
        "partial-unprivileged.json": (ctx_for("example.com", {}),
                                      collectors(with_path=False, with_local=False)),
        "h2-host.json": (ctx_for("h2.example.net", TOOLS), h2_collectors()),
    }


def write(name, ctx, collectors_map):
    trace = orchestrate(ctx, collectors=collectors_map)
    trace["generated_at"] = GENERATED_AT
    problems = schema.validate(trace)
    assert not problems, problems
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(json.dumps(trace, indent=2, default=str) + "\n")
    print(f"wrote {name}")
    return trace


def write_redacted(name, trace):
    # I5: no golden fixture exercised the page's redaction-rendering path at
    # all -- every one carried "redacted": false. Produced by running the real
    # redact.redact_trace() over an already-written fixture, never by hand.
    redacted = redact.redact_trace(trace)
    problems = schema.validate(redacted)
    assert not problems, problems
    (OUT / name).write_text(json.dumps(redacted, indent=2, default=str) + "\n")
    print(f"wrote {name}")


if __name__ == "__main__":
    traces = {name: write(name, ctx, collectors_map)
              for name, (ctx, collectors_map) in specs().items()}
    write_redacted("cdn-host-redacted.json", traces["cdn-host.json"])
