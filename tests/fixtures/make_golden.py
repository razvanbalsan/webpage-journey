"""Regenerate the golden trace documents. Deterministic — no network involved."""

import json
from pathlib import Path

from wj import capabilities, schema
from wj.context import Context
from wj.run import orchestrate

OUT = Path(__file__).parent / "golden"


def ctx_for(host, tools):
    caps = capabilities.Capabilities(
        libs={"dns": True, "cryptography": True, "h2": False},
        tools=tools, privileged=False, can_sudo=False)
    return Context(host=host, scheme="https", port=443, path="/",
                   timeout=8.0, deadline=1e9, caps=caps, results={})


def collectors(cdn=True, with_path=True, with_local=True):
    def local(ctx):
        if not with_local:
            return schema.unobserved("neither route nor ip is on PATH")
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
        # The tool offers only HTTP/1.1 over ALPN (wj/collect/tls.py), so no real
        # trace can ever negotiate "h2" here — what the host *advertises* lives in
        # dns.alpn_advertised instead. The chain has a leaf and its issuing
        # intermediate, matching what -showcerts / get_verified_chain() actually
        # return, so trust_root (computed from chain[-1]) is populated for real.
        return schema.observed(
            version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256",
            alpn="http/1.1", handshake_ms=38.2,
            chain=[{"subject_cn": ctx.host, "issuer_cn": "R3",
                    "not_before": "2026-06-01T00:00:00+00:00",
                    "not_after": "2026-08-30T00:00:00+00:00", "days_left": 10,
                    "key": {"type": "EC", "bits": 256}, "sig_algo": "ecdsa-with-SHA256",
                    "sans": [ctx.host, f"www.{ctx.host}"], "scts": 2,
                    "ocsp": ["http://r3.o.lencr.org"], "is_ca": False},
                   {"subject_cn": "R3", "issuer_cn": "ISRG Root X1",
                    "not_before": "2024-03-13T00:00:00+00:00",
                    "not_after": "2027-03-13T00:00:00+00:00", "days_left": 205,
                    "key": {"type": "RSA", "bits": 2048}, "sig_algo": "sha256WithRSAEncryption",
                    "sans": [], "scts": 0,
                    "ocsp": ["http://x1.i.lencr.org/"], "is_ca": True}],
            trust_root="R3", verified=True, caa_match=True,
            resumption={"tested": False}, legacy_versions_accepted=[])

    def http(ctx):
        # Requests always go out as literal HTTP/1.1 text over the socket
        # (wj/collect/http.py), so the response's own protocol string is always
        # "HTTP/1.1" — a CDN in front of the origin doesn't change that.
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
            hops=[{"url": f"http://{ctx.host}/", "status": 301,
                   "location": f"https://{ctx.host}/", "protocol": "HTTP/1.1",
                   "ttfb_ms": 40.1}],
            redirect_limit_reached=False,
            final={"url": f"https://{ctx.host}/", "status": 200, "reason": "OK",
                   "protocol": "HTTP/1.1",
                   "headers": [["content-type", "text/html; charset=utf-8"],
                               ["cache-control", "max-age=300"]],
                   "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000,
                   "decoded_bytes": 61000, "encoding": "gzip", "ratio": 4.36,
                   "content_type": "text/html"},
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
            hops=[{"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan",
                   "rtt_ms": 1.2, "asn": None, "as_name": None},
                  {"ttl": 2, "ip": None, "rdns": None, "rtt_ms": None,
                   "asn": None, "as_name": None},
                  {"ttl": 3, "ip": "203.0.113.9", "rdns": "ae-1.border.example.net",
                   "rtt_ms": 14.5, "asn": 8708, "as_name": "203.0.113.0/24"},
                  {"ttl": 4, "ip": "104.16.132.229", "rdns": None,
                   "rtt_ms": 15.0, "asn": 13335, "as_name": "104.16.0.0/12"}],
            asn_path=[8708, 13335], path_mtu=None)

    return {"local": local, "dns": dns, "tcp": tcp, "tls": tls,
            "http": http, "path": path_collect}


def write(name, ctx, collectors_map):
    trace = orchestrate(ctx, collectors=collectors_map)
    trace["generated_at"] = "2026-08-20T09:31:02+00:00"  # keep the fixtures stable
    problems = schema.validate(trace)
    assert not problems, problems
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(json.dumps(trace, indent=2, default=str) + "\n")
    print(f"wrote {name}")


if __name__ == "__main__":
    tools = {"traceroute": "/usr/sbin/traceroute", "route": "/sbin/route",
             "ifconfig": "/sbin/ifconfig", "arp": "/usr/sbin/arp"}
    write("cdn-host.json", ctx_for("example.com", tools), collectors())
    write("plain-host.json", ctx_for("plain.example.net", tools),
          collectors(cdn=False))
    write("partial-unprivileged.json", ctx_for("example.com", {}),
          collectors(with_path=False, with_local=False))
