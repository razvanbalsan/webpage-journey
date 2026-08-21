"""Choose the protocol the way a browser would, and record why.

A browser decides whether to try HTTP/3 from the host's HTTPS/SVCB record,
because that is the only signal available before the first connection —
Alt-Svc only helps on a return visit, which a one-shot tracer never has.
Phase 1 uses the same signal to decide whether to offer HTTP/2.

What we OFFER is our decision and is known now. What is CHOSEN is the
server's decision, known only once ALPN completes in the TLS handshake.
The section keeps them apart; claiming a protocol before the handshake
would assert something unmeasured.
"""

from wj.schema import observed, unobserved

H1 = "http/1.1"
H2 = "h2"


def choose(advertised, caps, scheme):
    """Decide what to offer over ALPN. Pure — no I/O, no context."""
    advertised = list(advertised or [])

    if scheme != "https":
        return {"advertised": advertised, "offered": [],
                "signal": "no TLS — ALPN does not apply", "unavailable": []}

    unavailable = []
    offered = []

    if H2 in advertised:
        if caps.has_lib(H2):
            offered.append(H2)
        else:
            unavailable.append(H2)

    offered.append(H1)

    signal = "HTTPS record" if advertised else "no HTTPS record"
    return {"advertised": advertised, "offered": offered,
            "signal": signal, "unavailable": unavailable}


def collect(ctx):
    dns = ctx.results.get("dns", {})
    if not dns.get("observed"):
        return unobserved(
            f"skipped because dns was not observed: {dns.get('why_not', 'unknown')}")

    decision = choose(dns.get("alpn_advertised"), ctx.caps, ctx.scheme)
    return observed(
        advertised=decision["advertised"],
        offered=decision["offered"],
        signal=decision["signal"],
        unavailable=decision["unavailable"],
        chosen=None,        # filled in by the http collector from the handshake
        attempted=[],
    )
