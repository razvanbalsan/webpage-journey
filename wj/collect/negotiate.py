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

from wj.schema import join_present, observed, unobserved

H1 = "http/1.1"
H2 = "h2"


def choose(advertised, caps, scheme, https_failed=False, https_present=False):
    """Decide what to offer over ALPN. Pure — no I/O, no context.

    An empty `advertised` list is ambiguous on its own -- wj/collect/dns.py's
    own contract is that a failed query and a genuine NoAnswer both leave the
    record list empty, and only `records_failed` tells them apart. Whether the
    HTTPS record was even queried successfully, and whether it exists at all,
    are two more distinct facts the caller has to hand in explicitly rather
    than let this function guess from the ALPN list alone -- collapsing "not
    advertised", "record has no alpn= parameter", and "could not tell" into
    one string would assert something never measured.
    """
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

    if advertised:
        signal = "HTTPS record"
    elif https_failed:
        signal = "could not tell — the HTTPS record query did not complete"
    elif https_present:
        signal = "HTTPS record published no ALPN protocol list"
    else:
        signal = "no HTTPS record"

    return {"advertised": advertised, "offered": offered,
            "signal": signal, "unavailable": unavailable}


def collect(ctx):
    dns = ctx.results.get("dns", {})
    if not dns.get("observed"):
        return unobserved(
            join_present(["skipped because dns was not observed:", dns.get("why_not")]))

    decision = choose(
        dns.get("alpn_advertised"), ctx.caps, ctx.scheme,
        https_failed="HTTPS" in (dns.get("records_failed") or []),
        https_present=bool((dns.get("records") or {}).get("HTTPS")))
    return observed(
        advertised=decision["advertised"],
        offered=decision["offered"],
        signal=decision["signal"],
        unavailable=decision["unavailable"],
        chosen=None,        # filled in by the http collector from the handshake
        attempted=[],
    )
