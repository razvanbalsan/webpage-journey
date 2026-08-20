"""Run the collectors on a budgeted dependency graph and assemble the document."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from wj import findings, schema
from wj.collect import dns as dns_collect
from wj.collect import http as http_collect
from wj.collect import local as local_collect
from wj.collect import path as path_collect
from wj.collect import tcp as tcp_collect
from wj.collect import tls as tls_collect

EXIT_OK = 0
EXIT_UNRESOLVABLE = 1
EXIT_USAGE = 2

COLLECTORS = {
    "local": local_collect.collect,
    "dns": dns_collect.collect,
    "tcp": tcp_collect.collect,
    "tls": tls_collect.collect,
    "http": http_collect.collect,
    "path": path_collect.collect,
}

# section -> the section it needs to have observed before it can run
DEPENDS_ON = {"tcp": "dns", "tls": "tcp", "http": "tcp", "path": "tcp"}


def _run_one(name, collector, ctx, now):
    if ctx.expired(now()):
        return schema.unobserved("budget exhausted")

    dependency = DEPENDS_ON.get(name)
    if dependency and not ctx.results.get(dependency, {}).get("observed"):
        return schema.unobserved(
            f"skipped because {dependency} was not observed")

    try:
        return collector(ctx)
    except Exception as exc:
        return schema.unobserved(f"{type(exc).__name__}: {exc}")


def build_timings(trace):
    dns = trace.get("dns", {})
    tcp = trace.get("tcp", {})
    tls = trace.get("tls", {})
    http = trace.get("http", {})
    final = http.get("final") or {}

    dns_ms = (dns.get("timing_ms") or {}).get("cold", 0.0) if dns.get("observed") else 0.0
    chosen_ip = (tcp.get("chosen") or {}).get("ip")
    tcp_ms = 0.0
    for candidate in tcp.get("candidates") or []:
        if candidate.get("ip") == chosen_ip and candidate.get("connect_ms"):
            tcp_ms = candidate["connect_ms"]
    tls_ms = tls.get("handshake_ms", 0.0) if tls.get("observed") else 0.0
    ttfb_ms = final.get("ttfb_ms") or 0.0
    download_ms = max((final.get("total_ms") or 0.0) - ttfb_ms, 0.0)

    rows = []
    cursor = 0.0
    for label, duration in (("DNS", dns_ms), ("TCP", tcp_ms), ("TLS", tls_ms),
                            ("TTFB", ttfb_ms), ("Download", download_ms)):
        rows.append({"label": label, "start_ms": round(cursor, 1),
                     "end_ms": round(cursor + duration, 1)})
        cursor += duration

    return {"waterfall": rows, "total_ms": round(cursor, 1)}


def close_sockets(trace):
    for name in ("tls", "tcp"):
        sock = trace.get(name, {}).get("_socket")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def strip_private(trace):
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if not str(k).startswith("_")}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    return clean(trace)


def orchestrate(ctx, collectors=None, now=time.monotonic):
    collectors = collectors or COLLECTORS

    trace = schema.new_trace(
        target={"input": f"{ctx.scheme}://{ctx.host}{ctx.path}", "host": ctx.host,
                "scheme": ctx.scheme, "port": ctx.port, "path": ctx.path},
        tool_version=_tool_version(),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        capabilities=ctx.caps.to_dict(),
        redacted=False,
    )

    # local is independent of everything; dns gates the rest.
    with ThreadPoolExecutor(max_workers=2) as pool:
        local_future = pool.submit(_run_one, "local", collectors["local"], ctx, now)
        ctx.results["dns"] = _run_one("dns", collectors["dns"], ctx, now)
        ctx.results["local"] = local_future.result()

    ctx.results["tcp"] = _run_one("tcp", collectors["tcp"], ctx, now)

    # path runs on its own socket, concurrently with the tls -> http chain.
    with ThreadPoolExecutor(max_workers=2) as pool:
        path_future = pool.submit(_run_one, "path", collectors["path"], ctx, now)
        ctx.results["tls"] = _run_one("tls", collectors["tls"], ctx, now)
        ctx.results["http"] = _run_one("http", collectors["http"], ctx, now)
        ctx.results["path"] = path_future.result()

    for name in schema.SECTIONS:
        trace[name] = ctx.results.get(name, schema.unobserved("not collected"))

    trace["timings"] = build_timings(trace)
    findings.analyse(trace)
    trace["osi"] = schema.build_osi(trace)
    return trace


def _tool_version():
    from wj import __version__
    return __version__
