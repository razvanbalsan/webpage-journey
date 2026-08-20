"""Layer 4: which address won the race, how long the handshake took, what the kernel saw."""

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from wj.schema import observed, unobserved

FAMILY = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}

# A smoothed RTT above this is not a measurement, it is a misread struct offset.
IMPLAUSIBLE_RTT_MS = 60_000


def plausible_rtt_ms(value):
    """Return the RTT, or None when the number cannot be a round-trip time.

    Struct offsets are derived per-platform and can drift between kernel
    versions. A value that fails this check means we read the wrong field,
    and reporting nothing is correct where reporting a guess is not.
    """
    if value is None or value < 0 or value > IMPLAUSIBLE_RTT_MS:
        return None
    return value


def candidates_from_dns(dns_section):
    """IPv6 candidates listed first, then IPv4 -- ordering only, not staggering."""
    if not dns_section.get("observed"):
        return []
    records = dns_section.get("records", {})
    out = [{"ip": r["data"], "family": "ipv6"} for r in records.get("AAAA", [])]
    out += [{"ip": r["data"], "family": "ipv4"} for r in records.get("A", [])]
    return out


def connect_one(ip, family, port, timeout):
    sock = socket.socket(FAMILY[family], socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.connect((ip, port))
    except OSError as exc:
        sock.close()
        return {"ip": ip, "family": family, "connect_ms": None,
                "error": str(exc), "socket": None}
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    return {"ip": ip, "family": family, "connect_ms": elapsed,
            "error": None, "socket": sock}


def read_kernel_info(sock):
    """Smoothed RTT, MSS and retransmits, where the platform exposes them."""
    try:
        mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    except OSError:
        mss = None

    # Linux tcp_info: tcpi_retransmits is a u8 at offset 2; tcpi_rtt is a u32
    # of microseconds at offset 68.
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
        retransmits = struct.unpack("B", raw[2:3])[0]
        rtt_us = struct.unpack("I", raw[68:72])[0]
        rtt_ms = plausible_rtt_ms(round(rtt_us / 1000.0, 2))
        return {"rtt_ms": rtt_ms, "mss": mss,
                "retransmits": retransmits, "source": "TCP_INFO"}
    except (AttributeError, OSError, struct.error):
        pass

    # macOS tcp_connection_info: tcpi_srtt is a u32 of milliseconds at offset 44.
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, 0x106, 104)
        srtt_ms = struct.unpack("I", raw[44:48])[0]
        rtt_ms = plausible_rtt_ms(float(srtt_ms))
        return {"rtt_ms": rtt_ms, "mss": mss,
                "retransmits": None, "source": "TCP_CONNECTION_INFO"}
    except (OSError, struct.error):
        pass

    if mss is not None:
        return {"rtt_ms": None, "mss": mss, "retransmits": None, "source": "TCP_MAXSEG"}
    return None


def collect(ctx):
    # This is a simultaneous connect race, not Happy Eyeballs (RFC 8305): every
    # candidate starts at once via pool.map, rather than staging IPv6 first and
    # delaying IPv4 by the RFC's "connection attempt delay". The per-socket
    # timings below are real measurements either way, but with more than four
    # candidates the ThreadPoolExecutor's worker cap means later entries wait
    # behind earlier ones for a free thread -- a structural disadvantage that
    # has nothing to do with which family they belong to.
    candidates = candidates_from_dns(ctx.results.get("dns", {}))
    if not candidates:
        return unobserved("no resolved address to connect to")

    timeout = ctx.budget_for(ctx.timeout)
    with ThreadPoolExecutor(max_workers=min(4, len(candidates))) as pool:
        attempts = list(pool.map(
            lambda c: connect_one(c["ip"], c["family"], ctx.port, timeout), candidates))

    winner = None
    for attempt in attempts:
        if attempt["socket"] is not None and (
                winner is None or attempt["connect_ms"] < winner["connect_ms"]):
            if winner is not None:
                winner["socket"].close()
                winner["socket"] = None
            winner = attempt
        elif attempt["socket"] is not None:
            attempt["socket"].close()
            attempt["socket"] = None

    reported = [{k: v for k, v in a.items() if k != "socket"} for a in attempts]

    if winner is None:
        first_error = next((a["error"] for a in attempts if a["error"]), "unknown")
        section = unobserved(f"no candidate accepted a connection: {first_error}")
        section["candidates"] = reported
        return section

    sock = winner["socket"]
    local_ip, local_port = sock.getsockname()[:2]
    section = observed(
        candidates=reported,
        chosen={"ip": winner["ip"], "family": winner["family"], "port": ctx.port},
        winner_family=winner["family"],
        local={"ip": local_ip, "port": local_port},
        kernel=read_kernel_info(sock),
    )
    section["_socket"] = sock
    return section
