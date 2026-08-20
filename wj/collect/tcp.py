"""Layer 4: which address won the race, how long the handshake took, what the kernel saw."""

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from wj.schema import observed, unobserved

FAMILY = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}


def candidates_from_dns(dns_section):
    """IPv6 first, then IPv4 — the ordering RFC 8305 Happy Eyeballs prescribes."""
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

    # Linux: TCP_INFO. struct tcp_info starts with 7 u8 then u32 rto/ato/snd_mss/rcv_mss,
    # with tcpi_retransmits at offset 1 and tcpi_rtt at offset 76.
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
        retransmits = struct.unpack("B", raw[1:2])[0]
        rtt_us = struct.unpack("I", raw[76:80])[0]
        return {"rtt_ms": round(rtt_us / 1000.0, 2), "mss": mss,
                "retransmits": retransmits, "source": "TCP_INFO"}
    except (AttributeError, OSError, struct.error):
        pass

    # macOS: TCP_CONNECTION_INFO (0x106). tcpi_srtt is in milliseconds at offset 32.
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, 0x106, 104)
        srtt_ms = struct.unpack("I", raw[32:36])[0]
        return {"rtt_ms": float(srtt_ms), "mss": mss,
                "retransmits": None, "source": "TCP_CONNECTION_INFO"}
    except (OSError, struct.error):
        pass

    if mss is not None:
        return {"rtt_ms": None, "mss": mss, "retransmits": None, "source": "TCP_MAXSEG"}
    return None


def collect(ctx):
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
