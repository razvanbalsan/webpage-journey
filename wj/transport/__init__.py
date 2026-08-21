"""Framing implementations, one per protocol, behind a single contract.

Each module exposes `fetcher(ctx) -> fetch(url, connection) -> response dict`,
where the response dict always has the same keys regardless of protocol:
protocol, status, reason, headers, body, ttfb_ms, total_ms, wire_bytes.
"""

from wj.transport import h1, h2

TRANSPORTS = {"http/1.1": h1, "h2": h2}
