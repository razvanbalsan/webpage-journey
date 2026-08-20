"""Per-run state every collector reads: target, budget, capabilities, prior results."""

import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Context:
    host: str
    scheme: str
    port: int
    path: str
    timeout: float
    deadline: float
    caps: object
    deep: bool = False
    privileged: bool = False
    no_path: bool = False
    geo_hops: bool = False
    results: dict = field(default_factory=dict)

    def remaining(self, now=None):
        now = time.monotonic() if now is None else now
        return max(0.0, self.deadline - now)

    def expired(self, now=None):
        return self.remaining(now) <= 0.0

    def budget_for(self, seconds, now=None):
        """The smaller of a collector's own cap and the time left in the run."""
        return min(seconds, self.remaining(now))


def parse_target(raw, forced_port, no_tls):
    """Return (host, scheme, port, path). Raises ValueError if no hostname."""
    if "://" not in raw:
        raw = ("http://" if no_tls else "https://") + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError(f"could not parse a hostname out of: {raw}")

    if no_tls:
        scheme = "http"
    elif parsed.scheme in ("http", "https"):
        scheme = parsed.scheme
    else:
        scheme = "https"

    port = forced_port or parsed.port or (80 if scheme == "http" else 443)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, scheme, port, path
