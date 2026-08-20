"""Layers 1 and 2: the interface the frames leave by, and the MAC they are addressed to.

The lesson this section exists to make concrete: a packet bound for a server on
the other side of the world leaves your machine in a frame addressed to your
router's MAC, not the server's.
"""

import ipaddress
import platform
import re
import subprocess

from wj.schema import observed, unobserved

MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})")


def parse_route_get_darwin(text):
    out = {"interface": None, "gateway": None}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("gateway:"):
            out["gateway"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("interface:"):
            out["interface"] = stripped.split(":", 1)[1].strip()
    return out


def parse_ip_route_get(text):
    out = {"interface": None, "gateway": None, "src": None}
    match = re.search(r"via\s+(\S+)", text)
    if match:
        out["gateway"] = match.group(1)
    match = re.search(r"dev\s+(\S+)", text)
    if match:
        out["interface"] = match.group(1)
    match = re.search(r"src\s+(\S+)", text)
    if match:
        out["src"] = match.group(1)
    return out


def parse_ifconfig(text):
    out = {"mac": None, "ipv4": None, "mtu": None, "status": None}
    match = re.search(r"\bether\s+(\S+)", text)
    if match:
        out["mac"] = match.group(1)
    match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", text)
    if match:
        out["ipv4"] = match.group(1)
    match = re.search(r"\bmtu\s+(\d+)", text)
    if match:
        out["mtu"] = int(match.group(1))
    match = re.search(r"\bstatus:\s+(\S+)", text)
    if match:
        out["status"] = match.group(1)
    return out


def parse_ip_addr(text):
    out = {"mac": None, "ipv4": None, "mtu": None, "status": None}
    match = re.search(r"link/ether\s+(\S+)", text)
    if match:
        out["mac"] = match.group(1)
    match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", text)
    if match:
        out["ipv4"] = match.group(1)
    match = re.search(r"\bmtu\s+(\d+)", text)
    if match:
        out["mtu"] = int(match.group(1))
    match = re.search(r"\bstate\s+(\S+)", text)
    if match:
        out["status"] = match.group(1).lower()
    return out


def parse_arp(text):
    if "incomplete" in text.lower():
        return None
    match = MAC_RE.search(text)
    return match.group(1) if match else None


def parse_ip_neigh(text):
    match = re.search(r"lladdr\s+(\S+)", text)
    return match.group(1) if match else None


def parse_ipconfig_getpacket(text):
    out = {"server": None, "lease_seconds": None, "dns": []}
    match = re.search(r"server_identifier \(ip\):\s*(\S+)", text)
    if match:
        out["server"] = match.group(1)
    match = re.search(r"lease_time \(uint32\):\s*(\S+)", text)
    if match:
        try:
            out["lease_seconds"] = int(match.group(1), 16 if match.group(1).startswith("0x") else 10)
        except ValueError:
            pass
    match = re.search(r"domain_name_server \(ip_mult\):\s*\{([^}]*)\}", text)
    if match:
        out["dns"] = [ip.strip() for ip in match.group(1).split(",") if ip.strip()]
    return out


def is_private(ip):
    """True when the address is not globally routable.

    Covers RFC 1918, loopback, link-local, IPv6 ULA, and — the case that
    matters — CGNAT (100.64.0.0/10), for which the stdlib's own is_private()
    returns False. A host behind carrier-grade NAT is NAT'd, and reporting
    otherwise would be a wrong answer rather than an absent one.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not addr.is_global


def _runner():
    def run(cmd, timeout):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout

    return run


def _public_ip():
    def lookup():
        import json
        from urllib.request import Request, urlopen
        try:
            req = Request("https://ipwho.is/", headers={"User-Agent": "webpage-journey/2.0"})
            with urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode()).get("ip")
        except Exception:
            return None

    return lookup


def collect(ctx, run=None, public_ip=None):
    run = run or _runner()
    public_ip = public_ip or _public_ip()

    target_ip = (ctx.results.get("tcp", {}).get("chosen") or {}).get("ip") or "1.1.1.1"
    darwin = platform.system() == "Darwin"

    route = {"interface": None, "gateway": None, "src": None}
    if darwin and ctx.caps.has_tool("route"):
        route.update(parse_route_get_darwin(run(["route", "-n", "get", target_ip], timeout=5)))
    elif ctx.caps.has_tool("ip"):
        route.update(parse_ip_route_get(run(["ip", "route", "get", target_ip], timeout=5)))
    else:
        return unobserved("neither route nor ip is on PATH — cannot find the egress interface")

    interface = route.get("interface")
    if not interface:
        return unobserved("could not determine the egress interface for this destination")

    if darwin and ctx.caps.has_tool("ifconfig"):
        link = parse_ifconfig(run(["ifconfig", interface], timeout=5))
    elif ctx.caps.has_tool("ip"):
        link = parse_ip_addr(run(["ip", "addr", "show", interface], timeout=5))
    else:
        link = {"mac": None, "ipv4": None, "mtu": None, "status": None}

    gateway_mac = None
    gateway = route.get("gateway")
    if gateway:
        if darwin and ctx.caps.has_tool("arp"):
            gateway_mac = parse_arp(run(["arp", "-n", gateway], timeout=5))
        elif ctx.caps.has_tool("ip"):
            gateway_mac = parse_ip_neigh(run(["ip", "neigh", "show", gateway], timeout=5))

    dhcp = {"server": None, "lease_seconds": None, "dns": []}
    if darwin and ctx.caps.has_tool("ipconfig"):
        dhcp = parse_ipconfig_getpacket(run(["ipconfig", "getpacket", interface], timeout=5))

    local_ip = link.get("ipv4") or route.get("src")
    public = public_ip()

    return observed(
        interface=interface,
        link=link.get("status"),
        mtu=link.get("mtu"),
        local_ip=local_ip,
        local_mac=link.get("mac"),
        gateway_ip=gateway,
        gateway_mac=gateway_mac,
        dhcp=dhcp,
        public_ip=public,
        nat=bool(local_ip and public and is_private(local_ip) and local_ip != public),
    )
