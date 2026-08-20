#!/usr/bin/env python3
"""
webpage_journey.py — show, with REAL data, everything that happens when a
browser requests a webpage: DNS resolution, TCP connect, TLS handshake, and
the HTTP request/response — for any domain you give it.

This is the hands-on companion to the interactive HTML walkthrough. The
browser page can show you real DNS records (via DNS-over-HTTPS, which a
browser is allowed to call), but browsers deliberately do NOT expose raw
TCP/TLS internals to JavaScript, for security reasons. This script opens
real sockets, so it can show you the parts the browser can't: actual TCP
connect timing, the actual negotiated TLS version/cipher, the actual
certificate presented, and the actual HTTP response.

Usage:
    python3 webpage_journey.py example.com
    python3 webpage_journey.py https://example.com/some/path
    python3 webpage_journey.py example.com --port 8443
    python3 webpage_journey.py example.com --no-tls        # plain HTTP on port 80
    python3 webpage_journey.py example.com --timeout 10

Dependencies:
    pip install rich dnspython
    (dnspython is optional — without it, MX/NS/TXT/CNAME lookups are skipped
    and only A/AAAA records are shown, via the standard library.)
"""

import argparse
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.text import Text
    from rich import box
except ImportError:
    print("This script needs the 'rich' library for its output.\n\n    pip install rich\n\nOptionally also install dnspython for MX/NS/TXT/CNAME records:\n\n    pip install dnspython\n")
    sys.exit(1)

try:
    import dns.resolver  # type: ignore
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

console = Console()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def parse_target(raw, forced_port, no_tls):
    if "://" not in raw:
        raw = ("http://" if no_tls else "https://") + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        console.print(f"[bold red]Couldn't parse a hostname out of:[/bold red] {raw}")
        sys.exit(1)
    scheme = "http" if no_tls else parsed.scheme if parsed.scheme in ("http", "https") else "https"
    port = forced_port or parsed.port or (80 if scheme == "http" else 443)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, scheme, port, path


def ms(seconds):
    return round(seconds * 1000, 1)


# --------------------------------------------------------------------------
# Step 1 — DNS resolution
# --------------------------------------------------------------------------

def resolve_dns(host, timeout):
    t0 = time.perf_counter()
    records = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
    errors = []

    try:
        for res in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = res[4][0]
            if ip not in records["A"]:
                records["A"].append(ip)
    except socket.gaierror as e:
        errors.append(f"A lookup failed: {e}")

    try:
        for res in socket.getaddrinfo(host, None, socket.AF_INET6):
            ip = res[4][0]
            if ip not in records["AAAA"]:
                records["AAAA"].append(ip)
    except socket.gaierror:
        pass  # plenty of domains simply have no AAAA record — not an error

    if HAVE_DNSPYTHON:
        # Run the extra record-type lookups in parallel and cap each one's
        # lifetime tightly — a single slow/unanswered query (e.g. no TXT
        # record) shouldn't make the whole trace wait the full timeout
        # four times over.
        per_query_lifetime = min(timeout, 3.0)
        resolver = dns.resolver.Resolver()
        resolver.timeout = per_query_lifetime
        resolver.lifetime = per_query_lifetime

        def lookup(rtype):
            try:
                answer = resolver.resolve(host, rtype)
                return rtype, [str(r).strip('"') for r in answer]
            except Exception:
                return rtype, []

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(lookup, rtype) for rtype in ("CNAME", "MX", "NS", "TXT")]
            for future in as_completed(futures):
                rtype, values = future.result()
                records[rtype] = values

    dns_time_ms = ms(time.perf_counter() - t0)
    return records, dns_time_ms, errors


def geolocate(ip, timeout):
    try:
        req = Request(f"https://ipwho.is/{ip}", headers={"User-Agent": "webpage-journey-script/1.0"})
        with urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        if data.get("success", True):
            return data
    except (URLError, TimeoutError, OSError, ValueError):
        pass
    return None


# --------------------------------------------------------------------------
# Step 2 & 3 — TCP connect + TLS handshake
# --------------------------------------------------------------------------

def tcp_connect(ip, port, timeout):
    t0 = time.perf_counter()
    sock = socket.create_connection((ip, port), timeout=timeout)
    connect_ms = ms(time.perf_counter() - t0)
    local_ip, local_port = sock.getsockname()[:2]
    return sock, connect_ms, local_port


def tls_handshake(sock, host, timeout):
    ctx = ssl.create_default_context()
    sock.settimeout(timeout)
    t0 = time.perf_counter()
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
    handshake_ms = ms(time.perf_counter() - t0)
    cert = tls_sock.getpeercert()
    return tls_sock, cert, tls_sock.version(), tls_sock.cipher(), handshake_ms


def cert_subject_field(cert, field):
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == field:
                return value
    return None


# --------------------------------------------------------------------------
# Step 4 & 5 — raw HTTP request / response over the socket we already opened
# --------------------------------------------------------------------------

def http_roundtrip(sock, host, path, timeout):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: webpage-journey-script/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    sock.settimeout(timeout)
    t0 = time.perf_counter()
    sock.sendall(request)

    chunks = []
    first_byte_ms = None
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        if first_byte_ms is None:
            first_byte_ms = ms(time.perf_counter() - t0)
        chunks.append(data)
    total_ms = ms(time.perf_counter() - t0)
    raw = b"".join(chunks)

    header_blob, _, body = raw.partition(b"\r\n\r\n")
    lines = header_blob.decode(errors="replace").split("\r\n")
    status_line = lines[0] if lines else ""
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))

    return request.decode(), status_line, headers, len(body), first_byte_ms, total_ms


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_dns(host, records, dns_time_ms, errors, geo):
    tree = Tree(f"[bold]{host}[/bold]  [dim]({dns_time_ms} ms)[/dim]")
    if records["A"]:
        branch = tree.add("[cyan]A[/cyan]  (IPv4)")
        for ip in records["A"]:
            branch.add(ip)
    if records["AAAA"]:
        branch = tree.add("[cyan]AAAA[/cyan]  (IPv6)")
        for ip in records["AAAA"]:
            branch.add(ip)
    if records["CNAME"]:
        branch = tree.add("[cyan]CNAME[/cyan]")
        for r in records["CNAME"]:
            branch.add(r)
    if records["MX"]:
        branch = tree.add("[cyan]MX[/cyan]")
        for r in records["MX"]:
            branch.add(r)
    if records["NS"]:
        branch = tree.add("[cyan]NS[/cyan]")
        for r in records["NS"]:
            branch.add(r)
    if records["TXT"]:
        branch = tree.add(f"[cyan]TXT[/cyan]  ({len(records['TXT'])} records)")
        for r in records["TXT"][:5]:
            branch.add(r if len(r) < 90 else r[:87] + "...")
        if len(records["TXT"]) > 5:
            branch.add(f"[dim]... {len(records['TXT']) - 5} more[/dim]")
    if not HAVE_DNSPYTHON:
        tree.add("[dim]install dnspython for CNAME / MX / NS / TXT records[/dim]")
    for e in errors:
        tree.add(f"[red]{e}[/red]")

    console.print(Panel(tree, title="[bold]1 + 2 · DNS Resolution[/bold]", border_style="blue", box=box.ROUNDED))

    if geo:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column(style="dim")
        table.add_column()
        table.add_row("IP", geo.get("ip", ""))
        table.add_row("Location", f"{geo.get('city','?')}, {geo.get('region','?')}, {geo.get('country','?')}")
        conn = geo.get("connection", {}) or {}
        table.add_row("Network / ASN", f"AS{conn.get('asn','?')}  {conn.get('org') or conn.get('isp') or '?'}")
        tz = geo.get("timezone", {}) or {}
        table.add_row("Timezone", f"{tz.get('id','?')}  (UTC{tz.get('utc','')})")
        console.print(Panel(table, title="[bold]IP Geolocation[/bold]  [dim](where that address physically sits)[/dim]", border_style="blue", box=box.ROUNDED))


def render_tcp(ip, port, local_port, connect_ms):
    text = Text()
    text.append(f"Client  ")
    text.append(f"<your IP>:{local_port}", style="bold")
    text.append("  →  Server  ")
    text.append(f"{ip}:{port}", style="bold")
    text.append(f"\n\nSYN → SYN-ACK → ACK completed in ", style="dim")
    text.append(f"{connect_ms} ms", style="bold green")
    console.print(Panel(text, title="[bold]3 · TCP Connection[/bold]", border_style="yellow", box=box.ROUNDED))


def render_tls(cert, version, cipher, handshake_ms):
    if cert is None:
        console.print(Panel("[dim]No TLS — plain HTTP connection (--no-tls).[/dim]", title="[bold]4 · TLS Handshake[/bold]", border_style="red", box=box.ROUNDED))
        return

    subject_cn = cert_subject_field(cert, "commonName") or "?"
    issuer_cn = None
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "commonName" or key == "organizationName":
                issuer_cn = value
    not_after = cert.get("notAfter")
    expires_note = ""
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            color = "green" if days_left > 21 else ("yellow" if days_left > 0 else "red")
            expires_note = f"  [{color}]({days_left} days left)[/{color}]"
        except ValueError:
            pass

    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Protocol negotiated", str(version))
    table.add_row("Cipher suite", f"{cipher[0]}" if cipher else "?")
    table.add_row("Handshake time", f"{handshake_ms} ms")
    table.add_row("Certificate subject", subject_cn)
    table.add_row("Certificate issuer", issuer_cn or "?")
    table.add_row("Valid until", f"{not_after}{expires_note}")
    if sans:
        table.add_row("Also valid for", ", ".join(sans[:6]) + (f"  (+{len(sans)-6} more)" if len(sans) > 6 else ""))

    console.print(Panel(table, title="[bold]4 · TLS Handshake[/bold]  [dim](what your browser does — and can't show you)[/dim]", border_style="red", box=box.ROUNDED))


def render_http(request_text, status_line, headers, body_len, ttfb_ms, total_ms, timeout):
    console.print(Panel(Text(request_text.strip(), style="dim"), title="[bold]5 · HTTP Request Sent[/bold]", border_style="magenta", box=box.ROUNDED))

    if not status_line:
        msg = (f"No response received within {timeout}s — the TCP connection accepted, "
               f"but nothing came back. This usually means a firewall/proxy silently drops "
               f"the traffic rather than rejecting it outright, or the server expects a "
               f"detail this bare-bones request didn't send (e.g. a specific Host format). "
               f"Try --timeout with a larger value, or compare against curl -v.")
        console.print(Panel(msg, title="[bold]6 · HTTP Response[/bold]", border_style="red", box=box.ROUNDED))
        return

    status_code = 0
    try:
        status_code = int(status_line.split()[1])
    except (IndexError, ValueError):
        pass
    status_color = "green" if 200 <= status_code < 300 else "yellow" if 300 <= status_code < 400 else "red"

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Status", f"[{status_color} bold]{status_line}[/{status_color} bold]")
    table.add_row("Time to first byte", f"{ttfb_ms} ms" if ttfb_ms else "?")
    table.add_row("Total download time", f"{total_ms} ms")
    table.add_row("Body size received", f"{body_len:,} bytes")
    for k, v in headers:
        table.add_row(k, v if len(v) < 90 else v[:87] + "...")

    console.print(Panel(table, title="[bold]6 · HTTP Response[/bold]", border_style="magenta", box=box.ROUNDED))


def render_timing_summary(dns_ms, connect_ms, handshake_ms, ttfb_ms, total_ms):
    ttfb_ms = ttfb_ms or 0
    download_ms = max(total_ms - ttfb_ms, 0)
    stages = [
        ("DNS resolution", dns_ms, "blue"),
        ("TCP connect", connect_ms, "yellow"),
        ("TLS handshake", handshake_ms or 0, "red"),
        ("Request → first byte (TTFB)", ttfb_ms, "magenta"),
        ("Downloading body", download_ms, "cyan"),
    ]
    grand_total = dns_ms + connect_ms + (handshake_ms or 0) + total_ms
    max_val = max(1, max(v for _, v, _ in stages))

    table = Table(title="Timing breakdown", box=box.SIMPLE_HEAVY)
    table.add_column("Stage")
    table.add_column("Time")
    table.add_column("Relative")
    for name, val, color in stages:
        val = max(val, 0)
        bar_len = max(1, int((val / max_val) * 30)) if val > 0 else 0
        table.add_row(name, f"{round(val,1)} ms", f"[{color}]{'█' * bar_len}[/{color}]")
    table.add_row("[bold]Total (page-request time)[/bold]", f"[bold]{round(grand_total,1)} ms[/bold]", "")
    console.print(table)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Show, with real data, the full journey of a webpage request.")
    parser.add_argument("target", nargs="?", help="Domain or URL, e.g. example.com or https://example.com/path")
    parser.add_argument("--port", type=int, default=None, help="Override the port")
    parser.add_argument("--no-tls", action="store_true", help="Use plain HTTP instead of HTTPS")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-step timeout in seconds (default 8)")
    args = parser.parse_args()

    raw = args.target or console.input("[bold]Domain or URL to trace:[/bold] ")
    host, scheme, port, path = parse_target(raw, args.port, args.no_tls)
    use_tls = scheme == "https"

    console.print(Panel(f"[bold]{scheme}://{host}:{port}{path}[/bold]", title="Tracing", border_style="white", box=box.HEAVY))

    # 1+2. DNS
    with console.status("Resolving DNS..."):
        records, dns_time_ms, dns_errors = resolve_dns(host, args.timeout)
    if not records["A"] and not records["AAAA"]:
        console.print(f"[bold red]Could not resolve {host} — is the domain correct?[/bold red]")
        for e in dns_errors:
            console.print(f"  [red]{e}[/red]")
        sys.exit(1)
    target_ip = records["A"][0] if records["A"] else records["AAAA"][0]

    with console.status("Looking up IP geolocation..."):
        geo = geolocate(target_ip, args.timeout)
    render_dns(host, records, dns_time_ms, dns_errors, geo)

    # 3. TCP
    try:
        with console.status(f"Opening TCP connection to {target_ip}:{port}..."):
            sock, connect_ms, local_port = tcp_connect(target_ip, port, args.timeout)
    except OSError as e:
        console.print(f"[bold red]TCP connection failed:[/bold red] {e}")
        sys.exit(1)
    render_tcp(target_ip, port, local_port, connect_ms)

    # 4. TLS
    handshake_ms = None
    cert = version = cipher = None
    if use_tls:
        try:
            with console.status("Performing TLS handshake..."):
                sock, cert, version, cipher, handshake_ms = tls_handshake(sock, host, args.timeout)
        except ssl.SSLError as e:
            console.print(f"[bold red]TLS handshake failed:[/bold red] {e}")
            sys.exit(1)
    render_tls(cert, version, cipher, handshake_ms)

    # 5+6. HTTP
    with console.status("Sending HTTP request..."):
        request_text, status_line, headers, body_len, ttfb_ms, total_ms = http_roundtrip(sock, host, path, args.timeout)
    render_http(request_text, status_line, headers, body_len, ttfb_ms, total_ms, args.timeout)

    render_timing_summary(dns_time_ms, connect_ms, handshake_ms, ttfb_ms, total_ms)

    sock.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)