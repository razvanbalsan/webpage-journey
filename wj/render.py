"""All terminal rendering for a trace run."""

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from wj import schema

OSI_LAYERS = [
    (7, "Application",  "blue",          "HTTP, DNS, gRPC, SMTP"),
    (6, "Presentation", "dark_orange3",  "TLS/SSL, compression, encoding"),
    (5, "Session",      "cyan",          "Session establishment"),
    (4, "Transport",    "yellow",        "TCP, UDP, ports"),
    (3, "Network",      "magenta",       "IP, routing, CIDR"),
    (2, "Data Link",    "green",         "Ethernet, MAC, switches"),
    (1, "Physical",     "medium_purple", "Cables, fiber, radio"),
]

LAYER_COLOR = {n: color for n, _, color, _ in OSI_LAYERS}
LAYER_NAME = {n: name for n, name, _, _ in OSI_LAYERS}

LAYER_JOBS = {
    7: "The protocols your application speaks. An API gateway or L7 load balancer routes on hostname, path, or headers here.",
    6: "Translating data format: encryption/decryption, compression, character encoding.",
    5: "Opening, maintaining, and closing the conversation between two applications.",
    4: "End-to-end delivery between hosts. TCP is reliable and ordered; UDP is fast with no guarantees. Ports live here.",
    3: "Routing between networks. IP addresses and CIDR blocks live here — the layer a router works at.",
    2: "Moving frames between devices on the same local network. MAC addresses and switches live here.",
    1: "The actual signal — electricity on copper, light in fiber, radio over Wi-Fi. An unplugged cable fails here.",
}


def layer_tags(*nums):
    """Render 'L7 L4 L3' chips in each layer's colour, for a panel title."""
    return " ".join(
        f"[{LAYER_COLOR[n]} bold]L{n}[/{LAYER_COLOR[n]} bold]" for n in nums
    )


def render_osi_reference(console):
    """--osi: print the model on its own, as a teaching reference, with no trace."""
    wide = console.width >= 100
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Layer", no_wrap=True)
    if wide:
        table.add_column("Protocols / examples", no_wrap=True)
    table.add_column("What it is responsible for", overflow="fold")

    for n, name, color, protos in OSI_LAYERS:
        label = f"[{color} bold]L{n} {name}[/{color} bold]"
        if wide:
            table.add_row(label, f"[dim]{protos}[/dim]", LAYER_JOBS[n])
        else:
            table.add_row(f"{label}\n[dim]{protos}[/dim]", LAYER_JOBS[n])

    console.print(Panel(
        table,
        title="[bold]The OSI model[/bold]",
        subtitle="[dim]top = closest to the user · bottom = closest to the wire[/dim]",
        border_style="white",
        box=box.HEAVY,
    ))
    console.print("[dim]Troubleshooting ladder: ping tests L3 · a port check tests L4 · a 502 from your app is L7.[/dim]")


SEVERITY_STYLE = {"critical": "bold red", "warn": "yellow", "info": "cyan"}
SEVERITY_ORDER = {"critical": 0, "warn": 1, "info": 2}


def _kv_table(rows):
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(style="dim")
    table.add_column(overflow="fold")
    for key, value in rows:
        if value not in (None, "", []):
            table.add_row(key, str(value))
    return table


def _panel(console, body, title, layers, border):
    console.print(Panel(body, title=f"[bold]{title}[/bold]  {layer_tags(*layers)}",
                        border_style=border, box=box.ROUNDED))


def _unobserved_panel(console, section, title, layers, border):
    _panel(console, Text(f"not observed — {section.get('why_not', 'not collected')}", style="dim"),
           title, layers, border)


def _pair(a, b, sep="  "):
    """Join two optional strings, without ever spelling out a missing one as 'None'."""
    if a and b:
        return f"{a}{sep}({b})"
    return a or b


def render_local(console, trace):
    section = trace.get("local", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "1 · Your local network", (1, 2), "medium_purple")

    body = _kv_table([
        ("Interface", _pair(section.get("interface"), section.get("link"))),
        ("MTU", section.get("mtu")),
        ("Your address", _pair(section.get("local_ip"), section.get("local_mac"))),
        ("Gateway", _pair(section.get("gateway_ip"), section.get("gateway_mac"))),
        ("Public address", section.get("public_ip")),
        ("NAT", "yes — your private address is translated on the way out"
                if section.get("nat") else "no"),
        ("DHCP server", (section.get("dhcp") or {}).get("server")),
    ])
    _panel(console, body, "1 · Your local network", (1, 2), "medium_purple")


def render_dns(console, trace):
    section = trace.get("dns", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "2 · DNS resolution", (7, 4, 3), "blue")

    timing = section.get("timing_ms") or {}
    timing_parts = []
    if timing.get("cold") is not None:
        timing_parts.append(f"{timing['cold']} ms cold")
    if timing.get("warm") is not None:
        timing_parts.append(f"{timing['warm']} ms warm")
    if timing.get("survey_ms") is not None:
        timing_parts.append(f"{timing['survey_ms']} ms for the full 9-record-type survey")
    timing_text = f"  [dim]({', '.join(timing_parts)})[/dim]" if timing_parts else ""
    tree = Tree(f"[bold]{trace['target']['host']}[/bold]{timing_text}")
    for rtype, records in (section.get("records") or {}).items():
        if not records:
            continue
        branch = tree.add(f"[cyan]{rtype}[/cyan]")
        for record in records[:5]:
            branch.add(f"{record['data']}  [dim]ttl {record['ttl']}[/dim]")
        if len(records) > 5:
            branch.add(f"[dim]… {len(records) - 5} more[/dim]")

    # An empty list under a record type means "unknown" for the types listed
    # here — the query failed — not "this domain publishes none of these".
    failed = section.get("records_failed") or []
    if failed:
        tree.add(f"[red]query failed — no answer for: {', '.join(failed)}[/red]")

    resolver = section.get("resolver") or {}
    footer = f"resolved via {', '.join(resolver.get('servers') or ['unknown'])}"
    if resolver.get("source"):
        footer += f" ({resolver['source']})"
    if section.get("dnssec"):
        footer += f" · DNSSEC {section['dnssec']}"
    tree.add(f"[dim]{footer}[/dim]")
    for hop in section.get("delegation") or []:
        tree.add(f"[dim]{hop.get('level')}: {hop.get('server')} → "
                 f"{', '.join(hop.get('referral') or hop.get('answer') or [])}[/dim]")

    _panel(console, tree, "2 · DNS resolution", (7, 4, 3), "blue")


def render_tcp(console, trace):
    section = trace.get("tcp", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "3 · TCP connection", (4, 3), "yellow")

    chosen = section.get("chosen") or {}
    local = section.get("local") or {}
    kernel = section.get("kernel") or {}

    def _endpoint(d):
        ip, port = d.get("ip"), d.get("port")
        if ip and port is not None:
            return f"{ip}:{port}"
        return ip or "unknown"

    text = Text()
    text.append("Client  ")
    text.append(_endpoint(local), style="bold")
    text.append("  →  Server  ")
    text.append(f"{_endpoint(chosen)}\n", style="bold")
    text.append("        └─ ephemeral port your OS picked\n", style="dim")
    text.append("                              └─ well-known port for this service\n", style="dim")
    if section.get("winner_family"):
        text.append(f"\n{section['winner_family']} won the connection race", style="dim")

    rows = [(f"{c['family']}  {c['ip']}",
             f"{c['connect_ms']} ms" if c.get("connect_ms") is not None else c.get("error"))
            for c in section.get("candidates") or []]
    if kernel:
        # Any of rtt_ms / mss / retransmits / source may individually be missing
        # (a plausibility check on rtt_ms, an unsupported sockopt, …) even though
        # the kernel exposed something — build the summary from what is present.
        stats = []
        if kernel.get("rtt_ms") is not None:
            stats.append(f"RTT {kernel['rtt_ms']} ms")
        if kernel.get("mss") is not None:
            stats.append(f"MSS {kernel['mss']}")
        if kernel.get("retransmits") is not None:
            stats.append(f"{kernel['retransmits']} retransmits")
        summary = " · ".join(stats) or "no further detail from the kernel"
        if kernel.get("source"):
            summary += f" ({kernel['source']})"
        rows.append(("Kernel", summary))

    console.print(Panel(text, title=f"[bold]3 · TCP connection[/bold]  {layer_tags(4, 3)}",
                        border_style="yellow", box=box.ROUNDED))
    console.print(_kv_table(rows))


def render_tls(console, trace):
    section = trace.get("tls", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "4 · TLS handshake", (6, 5), "dark_orange3")

    chain = section.get("chain") or []
    rows = [
        ("Protocol", section.get("version")),
        ("Cipher", section.get("cipher")),
        ("ALPN", section.get("alpn")),
        ("Handshake", f"{section.get('handshake_ms')} ms"
                      if section.get("handshake_ms") is not None else None),
        ("Trusted via", section.get("trust_root")),
        ("CAA", {True: "issuer is authorised", False: "issuer is NOT listed",
                 None: "no comparable CAA record"}[section.get("caa_match")]),
    ]
    for i, cert in enumerate(chain):
        subject, issuer = cert.get("subject_cn"), cert.get("issuer_cn")
        names = f"{subject} ← {issuer}" if subject and issuer else (subject or issuer)
        key = cert.get("key") or {}
        key_text = f"{key.get('type')}{key.get('bits')}" if key.get("type") else None
        days_left = cert.get("days_left")
        days_text = f"{days_left} days left" if days_left is not None else None
        detail = " · ".join(p for p in (names, key_text, days_text) if p)
        # A chain entry with every field unparsed would otherwise vanish from the
        # table (an empty string is one of _kv_table's drop conditions), leaving no
        # trace that a certificate sits at this position at all.
        rows.append((f"Cert {i}", detail or "[dim]no fields parsed[/dim]"))
        if i == 0 and cert.get("sans"):
            rows.append(("  also valid for", ", ".join(cert["sans"][:6])))

    _panel(console, _kv_table(rows), "4 · TLS handshake", (6, 5), "dark_orange3")


def render_path(console, trace):
    section = trace.get("path", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "5 · Crossing the internet", (3,), "magenta")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("#", no_wrap=True)
    table.add_column("Address")
    table.add_column("Name", overflow="fold")
    table.add_column("RTT")
    table.add_column("AS")
    for hop in section.get("hops") or []:
        table.add_row(str(hop.get("ttl")), hop.get("ip") or "[dim]*[/dim]",
                      hop.get("rdns") or "",
                      f"{hop['rtt_ms']} ms" if hop.get("rtt_ms") else "",
                      f"AS{hop['asn']}" if hop.get("asn") else "")
    as_path = " → ".join(f"AS{n}" for n in section.get("asn_path") or [])
    console.print(Panel(table,
                        title=f"[bold]5 · Crossing the internet[/bold]  {layer_tags(3)}",
                        subtitle=f"[dim]{as_path}[/dim]" if as_path else None,
                        border_style="magenta", box=box.ROUNDED))


def render_http(console, trace):
    section = trace.get("http", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "6 · HTTP request & response", (7,), "blue")

    final = section.get("final") or {}
    status = final.get("status")
    protocol = final.get("protocol")
    if status is None:
        # A malformed or absent status line is not a measured status of 0 — say so
        # plainly rather than inventing a code and colouring it like a real error.
        status_text = "[dim]no status line in the response[/dim]"
    else:
        colour = "green" if 200 <= status < 300 else "yellow" if status < 400 else "red"
        status_text = f"[{colour} bold]{' '.join(p for p in (protocol, str(status)) if p)}[/{colour} bold]"

    rows = []
    for hop in section.get("hops") or []:
        rows.append((f"{hop['status']} redirect", f"{hop['url']} → {hop['location']}"))
    if section.get("redirect_limit_reached") and section.get("hops"):
        # A hop count alone reads as the whole chain — say plainly that it was cut short.
        rows.append(("", f"[dim]redirect chain truncated after "
                          f"{len(section['hops'])} hop(s) — the limit was reached[/dim]"))

    cache = section.get("cache") or {}
    cache_parts = []
    if cache.get("state"):
        cache_parts.append(cache["state"])
    if cache.get("age") is not None:
        cache_parts.append(f"age {cache['age']}")
    if cache.get("directives"):
        cache_parts.append(cache["directives"])
    cache_value = " · ".join(cache_parts) if cache_parts else None

    rows += [
        ("Status", status_text),
        ("URL", final.get("url")),
        ("TTFB", f"{final.get('ttfb_ms')} ms" if final.get("ttfb_ms") is not None else None),
        ("Total", f"{final.get('total_ms')} ms" if final.get("total_ms") is not None else None),
        ("Body", f"{final.get('wire_bytes')} bytes on the wire → "
                 f"{final.get('decoded_bytes')} decoded"
                 + (f" ({final.get('encoding')}, {final.get('ratio')}:1)"
                    if final.get("encoding") else "")),
        ("Content type", final.get("content_type")),
        ("CDN", section.get("cdn")),
        ("Cache", cache_value),
        ("Security grade", (section.get("security") or {}).get("grade")),
        ("Missing headers", ", ".join((section.get("security") or {}).get("missing") or [])),
    ]
    _panel(console, _kv_table(rows), "6 · HTTP request & response", (7,), "blue")


def render_findings(console, trace):
    notes = sorted(trace.get("notes") or [],
                   key=lambda n: SEVERITY_ORDER.get(n["severity"], 9))
    if not notes:
        console.print(Panel("[green]Nothing worth flagging in this trace.[/green]",
                            title="[bold]Findings[/bold]", border_style="green",
                            box=box.ROUNDED))
        return

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(no_wrap=True)
    table.add_column(style="dim", no_wrap=True)
    table.add_column(overflow="fold")
    for note in notes:
        style = SEVERITY_STYLE.get(note["severity"], "")
        table.add_row(f"[{style}]{note['severity']}[/{style}]", note["section"], note["text"])

    console.print(Panel(table, title=f"[bold]Findings[/bold]  ({len(notes)})",
                        border_style="yellow", box=box.ROUNDED))


def render_waterfall(console, trace):
    rows = (trace.get("timings") or {}).get("waterfall") or []
    total = (trace.get("timings") or {}).get("total_ms") or 0.0
    if not rows or total <= 0:
        return

    width = 40
    table = Table(title="Timing waterfall", box=box.SIMPLE_HEAVY)
    table.add_column("Stage")
    table.add_column("Duration", justify="right")
    table.add_column("Timeline")

    for row in rows:
        duration = row["end_ms"] - row["start_ms"]
        lead = int((row["start_ms"] / total) * width)
        bar = max(1, int((duration / total) * width)) if duration > 0 else 0
        table.add_row(row["label"], f"{round(duration, 1)} ms",
                      " " * lead + "█" * bar)

    table.add_row("[bold]Total[/bold]", f"[bold]{total} ms[/bold]", "")
    console.print(table)


def render_osi_stack(console, trace):
    osi = trace.get("osi") or schema.build_osi(trace)
    wide = console.width >= 100

    # The descriptive column is capped: left unbounded, a single long, unbroken
    # job description (up to ~120 chars) forces Rich's column-fitting to starve
    # the measurement column of width entirely at anything narrower than ~140
    # columns -- the one column that exists to show real, measured data. (A
    # min_width on the measurement column looked like the fix too, but at
    # narrow terminal widths it overcommits past what's available and Rich
    # silently drops the overflow instead of wrapping it — worse than the
    # crowding it was meant to solve.)
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", padding=(0, 1))
    if wide:
        table.add_column("Layer", no_wrap=True)
        table.add_column("What happens here", max_width=32)
    else:
        table.add_column("Layer", max_width=32)
    table.add_column("What THIS request actually did", overflow="fold")

    for n, name, colour, _protos in OSI_LAYERS:
        layer = osi.get(f"l{n}", {})
        if layer.get("observed"):
            observed_text = "\n".join(layer.get("facts") or []) or "—"
        else:
            observed_text = f"[dim]not observed — {layer.get('why_not', 'not collected')}[/dim]"

        label = f"[{colour} bold]L{n} {name}[/{colour} bold]"
        if wide:
            table.add_row(label, f"[dim]{LAYER_JOBS[n]}[/dim]", observed_text)
        else:
            table.add_row(f"{label}\n[dim]{LAYER_JOBS[n]}[/dim]", observed_text)

    console.print()
    console.print(Panel(table,
                        title="[bold]The OSI model — mapped onto the request you just traced[/bold]",
                        subtitle="[dim]top = closest to you · bottom = closest to the wire[/dim]",
                        border_style="white", box=box.HEAVY))


def render_ladder(console, trace):
    osi = trace.get("osi") or schema.build_osi(trace)
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column(no_wrap=True)
    table.add_column(overflow="fold")
    for n, name, colour, _protos in OSI_LAYERS:
        command = (osi.get(f"l{n}") or {}).get("test_command")
        if command:
            table.add_row(f"[{colour} bold]L{n} {name}[/{colour} bold]", command)
    console.print(Panel(table, title="[bold]Test each layer yourself[/bold]",
                        border_style="white", box=box.ROUNDED))


def render_trace(console, trace):
    target = trace.get("target", {})
    console.print(Panel(
        f"[bold]{target.get('scheme')}://{target.get('host')}:{target.get('port')}"
        f"{target.get('path')}[/bold]",
        title="Traced", border_style="white", box=box.HEAVY))

    render_local(console, trace)
    render_dns(console, trace)
    render_tcp(console, trace)
    render_tls(console, trace)
    render_path(console, trace)
    render_http(console, trace)
    render_waterfall(console, trace)
    render_findings(console, trace)
    render_osi_stack(console, trace)
    render_ladder(console, trace)
