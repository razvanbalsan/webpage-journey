"""All terminal rendering for a trace run."""

from rich import box
from rich.panel import Panel
from rich.table import Table

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
