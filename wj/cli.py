"""wj.cli — trace one webpage request end to end and map it onto the OSI model.

This is the argument parser and entry point behind both `python3 trace.py` (the
repo-root shim) and the installed `webpage-journey` console script.
"""

import argparse
import json
import sys
import time

from rich.console import Console

from wj import __version__, capabilities, redact, render, run, schema
from wj.context import Context, parse_target


def build_parser():
    p = argparse.ArgumentParser(
        prog="trace.py",
        description="Trace a webpage request end to end, with real data, mapped onto the OSI model.",
        epilog="Trace only hosts you are authorised to probe.",
    )
    p.add_argument("target", nargs="?", help="Domain or URL, e.g. example.com")
    p.add_argument("--port", type=int, default=None, help="Override the port")
    p.add_argument("--no-tls", action="store_true", help="Use plain HTTP instead of HTTPS")
    p.add_argument("--timeout", type=float, default=8.0, help="Per-operation timeout (default 8)")
    p.add_argument("--budget", type=float, default=25.0, help="Total wall-clock cap (default 25)")
    p.add_argument("--json", dest="json_path", metavar="PATH",
                   help="Export the trace document; '-' writes to stdout")
    p.add_argument("--no-path", action="store_true", help="Skip traceroute entirely")
    redaction = p.add_mutually_exclusive_group()
    redaction.add_argument("--redact", dest="redact", action="store_true", default=True,
                           help="Redact MAC / local IP / public IP in exports (default)")
    redaction.add_argument("--no-redact", dest="redact", action="store_false",
                           help="Keep identifying detail in exports")
    install = p.add_mutually_exclusive_group()
    install.add_argument("--auto-install", dest="install_mode", action="store_const",
                         const="auto", default="auto", help="Install missing libraries (default)")
    install.add_argument("--offline", dest="install_mode", action="store_const",
                         const="offline", help="Never install anything")
    p.add_argument("--osi", action="store_true",
                   help="Print the OSI reference table alone and exit (no trace)")
    p.add_argument("--version", action="version", version=f"trace.py {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    # When the document goes to stdout, all narration goes to stderr so it stays pipeable.
    to_stdout = args.json_path == "-"
    console = Console(stderr=to_stdout)

    if args.osi:
        render.render_osi_reference(console)
        return run.EXIT_OK

    if not args.target:
        console.print("[red]No target given.[/red] Try: trace.py example.com")
        return run.EXIT_USAGE

    try:
        host, scheme, port, path = parse_target(args.target, args.port, args.no_tls)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return run.EXIT_USAGE

    caps = capabilities.detect()
    caps = capabilities.ensure_libs(caps, mode=args.install_mode)

    ctx = Context(host=host, scheme=scheme, port=port, path=path,
                  timeout=args.timeout, deadline=time.monotonic() + args.budget,
                  caps=caps, no_path=args.no_path, results={})

    with console.status(f"Tracing {scheme}://{host}:{port}{path} …"):
        trace = run.orchestrate(ctx)

    run.close_sockets(trace)
    trace = run.strip_private(trace)

    problems = schema.validate(trace)
    if problems:
        console.print(f"[yellow]Trace document has {len(problems)} schema problem(s):[/yellow]")
        for problem in problems:
            console.print(f"  [yellow]{problem}[/yellow]")

    render.render_trace(console, trace)

    if args.json_path:
        document = redact.redact_trace(trace) if args.redact else trace
        payload = json.dumps(document, indent=2, default=str)
        if to_stdout:
            print(payload)
        else:
            with open(args.json_path, "w") as fh:
                fh.write(payload + "\n")
            console.print(f"[dim]Trace written to {args.json_path}"
                          f"{' (redacted)' if args.redact else ''}[/dim]")

    if not trace["dns"]["observed"] and not trace["tcp"]["observed"]:
        return run.EXIT_UNRESOLVABLE
    return run.EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        Console().print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)
