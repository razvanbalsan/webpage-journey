#!/usr/bin/env python3
"""trace.py — trace one webpage request end to end and map it onto the OSI model."""

import argparse
import sys

from rich.console import Console

from wj import __version__, render


def build_parser():
    p = argparse.ArgumentParser(
        prog="trace.py",
        description="Trace a webpage request end to end, with real data, mapped onto the OSI model.",
    )
    p.add_argument("target", nargs="?", help="Domain or URL, e.g. example.com")
    p.add_argument("--osi", action="store_true",
                   help="Print the OSI reference table alone and exit (no trace)")
    p.add_argument("--version", action="version", version=f"trace.py {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    console = Console()
    if args.osi:
        render.render_osi_reference(console)
        return 0
    console.print("[dim]Tracing is not implemented yet — see the implementation plan.[/dim]")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        Console().print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)
