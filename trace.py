#!/usr/bin/env python3
"""trace.py — thin shim so `python3 trace.py ...` keeps working.

The actual CLI (build_parser/main) lives in wj/cli.py — a console-script
entry point can't target a root-level module, and the name `trace` shadows
the standard library's own trace module, which is why the real
implementation moved into the wj package. This file exists only for anyone
still invoking `python3 trace.py example.com` directly.
"""

import sys

from rich.console import Console

from wj.cli import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        Console().print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)
