# Webpage Journey Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn an OSI-annotated terminal tracer and an interactive HTML walkthrough into a pair that both diagnoses a real host end to end and explains every measurement in OSI terms, coupled only by a versioned JSON trace document.

**Architecture:** A Python package `wj/` of six independent collectors (local, dns, tcp, tls, http, path) each returning one section of a versioned trace document; an orchestrator that runs them on a budgeted dependency graph and degrades rather than aborts; a rich terminal renderer; and a single self-contained HTML page that imports those trace documents, falls back to live DNS-over-HTTPS, and labels every fact as measured, live, or illustrative.

**Tech Stack:** Python 3.11+, `rich`, `dnspython`, `cryptography`, `h2`/`httpx` (all optional and auto-installed), `pytest`; vanilla HTML/CSS/JS with no build step and no external assets.

**Spec:** `docs/superpowers/specs/2026-08-20-webpage-journey-design.md`

## Global Constraints

- Project root for all paths in this plan: `/Users/razvanbalsan/Projects/webpage-journey/`.
- Virtualenv: `webpage-journey/.venv`. Every `python3`/`pytest` command below runs from that venv.
- Git repository is initialised in `webpage-journey/` (Task 1). Every task ends with a commit.
- Trace schema constant: `webpage-journey-trace/1`. Major version `1`.
- **Every field is either measured or absent.** Sections carry `observed: bool`, and `why_not: str` whenever `observed` is false. Never emit a plausible-looking placeholder value.
- Note severities are exactly `"info" | "warn" | "critical"`.
- Redaction is ON by default for `--json` export, OFF for terminal output.
- Only an unresolvable host is fatal. Exit codes: `0` trace completed (findings do not change this), `1` target unresolvable, `2` usage error.
- `--deep` gates the three actively-scanning probes: TLS downgrade, session resumption retest, conditional-request replay.
- The HTML stays ONE self-contained file. No CDN, no external font, no build step. All live-fetch code sits behind the single constant `LIVE_LOOKUPS_ENABLED`.
- Unit tests never touch the network. Network tests are marked `@pytest.mark.network` and are opt-in.
- Layer chip colours must reach ≥4.5:1 contrast against their text colour in both themes.

**Deviation from the spec's file layout:** this plan adds `wj/context.py` holding the `Context` dataclass that every collector consumes. The spec's layout did not name it; putting it in `schema.py` would conflate the document format with run state.

---

## File Structure

| File | Responsibility |
|---|---|
| `trace.py` | CLI entry: argument parsing, orchestration DAG, budget, exit codes |
| `wj/schema.py` | Trace document construction, version constant, validation, `build_osi` |
| `wj/context.py` | `Context` dataclass: run parameters, deadline, capabilities, prior results |
| `wj/capabilities.py` | Library/tool/privilege detection and dependency auto-install |
| `wj/redact.py` | Redaction of MAC / local IP / public IP in exported documents |
| `wj/render.py` | All rich terminal output: step panels, findings, waterfall, OSI finale, ladder |
| `wj/collect/local.py` | L1/L2: interface, MTU, MAC, gateway MAC, DHCP, NAT |
| `wj/collect/dns.py` | Records with TTLs, resolver in use, delegation walk, DNSSEC, cache timing |
| `wj/collect/tcp.py` | Happy Eyeballs, per-address connect timing, kernel `TCP_INFO` |
| `wj/collect/tls.py` | ALPN, full chain, trust root, CAA cross-check, resumption, downgrade probe |
| `wj/collect/http.py` | Redirect chain, HTTP/2-3, decoding, cache/CDN state, security grading |
| `wj/collect/path.py` | Traceroute, per-hop ASN, path MTU |
| `webpage-journey.html` | The teaching page: import, live fallback, 15 stages, simulator |
| `tests/fixtures/` | Captured command output, DER certificates, golden trace documents |

---

## Task 1: Project scaffold and `--osi` reference

**Files:**
- Create: `.gitignore`, `wj/__init__.py`, `wj/collect/__init__.py`, `wj/render.py`, `trace.py`
  (`README.md` is written in Task 21, which supplies its full content — it is not a Task 1 deliverable)
- Move: `~/Projects/webpage-journey_osi.py` content is the source for the OSI table (the original stays at `~/Projects/webpage_journey_osi.py` until Task 20)
- Test: `tests/test_osi_reference.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `wj.render.OSI_LAYERS: list[tuple[int, str, str, str]]`, `wj.render.LAYER_COLOR: dict[int, str]`, `wj.render.LAYER_NAME: dict[int, str]`, `wj.render.layer_tags(*nums: int) -> str`, `wj.render.render_osi_reference(console) -> None`, `wj.__version__: str`.

- [ ] **Step 1: Create the project skeleton and repository**

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
mkdir -p wj/collect tests/fixtures
git init
python3 -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet pytest rich dnspython
printf '.venv/\n__pycache__/\n*.pyc\n.pytest_cache/\n' > .gitignore
touch wj/__init__.py wj/collect/__init__.py
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_osi_reference.py`:

```python
from wj import render


def test_seven_layers_ordered_top_to_bottom():
    numbers = [n for n, _name, _color, _protos in render.OSI_LAYERS]
    assert numbers == [7, 6, 5, 4, 3, 2, 1]


def test_layer_lookup_tables_cover_every_layer():
    assert render.LAYER_NAME[4] == "Transport"
    assert set(render.LAYER_COLOR) == {1, 2, 3, 4, 5, 6, 7}


def test_layer_tags_renders_one_chip_per_layer():
    tags = render.layer_tags(7, 4)
    assert "L7" in tags and "L4" in tags
    assert tags.count("[/") == 2
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_osi_reference.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.render'`

- [ ] **Step 4: Write `wj/render.py`**

```python
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
```

Then `wj/__init__.py`:

```python
__version__ = "2.0.0"
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_osi_reference.py -v`
Expected: PASS, 3 tests

- [ ] **Step 6: Write the CLI entry point**

Create `trace.py`:

```python
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
```

- [ ] **Step 7: Verify the reference table renders**

Run: `.venv/bin/python trace.py --osi`
Expected: a bordered table listing L7 down to L1 with the troubleshooting-ladder line beneath it.

- [ ] **Step 8: Commit**

```bash
git add .gitignore wj trace.py tests
git commit -m "feat: project scaffold with OSI reference table"
```

---

## Task 2: Trace document schema

**Files:**
- Create: `wj/schema.py`
- Test: `tests/test_schema.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `SCHEMA: str = "webpage-journey-trace/1"`, `SCHEMA_MAJOR: int = 1`
  - `SECTIONS: tuple[str, ...] = ("local", "dns", "tcp", "tls", "http", "path")`
  - `schema_major(schema: str) -> int`
  - `observed(**fields) -> dict` — returns `{"observed": True, **fields}`
  - `unobserved(why_not: str) -> dict` — returns `{"observed": False, "why_not": why_not}`
  - `new_trace(target: dict, tool_version: str, generated_at: str, capabilities: dict, redacted: bool) -> dict`
  - `add_note(trace: dict, severity: str, section: str, text: str) -> None`
  - `validate(trace: dict) -> list[str]` — returns problem strings; empty list means valid

- [ ] **Step 1: Write the failing test**

Create `tests/test_schema.py`:

```python
import pytest

from wj import schema


def make_trace():
    return schema.new_trace(
        target={"input": "example.com", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.0.0",
        generated_at="2026-08-20T09:31:02Z",
        capabilities={"privileged": False, "tools": [], "libs": {}},
        redacted=True,
    )


def test_new_trace_carries_version_and_target():
    t = make_trace()
    assert t["schema"] == "webpage-journey-trace/1"
    assert t["tool"] == {"name": "trace.py", "version": "2.0.0"}
    assert t["target"]["host"] == "example.com"
    assert t["redacted"] is True


def test_every_section_starts_unobserved_with_a_reason():
    t = make_trace()
    for name in schema.SECTIONS:
        assert t[name] == {"observed": False, "why_not": "not collected"}


def test_new_trace_validates_clean():
    assert schema.validate(make_trace()) == []


def test_validate_rejects_unobserved_section_without_reason():
    t = make_trace()
    t["dns"] = {"observed": False}
    assert "dns: observed is false but why_not is missing" in schema.validate(t)


def test_validate_rejects_unknown_note_severity():
    t = make_trace()
    t["notes"].append({"severity": "urgent", "section": "tls", "text": "x"})
    assert "notes[0]: unknown severity 'urgent'" in schema.validate(t)


def test_validate_rejects_wrong_schema_major():
    t = make_trace()
    t["schema"] = "webpage-journey-trace/2"
    assert "schema: unsupported major version 2" in schema.validate(t)


def test_add_note_appends_in_order():
    t = make_trace()
    schema.add_note(t, "warn", "tls", "certificate expires in 9 days")
    schema.add_note(t, "info", "dns", "no AAAA record")
    assert [n["section"] for n in t["notes"]] == ["tls", "dns"]
    assert t["notes"][0]["severity"] == "warn"


def test_schema_major_parses_trailing_integer():
    assert schema.schema_major("webpage-journey-trace/1") == 1


def test_observed_and_unobserved_helpers():
    assert schema.observed(version="TLSv1.3") == {"observed": True, "version": "TLSv1.3"}
    assert schema.unobserved("no privilege") == {"observed": False, "why_not": "no privilege"}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.schema'`

- [ ] **Step 3: Write `wj/schema.py`**

```python
"""The trace document: construction, validation, and derived OSI assembly.

The single rule this module exists to enforce: every field is either measured
or absent. A section that could not be collected says so, and says why.
"""

SCHEMA = "webpage-journey-trace/1"
SCHEMA_MAJOR = 1

SECTIONS = ("local", "dns", "tcp", "tls", "http", "path")
SEVERITIES = ("info", "warn", "critical")


def schema_major(schema):
    """'webpage-journey-trace/1' -> 1. Raises ValueError on anything else."""
    return int(schema.rsplit("/", 1)[1])


def observed(**fields):
    return {"observed": True, **fields}


def unobserved(why_not):
    return {"observed": False, "why_not": why_not}


def new_trace(target, tool_version, generated_at, capabilities, redacted):
    trace = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "tool": {"name": "trace.py", "version": tool_version},
        "target": target,
        "capabilities": capabilities,
        "redacted": redacted,
        "timings": {},
        "osi": {},
        "notes": [],
    }
    for name in SECTIONS:
        trace[name] = unobserved("not collected")
    return trace


def add_note(trace, severity, section, text):
    trace["notes"].append({"severity": severity, "section": section, "text": text})


def validate(trace):
    """Return a list of human-readable problems. Empty list means the document is valid."""
    problems = []

    try:
        major = schema_major(trace.get("schema", ""))
    except (ValueError, IndexError):
        problems.append("schema: missing or unparseable")
    else:
        if major != SCHEMA_MAJOR:
            problems.append(f"schema: unsupported major version {major}")

    for key in ("generated_at", "tool", "target", "capabilities", "timings", "osi", "notes"):
        if key not in trace:
            problems.append(f"{key}: missing")

    for name in SECTIONS:
        sec = trace.get(name)
        if not isinstance(sec, dict):
            problems.append(f"{name}: missing or not an object")
            continue
        if "observed" not in sec:
            problems.append(f"{name}: missing observed flag")
        elif sec["observed"] is False and not sec.get("why_not"):
            problems.append(f"{name}: observed is false but why_not is missing")

    for i, note in enumerate(trace.get("notes", [])):
        if note.get("severity") not in SEVERITIES:
            problems.append(f"notes[{i}]: unknown severity {note.get('severity')!r}")

    return problems
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_schema.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add wj/schema.py tests/test_schema.py
git commit -m "feat: versioned trace document schema with validation"
```

---

## Task 3: Capability detection and dependency auto-install

**Files:**
- Create: `wj/capabilities.py`
- Test: `tests/test_capabilities.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `TOOL_NAMES: tuple[str, ...]`
  - `OPTIONAL_LIBS: dict[str, tuple[str, str]]` — import name → (pip name, reason)
  - `Capabilities` dataclass with fields `libs: dict[str, bool]`, `tools: dict[str, str | None]`, `privileged: bool`, `can_sudo: bool`, `installed_during_run: list[str]`; methods `has_tool(name) -> bool`, `has_lib(name) -> bool`, `to_dict() -> dict`
  - `detect(which=shutil.which, geteuid=os.geteuid, run=subprocess.run) -> Capabilities`
  - `ensure_libs(caps, mode="auto", in_venv=None, installer=None, prompt=None) -> Capabilities` — `mode` is `"auto"` or `"offline"`

- [ ] **Step 1: Write the failing test**

Create `tests/test_capabilities.py`:

```python
from wj import capabilities


class FakeRun:
    """Stands in for subprocess.run: returns a canned return code."""

    def __init__(self, returncode):
        self.returncode = returncode
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        class R:
            pass
        r = R()
        r.returncode = self.returncode
        r.stdout = ""
        r.stderr = ""
        return r


def test_detect_records_found_and_missing_tools():
    run = FakeRun(1)
    caps = capabilities.detect(
        which=lambda name: "/usr/bin/dig" if name == "dig" else None,
        geteuid=lambda: 501,
        run=run,
    )
    assert caps.tools["dig"] == "/usr/bin/dig"
    assert caps.tools["traceroute"] is None
    assert caps.has_tool("dig") is True
    assert caps.has_tool("traceroute") is False


def test_detect_reports_root_and_sudo_ability():
    caps = capabilities.detect(which=lambda n: None, geteuid=lambda: 0, run=FakeRun(0))
    assert caps.privileged is True

    caps = capabilities.detect(which=lambda n: "/usr/bin/sudo", geteuid=lambda: 501, run=FakeRun(0))
    assert caps.privileged is False
    assert caps.can_sudo is True

    caps = capabilities.detect(which=lambda n: "/usr/bin/sudo", geteuid=lambda: 501, run=FakeRun(1))
    assert caps.can_sudo is False


def test_to_dict_shape_matches_trace_capabilities_block():
    caps = capabilities.detect(
        which=lambda name: "/usr/bin/dig" if name == "dig" else None,
        geteuid=lambda: 501,
        run=FakeRun(1),
    )
    d = caps.to_dict()
    assert d["privileged"] is False
    assert d["tools"] == ["dig"]
    assert "cryptography" in d["libs"]
    assert d["installed_during_run"] == []


def test_ensure_libs_offline_mode_installs_nothing():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    installed = []
    out = capabilities.ensure_libs(
        caps, mode="offline",
        installer=lambda pkg: installed.append(pkg) or True,
        prompt=lambda msg: True,
    )
    assert installed == []
    assert out.libs["cryptography"] is False


def test_ensure_libs_in_venv_installs_without_prompting():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    installed = []
    prompted = []
    out = capabilities.ensure_libs(
        caps, mode="auto", in_venv=True,
        installer=lambda pkg: installed.append(pkg) or True,
        prompt=lambda msg: prompted.append(msg) or True,
    )
    assert installed == ["cryptography"]
    assert prompted == []
    assert out.libs["cryptography"] is True
    assert out.installed_during_run == ["cryptography"]


def test_ensure_libs_outside_venv_asks_first_and_honours_no():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    installed = []
    out = capabilities.ensure_libs(
        caps, mode="auto", in_venv=False,
        installer=lambda pkg: installed.append(pkg) or True,
        prompt=lambda msg: False,
    )
    assert installed == []
    assert out.libs["cryptography"] is False


def test_ensure_libs_records_failed_install_as_unavailable():
    caps = capabilities.Capabilities(
        libs={"cryptography": False}, tools={}, privileged=False,
        can_sudo=False, installed_during_run=[],
    )
    out = capabilities.ensure_libs(
        caps, mode="auto", in_venv=True,
        installer=lambda pkg: False,
        prompt=lambda msg: True,
    )
    assert out.libs["cryptography"] is False
    assert out.installed_during_run == []


def test_pip_name_differs_from_import_name_for_dnspython():
    pip_name, reason = capabilities.OPTIONAL_LIBS["dns"]
    assert pip_name == "dnspython"
    assert reason
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_capabilities.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.capabilities'`

- [ ] **Step 3: Write `wj/capabilities.py`**

```python
"""What this machine can actually do, so every 'not observed' is explainable."""

import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

TOOL_NAMES = (
    "dig", "traceroute", "tracepath", "openssl", "ip", "ifconfig",
    "route", "arp", "ipconfig", "ethtool", "wdutil", "scutil", "sudo",
)

# import name -> (pip name, why this run wants it)
OPTIONAL_LIBS = {
    "dns": ("dnspython", "DNS record types, TTLs, and the delegation walk"),
    "cryptography": ("cryptography", "full certificate chain parsing"),
    "h2": ("h2", "HTTP/2 negotiation"),
}


@dataclass
class Capabilities:
    libs: dict
    tools: dict
    privileged: bool
    can_sudo: bool
    installed_during_run: list = field(default_factory=list)

    def has_tool(self, name):
        return bool(self.tools.get(name))

    def has_lib(self, name):
        return bool(self.libs.get(name))

    def to_dict(self):
        return {
            "privileged": self.privileged,
            "can_sudo": self.can_sudo,
            "tools": sorted(n for n, p in self.tools.items() if p),
            "libs": dict(self.libs),
            "installed_during_run": list(self.installed_during_run),
        }


def _lib_present(import_name):
    return importlib.util.find_spec(import_name) is not None


def detect(which=shutil.which, geteuid=os.geteuid, run=subprocess.run):
    tools = {name: which(name) for name in TOOL_NAMES}
    privileged = geteuid() == 0

    can_sudo = False
    if not privileged and tools.get("sudo"):
        try:
            can_sudo = run(["sudo", "-n", "true"], capture_output=True, timeout=3).returncode == 0
        except Exception:
            can_sudo = False

    libs = {name: _lib_present(name) for name in OPTIONAL_LIBS}
    return Capabilities(libs=libs, tools=tools, privileged=privileged, can_sudo=can_sudo)


def in_virtualenv():
    return sys.prefix != sys.base_prefix


def _pip_install(pip_name):
    try:
        return subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--disable-pip-version-check", pip_name],
            timeout=180,
        ).returncode == 0
    except Exception:
        return False


def ensure_libs(caps, mode="auto", in_venv=None, installer=None, prompt=None):
    """Install missing optional libraries, with a virtualenv guardrail.

    Inside a virtualenv we install quietly. Against a system interpreter we ask
    once, because silently mutating a system Python is unpleasant to undo.
    """
    if mode == "offline":
        return caps

    installer = installer or _pip_install
    prompt = prompt or _confirm
    if in_venv is None:
        in_venv = in_virtualenv()

    missing = [name for name, ok in caps.libs.items() if not ok]
    if not missing:
        return caps

    if not in_venv:
        names = ", ".join(OPTIONAL_LIBS[m][0] for m in missing)
        if not prompt(f"Install {names} into this system Python?"):
            return caps

    for import_name in missing:
        pip_name, _reason = OPTIONAL_LIBS[import_name]
        if installer(pip_name):
            caps.libs[import_name] = True
            caps.installed_during_run.append(import_name)

    return caps


def _confirm(message):
    try:
        return input(f"{message} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_capabilities.py -v`
Expected: PASS, 8 tests

- [ ] **Step 5: Commit**

```bash
git add wj/capabilities.py tests/test_capabilities.py
git commit -m "feat: capability detection and guarded dependency auto-install"
```

---

## Task 4: Run context

**Files:**
- Create: `wj/context.py`
- Test: `tests/test_context.py`

**Interfaces:**
- Consumes: `wj.capabilities.Capabilities`.
- Produces: `Context` dataclass with fields `host: str`, `scheme: str`, `port: int`, `path: str`, `timeout: float`, `deadline: float`, `caps: Capabilities`, `deep: bool`, `privileged: bool`, `no_path: bool`, `geo_hops: bool`, `results: dict`; methods `remaining(now=None) -> float`, `expired(now=None) -> bool`, `budget_for(seconds, now=None) -> float`.
- Also produces `parse_target(raw: str, forced_port: int | None, no_tls: bool) -> tuple[str, str, int, str]` returning `(host, scheme, port, path)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_context.py`:

```python
import pytest

from wj import capabilities
from wj.context import Context, parse_target


def make_ctx(deadline):
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=8.0, deadline=deadline, caps=caps, deep=False,
                   privileged=False, no_path=False, geo_hops=False, results={})


def test_remaining_counts_down_to_the_deadline():
    ctx = make_ctx(deadline=100.0)
    assert ctx.remaining(now=90.0) == pytest.approx(10.0)
    assert ctx.expired(now=90.0) is False


def test_expired_once_the_deadline_passes():
    ctx = make_ctx(deadline=100.0)
    assert ctx.expired(now=100.0) is True
    assert ctx.remaining(now=140.0) == 0.0


def test_budget_for_never_exceeds_remaining_time():
    ctx = make_ctx(deadline=100.0)
    assert ctx.budget_for(30.0, now=95.0) == pytest.approx(5.0)
    assert ctx.budget_for(2.0, now=95.0) == pytest.approx(2.0)


def test_parse_target_defaults_to_https_and_root_path():
    assert parse_target("example.com", None, False) == ("example.com", "https", 443, "/")


def test_parse_target_honours_explicit_url_and_query():
    assert parse_target("https://example.com/a/b?x=1", None, False) == (
        "example.com", "https", 443, "/a/b?x=1")


def test_parse_target_no_tls_switches_scheme_and_port():
    assert parse_target("example.com", None, True) == ("example.com", "http", 80, "/")


def test_parse_target_forced_port_wins():
    assert parse_target("https://example.com", 8443, False) == (
        "example.com", "https", 8443, "/")


def test_parse_target_rejects_input_without_a_hostname():
    with pytest.raises(ValueError):
        parse_target("https:///nohost", None, False)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_context.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.context'`

- [ ] **Step 3: Write `wj/context.py`**

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_context.py -v`
Expected: PASS, 8 tests

- [ ] **Step 5: Commit**

```bash
git add wj/context.py tests/test_context.py
git commit -m "feat: run context with budget arithmetic and target parsing"
```

---

## Task 5: DNS collector

**Files:**
- Create: `wj/collect/dns.py`
- Test: `tests/test_collect_dns.py`, `tests/fixtures/scutil_dns.txt`, `tests/fixtures/resolv.conf`

**Interfaces:**
- Consumes: `wj.context.Context`, `wj.schema.observed/unobserved/add_note`.
- Produces:
  - `RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS")`
  - `parse_https_rr(value: str) -> dict` → `{"alpn": list[str], "ech": bool}`
  - `parse_resolv_conf(text: str) -> list[str]`
  - `parse_scutil_dns(text: str) -> list[str]`
  - `classify_dnssec(ad_flag: bool | None, had_answer: bool) -> str` → `"secure" | "insecure" | "unknown"`
  - `walk_delegation(host: str, query_at, root_ip: str = "198.41.0.4") -> list[dict]`
  - `collect(ctx, query=None, delegation=None, resolvers=None) -> dict`

  `query(name, rtype)` is the injectable seam: it returns `(records, ad_flag)` where `records` is `list[{"data": str, "ttl": int}]` and `ad_flag` is `bool | None`. It raises `LookupError` when the name does not exist.

  **Amended during implementation (Task 5 review, fix round 1).** The seam returns `None` for
  `records` when the query *failed* and `[]` only when the record type is genuinely absent
  (`dns.resolver.NoAnswer`); `collect` stores `[]` for a failed type but names it in an additive
  `records_failed: list[str]` on the section, so "unknown" and "none published" stay distinct.
  The AD flag feeding `classify_dnssec` is taken from `A`/`AAAA` only. Every `RECORD_TYPES` key is
  still present with a list value, so tasks 6, 7, 12 and 18 are unaffected.

  The section shape `collect` returns:

```python
{"observed": True,
 "records": {"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": [], ...},
 "resolver": {"servers": ["1.1.1.1"], "source": "scutil"},
 "dnssec": "insecure",
 "delegation": [{"level": "root", "server": "198.41.0.4", "referral": ["a.gtld-servers.net"]}],
 "alpn_advertised": ["h3", "h2"],
 "ech": False,
 "timing_ms": {"cold": 41.2, "warm": 1.1}}
```

- [ ] **Step 1: Create the resolver-config fixtures**

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
cat > tests/fixtures/resolv.conf <<'EOF'
# Generated by resolvconf
search lan
nameserver 192.168.1.1
nameserver 1.1.1.1
options edns0
EOF
cat > tests/fixtures/scutil_dns.txt <<'EOF'
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 1.1.1.1
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
EOF
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_collect_dns.py`:

```python
from pathlib import Path

import pytest

from wj import capabilities, schema
from wj.collect import dns as dns_collect
from wj.context import Context

FIXTURES = Path(__file__).parent / "fixtures"


def make_ctx(has_dnspython=True):
    caps = capabilities.Capabilities(
        libs={"dns": has_dnspython}, tools={}, privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=8.0, deadline=1e9, caps=caps, results={})


def test_parse_https_rr_extracts_alpn_and_ech():
    out = dns_collect.parse_https_rr('1 . alpn="h3,h2" ipv4hint=104.16.1.1 ech="AEX+DQ"')
    assert out == {"alpn": ["h3", "h2"], "ech": True}


def test_parse_https_rr_without_alpn_or_ech():
    assert dns_collect.parse_https_rr("1 . ipv4hint=104.16.1.1") == {"alpn": [], "ech": False}


def test_parse_resolv_conf_returns_nameservers_in_order():
    text = (FIXTURES / "resolv.conf").read_text()
    assert dns_collect.parse_resolv_conf(text) == ["192.168.1.1", "1.1.1.1"]


def test_parse_scutil_dns_deduplicates_nameservers():
    text = (FIXTURES / "scutil_dns.txt").read_text()
    assert dns_collect.parse_scutil_dns(text) == ["192.168.1.1", "1.1.1.1"]


def test_classify_dnssec():
    assert dns_collect.classify_dnssec(True, True) == "secure"
    assert dns_collect.classify_dnssec(False, True) == "insecure"
    assert dns_collect.classify_dnssec(None, True) == "unknown"


def test_walk_delegation_follows_root_to_authoritative():
    responses = {
        ("198.41.0.4", "example.com", "NS"): {
            "answer": [], "authority": ["a.gtld-servers.net"],
            "additional": {"a.gtld-servers.net": "192.5.6.30"}},
        ("192.5.6.30", "example.com", "NS"): {
            "answer": [], "authority": ["ns1.example.com"],
            "additional": {"ns1.example.com": "203.0.113.9"}},
        ("203.0.113.9", "example.com", "NS"): {
            "answer": ["ns1.example.com"], "authority": [], "additional": {}},
    }

    def query_at(server_ip, name, rtype):
        return responses[(server_ip, name, rtype)]

    walk = dns_collect.walk_delegation("example.com", query_at)
    assert [hop["level"] for hop in walk] == ["root", "tld", "authoritative"]
    assert walk[0]["referral"] == ["a.gtld-servers.net"]
    assert walk[2]["answer"] == ["ns1.example.com"]


def test_walk_delegation_stops_at_the_hop_limit():
    def loops(server_ip, name, rtype):
        return {"answer": [], "authority": ["ns.loop"], "additional": {"ns.loop": "203.0.113.1"}}

    walk = dns_collect.walk_delegation("example.com", loops)
    assert len(walk) <= 8


def test_collect_builds_records_with_ttls():
    answers = {
        "A": ([{"data": "93.184.216.34", "ttl": 300}], False),
        "AAAA": ([], False),
        "HTTPS": ([{"data": '1 . alpn="h3,h2"', "ttl": 60}], False),
    }

    def query(name, rtype):
        return answers.get(rtype, ([], False))

    section = dns_collect.collect(make_ctx(), query=query,
                                  delegation=lambda host: [], resolvers=lambda: ([], "none"))
    assert section["observed"] is True
    assert section["records"]["A"][0] == {"data": "93.184.216.34", "ttl": 300}
    assert section["records"]["AAAA"] == []
    assert section["alpn_advertised"] == ["h3", "h2"]
    assert section["dnssec"] == "insecure"
    assert set(section["records"]) == set(dns_collect.RECORD_TYPES)


def test_collect_marks_unobserved_when_nothing_resolves():
    def query(name, rtype):
        raise LookupError("NXDOMAIN")

    section = dns_collect.collect(make_ctx(), query=query,
                                  delegation=lambda host: [], resolvers=lambda: ([], "none"))
    assert section["observed"] is False
    assert "NXDOMAIN" in section["why_not"] or "did not resolve" in section["why_not"]


def test_collect_without_dnspython_says_so():
    section = dns_collect.collect(make_ctx(has_dnspython=False))
    assert section == {"observed": False, "why_not": "dnspython not installed"}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_collect_dns.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.collect.dns'`

- [ ] **Step 4: Write `wj/collect/dns.py`**

```python
"""Layer 7 riding on 4 and 3: what the name resolves to, and how that answer was found."""

import platform
import re
import subprocess
import time

from wj.schema import observed, unobserved

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS")

ROOT_SERVER_IP = "198.41.0.4"  # a.root-servers.net
MAX_DELEGATION_HOPS = 8


def parse_https_rr(value):
    """Pull ALPN protocols and ECH presence out of an HTTPS/SVCB record's text form."""
    alpn = []
    match = re.search(r'alpn="([^"]+)"', value)
    if match:
        alpn = [p.strip() for p in match.group(1).split(",") if p.strip()]
    return {"alpn": alpn, "ech": "ech=" in value}


def parse_resolv_conf(text):
    return [line.split()[1] for line in text.splitlines()
            if line.strip().startswith("nameserver") and len(line.split()) > 1]


def parse_scutil_dns(text):
    seen = []
    for match in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", text):
        ip = match.group(1)
        if ip not in seen:
            seen.append(ip)
    return seen


def classify_dnssec(ad_flag, had_answer):
    if ad_flag is None:
        return "unknown"
    if not had_answer:
        return "unknown"
    return "secure" if ad_flag else "insecure"


def system_resolvers():
    """Return (servers, source). Best effort; an empty list is a fine answer."""
    if platform.system() == "Darwin":
        try:
            out = subprocess.run(["scutil", "--dns"], capture_output=True,
                                 text=True, timeout=5).stdout
            servers = parse_scutil_dns(out)
            if servers:
                return servers, "scutil"
        except Exception:
            pass
    try:
        with open("/etc/resolv.conf") as fh:
            servers = parse_resolv_conf(fh.read())
        if servers:
            return servers, "resolv.conf"
    except OSError:
        pass
    return [], "unknown"


def walk_delegation(host, query_at, root_ip=ROOT_SERVER_IP):
    """Root -> TLD -> authoritative, following referrals by hand.

    query_at(server_ip, name, rtype) must return
    {"answer": [...], "authority": [...], "additional": {name: ip}}.
    """
    levels = ["root", "tld", "authoritative"]
    walk = []
    server = root_ip

    for hop in range(MAX_DELEGATION_HOPS):
        try:
            response = query_at(server, host, "NS")
        except Exception as exc:
            walk.append({"level": levels[min(hop, len(levels) - 1)],
                         "server": server, "error": str(exc)})
            break

        level = levels[hop] if hop < len(levels) else f"hop{hop + 1}"
        entry = {"level": level, "server": server,
                 "referral": list(response.get("authority", [])),
                 "answer": list(response.get("answer", []))}
        walk.append(entry)

        if entry["answer"]:
            break
        additional = response.get("additional", {})
        next_ip = next((additional[n] for n in entry["referral"] if n in additional), None)
        if not next_ip:
            break
        server = next_ip

    return walk


def _dnspython_query(ctx):
    import dns.flags
    import dns.resolver

    resolver = dns.resolver.Resolver()
    per_query = min(ctx.timeout, 3.0)
    resolver.timeout = per_query
    resolver.lifetime = per_query
    resolver.use_edns(0, dns.flags.DO, 4096)

    def query(name, rtype):
        try:
            answer = resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN as exc:
            raise LookupError(f"NXDOMAIN for {name}") from exc
        except Exception:
            return [], None
        ad = bool(answer.response.flags & dns.flags.AD)
        ttl = answer.rrset.ttl if answer.rrset is not None else 0
        return [{"data": str(r).strip('"'), "ttl": ttl} for r in answer], ad

    return query


def _dnspython_delegation(ctx):
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype

    def query_at(server_ip, name, rtype):
        message = dns.message.make_query(name, rtype)
        message.flags &= ~dns.flags.RD
        response = dns.query.udp(message, server_ip, timeout=min(ctx.timeout, 3.0))
        authority, additional = [], {}
        for rrset in response.authority:
            for item in rrset:
                authority.append(str(item).rstrip("."))
        for rrset in response.additional:
            for item in rrset:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    additional[str(rrset.name).rstrip(".")] = str(item)
        answer = [str(i).rstrip(".") for rrset in response.answer for i in rrset]
        return {"answer": answer, "authority": authority, "additional": additional}

    return lambda host: walk_delegation(host, query_at)


def collect(ctx, query=None, delegation=None, resolvers=None):
    if not ctx.caps.has_lib("dns"):
        return unobserved("dnspython not installed")

    query = query or _dnspython_query(ctx)
    delegation = delegation or _dnspython_delegation(ctx)
    resolvers = resolvers or system_resolvers

    records = {}
    ad_flags = []
    cold_start = time.perf_counter()
    try:
        for rtype in RECORD_TYPES:
            found, ad = query(ctx.host, rtype)
            records[rtype] = found
            if ad is not None:
                ad_flags.append(ad)
    except LookupError as exc:
        return unobserved(str(exc))
    cold_ms = round((time.perf_counter() - cold_start) * 1000, 1)

    if not records.get("A") and not records.get("AAAA"):
        return unobserved(f"{ctx.host} did not resolve to any address")

    warm_start = time.perf_counter()
    try:
        query(ctx.host, "A")
    except LookupError:
        pass
    warm_ms = round((time.perf_counter() - warm_start) * 1000, 1)

    https_info = {"alpn": [], "ech": False}
    if records.get("HTTPS"):
        https_info = parse_https_rr(records["HTTPS"][0]["data"])

    servers, source = resolvers()

    return observed(
        records=records,
        resolver={"servers": servers, "source": source},
        dnssec=classify_dnssec(ad_flags[0] if ad_flags else None, True),
        delegation=delegation(ctx.host),
        alpn_advertised=https_info["alpn"],
        ech=https_info["ech"],
        timing_ms={"cold": cold_ms, "warm": warm_ms},
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_collect_dns.py -v`
Expected: PASS, 10 tests

- [ ] **Step 6: Commit**

```bash
git add wj/collect/dns.py tests/test_collect_dns.py tests/fixtures/resolv.conf tests/fixtures/scutil_dns.txt
git commit -m "feat: DNS collector with TTLs, delegation walk, DNSSEC and HTTPS RR"
```

---

## Task 6: TCP collector with Happy Eyeballs

**Files:**
- Create: `wj/collect/tcp.py`
- Test: `tests/test_collect_tcp.py`

**Interfaces:**
- Consumes: `wj.context.Context`; reads `ctx.results["dns"]` for candidate addresses.
- Produces:
  - `candidates_from_dns(dns_section: dict) -> list[dict]` → `[{"ip": str, "family": "ipv6"|"ipv4"}]`, IPv6 first per RFC 8305
  - `connect_one(ip: str, family: str, port: int, timeout: float) -> dict` → `{"ip", "family", "connect_ms", "error", "socket"}`
  - `read_kernel_info(sock) -> dict | None` → `{"rtt_ms", "mss", "retransmits", "source"}`
  - `collect(ctx) -> dict`

  Section shape:

```python
{"observed": True,
 "candidates": [{"ip": "93.184.216.34", "family": "ipv4", "connect_ms": 12.4, "error": None}],
 "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443},
 "winner_family": "ipv4",
 "local": {"ip": "192.168.1.23", "port": 54213},
 "kernel": {"rtt_ms": 12.4, "mss": 1460, "retransmits": 0, "source": "TCP_CONNECTION_INFO"}}
```

  `collect` stores the live socket on the returned dict under the key `"_socket"`, which the orchestrator hands to the TLS and HTTP collectors and strips before export.

  **Amended during implementation (Task 6 review, fix round 1).** The struct offsets in
  `read_kernel_info` were wrong and are corrected: macOS `tcpi_srtt` is a u32 of milliseconds at
  **offset 44** (offset 32, which the draft used, is `tcpi_snd_sbbytes` — proved empirically by
  sending 200,000 bytes and watching that word read back exactly 200000); Linux `tcpi_retransmits`
  is at **offset 2** and `tcpi_rtt` at **offset 68** in microseconds. A pure
  `plausible_rtt_ms(value)` guard (`IMPLAUSIBLE_RTT_MS = 60_000`) now filters both branches, so an
  offset that drifts on a future kernel yields an absent RTT rather than a wrong one — the Linux
  branch cannot be executed on a Darwin machine, and an unverifiable offset must fail toward absent.

- [ ] **Step 1: Write the failing test**

Create `tests/test_collect_tcp.py`:

```python
import socket

import pytest

from wj import capabilities
from wj.collect import tcp as tcp_collect
from wj.context import Context


@pytest.fixture
def listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    yield server.getsockname()[1]
    server.close()


def make_ctx(port):
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="localhost", scheme="https", port=port, path="/",
                  timeout=3.0, deadline=1e9, caps=caps, results={})
    ctx.results["dns"] = {"observed": True,
                          "records": {"A": [{"data": "127.0.0.1", "ttl": 60}], "AAAA": []}}
    return ctx


def test_candidates_put_ipv6_first():
    section = {"observed": True, "records": {
        "A": [{"data": "93.184.216.34", "ttl": 300}],
        "AAAA": [{"data": "2606:2800::1", "ttl": 300}]}}
    assert tcp_collect.candidates_from_dns(section) == [
        {"ip": "2606:2800::1", "family": "ipv6"},
        {"ip": "93.184.216.34", "family": "ipv4"},
    ]


def test_candidates_from_unobserved_dns_is_empty():
    assert tcp_collect.candidates_from_dns({"observed": False, "why_not": "x"}) == []


def test_connect_one_succeeds_against_a_real_listener(listening_port):
    result = tcp_collect.connect_one("127.0.0.1", "ipv4", listening_port, timeout=2.0)
    assert result["error"] is None
    assert result["connect_ms"] >= 0
    assert result["socket"] is not None
    result["socket"].close()


def test_connect_one_records_refusal_without_raising():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()

    result = tcp_collect.connect_one("127.0.0.1", "ipv4", port, timeout=2.0)
    assert result["socket"] is None
    assert result["error"]


def test_collect_reports_local_port_and_winner(listening_port):
    section = tcp_collect.collect(make_ctx(listening_port))
    assert section["observed"] is True
    assert section["chosen"]["ip"] == "127.0.0.1"
    assert section["winner_family"] == "ipv4"
    assert section["local"]["port"] > 0
    assert len(section["candidates"]) == 1
    assert section["candidates"][0]["error"] is None
    section["_socket"].close()


def test_collect_without_addresses_is_unobserved():
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=1.0, deadline=1e9, caps=caps, results={})
    ctx.results["dns"] = {"observed": False, "why_not": "did not resolve"}
    section = tcp_collect.collect(ctx)
    assert section["observed"] is False
    assert "no resolved address" in section["why_not"]


def test_candidates_carry_no_socket_key_in_exportable_output(listening_port):
    section = tcp_collect.collect(make_ctx(listening_port))
    for candidate in section["candidates"]:
        assert "socket" not in candidate
    section["_socket"].close()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_collect_tcp.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.collect.tcp'`

- [ ] **Step 3: Write `wj/collect/tcp.py`**

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_collect_tcp.py -v`
Expected: PASS, 7 tests

- [ ] **Step 5: Commit**

```bash
git add wj/collect/tcp.py tests/test_collect_tcp.py
git commit -m "feat: TCP collector with Happy Eyeballs and kernel connection info"
```

---

## Task 7: TLS collector

**Files:**
- Create: `wj/collect/tls.py`
- Test: `tests/test_collect_tls.py`, `tests/fixtures/make_cert.py`, `tests/fixtures/leaf.der`

**Interfaces:**
- Consumes: `wj.context.Context`; reads `ctx.results["tcp"]["_socket"]` and `ctx.results["dns"]["records"]["CAA"]`.
- Produces:
  - `summarise_cert(der: bytes) -> dict` → `{"subject_cn", "issuer_cn", "not_before", "not_after", "days_left", "key": {"type", "bits"}, "sig_algo", "sans": list[str], "scts": int, "ocsp": list[str], "is_ca": bool}`
  - `caa_allows(caa_records: list[dict], issuer_cn: str) -> bool | None`
    **Amended during implementation (Task 7).** The draft's brand-substring fallback compared raw
    lowercased strings, so `caa_allows(…, "R3 (Let's Encrypt)")` returned `False` where the task's own
    test asserts `None` — the apostrophe and space break the match against `letsencrypt`. Both sides of
    that fallback are now normalised to alphanumerics. The exact-match `True` branch is untouched, so
    the change can only soften a `False` into a `None`, never inflate anything into a `True`.
  - `grade_expiry(days_left: int) -> tuple[str, str] | None` → `(severity, message)` or `None` when healthy
  - `collect(ctx) -> dict`

  Section shape:

```python
{"observed": True, "version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
 "alpn": "h2", "handshake_ms": 38.2,
 "chain": [ ...summarise_cert dicts, leaf first... ],
 "trust_root": "ISRG Root X1", "verified": True, "caa_match": True,
 "resumption": {"tested": False}, "legacy_versions_accepted": []}
```

- [ ] **Step 1: Generate the certificate fixture**

Create `tests/fixtures/make_cert.py`:

```python
"""Regenerate leaf.der. Run once; the DER file is the committed fixture."""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA R3")])
now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=90))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("example.com"), x509.DNSName("www.example.com")]),
        critical=False,
    )
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

Path(__file__).with_name("leaf.der").write_bytes(
    cert.public_bytes(serialization.Encoding.DER))
print("wrote leaf.der")
```

Run it:

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
.venv/bin/python -m pip install --quiet cryptography
.venv/bin/python tests/fixtures/make_cert.py
```

Expected: `wrote leaf.der`, and `tests/fixtures/leaf.der` exists.

- [ ] **Step 2: Write the failing test**

Create `tests/test_collect_tls.py`:

```python
from pathlib import Path

import pytest

from wj.collect import tls as tls_collect

FIXTURES = Path(__file__).parent / "fixtures"


def leaf_der():
    return (FIXTURES / "leaf.der").read_bytes()


def test_summarise_cert_reads_subject_issuer_and_sans():
    info = tls_collect.summarise_cert(leaf_der())
    assert info["subject_cn"] == "example.com"
    assert info["issuer_cn"] == "Test CA R3"
    assert info["sans"] == ["example.com", "www.example.com"]
    assert info["is_ca"] is False


def test_summarise_cert_reports_key_and_signature():
    info = tls_collect.summarise_cert(leaf_der())
    assert info["key"] == {"type": "RSA", "bits": 2048}
    assert "sha256" in info["sig_algo"].lower()


def test_summarise_cert_computes_days_left_against_a_fixed_now():
    import datetime
    now = datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc)
    info = tls_collect.summarise_cert(leaf_der(), now=now)
    assert info["days_left"] == 59


def test_caa_allows_matches_on_issuer_substring():
    caa = [{"data": '0 issue "letsencrypt.org"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "R3 (Let's Encrypt)") is None
    assert tls_collect.caa_allows(caa, "letsencrypt.org") is True
    assert tls_collect.caa_allows(caa, "DigiCert Global Root") is False


def test_caa_allows_is_unknown_when_no_caa_published():
    assert tls_collect.caa_allows([], "anyone") is None


def test_grade_expiry_thresholds():
    assert tls_collect.grade_expiry(90) is None
    severity, message = tls_collect.grade_expiry(9)
    assert severity == "warn" and "9" in message
    severity, message = tls_collect.grade_expiry(-1)
    assert severity == "critical"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_collect_tls.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.collect.tls'`

- [ ] **Step 4: Write `wj/collect/tls.py`**

```python
"""Layers 6 and 5: what was negotiated, which certificates were presented, and why they are trusted."""

import datetime
import re
import ssl
import subprocess
import time

from wj.schema import observed, unobserved

EXPIRY_WARN_DAYS = 21


def summarise_cert(der, now=None):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.datetime.now(datetime.timezone.utc)

    def common_name(name):
        values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if values:
            return values[0].value
        org = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return org[0].value if org else None

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_info = {"type": "RSA", "bits": key.key_size}
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_info = {"type": "EC", "bits": key.curve.key_size}
    else:
        key_info = {"type": type(key).__name__, "bits": getattr(key, "key_size", None)}

    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        pass

    scts = 0
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        scts = len(ext.value)
    except x509.ExtensionNotFound:
        pass

    ocsp = []
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp = [d.access_location.value for d in aia
                if d.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"]
    except x509.ExtensionNotFound:
        pass

    not_after = cert.not_valid_after_utc
    return {
        "subject_cn": common_name(cert.subject),
        "issuer_cn": common_name(cert.issuer),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "key": key_info,
        "sig_algo": cert.signature_algorithm_oid._name,
        "sans": list(sans),
        "scts": scts,
        "ocsp": ocsp,
        "is_ca": is_ca,
    }


def caa_allows(caa_records, issuer_cn):
    """True/False when CAA is published and comparable, None when it cannot be judged."""
    if not caa_records or not issuer_cn:
        return None
    issuers = []
    for record in caa_records:
        match = re.search(r'issue(?:wild)?\s+"([^"]+)"', record.get("data", ""))
        if match:
            issuers.append(match.group(1).lower())
    if not issuers:
        return None
    haystack = issuer_cn.lower()
    if any(i in haystack for i in issuers):
        return True
    if any(i.split(".")[0] in haystack for i in issuers):
        return None  # plausible match on the brand alone — not proof either way
    return False


def grade_expiry(days_left):
    if days_left < 0:
        return ("critical", f"certificate expired {abs(days_left)} days ago")
    if days_left <= EXPIRY_WARN_DAYS:
        return ("warn", f"certificate expires in {days_left} days")
    return None


def _chain_via_openssl(host, port, timeout):
    try:
        out = subprocess.run(
            ["openssl", "s_client", "-showcerts", "-servername", host,
             "-connect", f"{host}:{port}"],
            input="", capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return []
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    return [ssl.PEM_cert_to_DER_cert(p) for p in pems]


def collect(ctx):
    if ctx.scheme != "https":
        return unobserved("plain HTTP requested — no TLS layer in this trace")

    tcp = ctx.results.get("tcp", {})
    sock = tcp.get("_socket")
    if sock is None:
        return unobserved("no TCP connection to negotiate over")

    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    sock.settimeout(ctx.budget_for(ctx.timeout))

    started = time.perf_counter()
    try:
        tls_sock = context.wrap_socket(sock, server_hostname=ctx.host)
    except ssl.SSLError as exc:
        return unobserved(f"TLS handshake failed: {exc}")
    except OSError as exc:
        return unobserved(f"TLS handshake failed: {exc}")
    handshake_ms = round((time.perf_counter() - started) * 1000, 1)

    ders = []
    getter = getattr(tls_sock, "get_verified_chain", None)
    if getter:
        try:
            ders = [c.public_bytes(ssl._ssl.ENCODING_DER) if hasattr(c, "public_bytes")
                    else c for c in getter()]
        except Exception:
            ders = []
    if not ders:
        leaf = tls_sock.getpeercert(True)
        ders = [leaf] if leaf else []
        ders += _chain_via_openssl(ctx.host, ctx.port, min(ctx.timeout, 5))[1:]

    chain = []
    if ctx.caps.has_lib("cryptography"):
        for der in ders:
            try:
                chain.append(summarise_cert(der))
            except Exception:
                continue

    caa_records = ctx.results.get("dns", {}).get("records", {}).get("CAA", [])
    issuer = chain[0]["issuer_cn"] if chain else None

    section = observed(
        version=tls_sock.version(),
        cipher=(tls_sock.cipher() or [None])[0],
        alpn=tls_sock.selected_alpn_protocol(),
        handshake_ms=handshake_ms,
        chain=chain,
        trust_root=chain[-1]["subject_cn"] if len(chain) > 1 else None,
        verified=True,
        caa_match=caa_allows(caa_records, issuer),
        resumption={"tested": False},
        legacy_versions_accepted=[],
    )
    section["_socket"] = tls_sock
    return section
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_collect_tls.py -v`
Expected: PASS, 6 tests

- [ ] **Step 6: Commit**

```bash
git add wj/collect/tls.py tests/test_collect_tls.py tests/fixtures/make_cert.py tests/fixtures/leaf.der
git commit -m "feat: TLS collector with chain parsing, ALPN and CAA cross-check"
```

---

## Task 8: HTTP collector

**Files:**
- Create: `wj/collect/http.py`
- Test: `tests/test_collect_http.py`

**Interfaces:**
- Consumes: `wj.context.Context`; reads the socket left by TLS (`ctx.results["tls"]["_socket"]`) or TCP (`ctx.results["tcp"]["_socket"]`).
- Produces:
  - `parse_response(raw: bytes) -> dict` → `{"protocol", "status", "reason", "headers": list[tuple[str, str]], "body": bytes}`
  - `header_value(headers, name) -> str | None` (case-insensitive)
  - `dechunk(body: bytes) -> bytes`
  - `decode_body(headers, body: bytes) -> tuple[bytes, str | None]`
  - `parse_cookies(headers) -> list[dict]` → `[{"name", "secure", "httponly", "samesite"}]`
  - `grade_security(headers, scheme: str) -> dict` → `{"grade", "present", "missing", "cookies"}`
  - `cache_state(headers) -> dict` → `{"state", "age", "header", "directives"}`
  - `detect_cdn(headers) -> str | None`
  - `collect(ctx, fetch=None) -> dict`

  `fetch(url, path, sock)` is the injectable seam returning the `parse_response` dict plus `{"ttfb_ms", "total_ms", "wire_bytes"}`.

  **Amended during implementation (Tasks 7-8 reviews).** Five corrections to the draft below:
  (1) the socket fallback `tls.get("_socket") or tcp.get("_socket")` is unsafe — `wrap_socket()`
  detaches the underlying fd before the handshake and closes it on failure, so after a failed
  handshake the TCP socket is dead. `collect` now branches: TLS observed → its socket; else scheme is
  https → `unobserved("no encrypted channel: …")` touching no socket; else → the TCP socket (still
  required for `--no-tls`). (2) `final["url"]` now comes from a separate `fetched_url` tracked at each
  successful fetch — the draft reassigned `url` before the loop ended, so a chain hitting
  `MAX_REDIRECTS` reported an unfetched URL alongside the previous hop's measurements. (3) the section
  carries `redirect_limit_reached: bool`, so a truncated chain is visible rather than silent.
  (4) `fetch` closes the per-hop sockets `_open` creates (`opened_here = sock is None`, `try/finally`)
  and never the first hop's, which belongs to the orchestrator. (5) `content_type` and `reason` are
  `None` when absent, not `""` — an empty string is a fabricated value, not a measurement.

  Section shape:

```python
{"observed": True,
 "hops": [{"url": "http://example.com/", "status": 301,
           "location": "https://example.com/", "protocol": "HTTP/1.1", "ttfb_ms": 40.1}],
 "final": {"url": "...", "status": 200, "protocol": "HTTP/1.1", "headers": [["server", "ECS"]],
           "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000,
           "decoded_bytes": 61000, "encoding": "gzip", "ratio": 4.36,
           "content_type": "text/html"},
 "cache": {...}, "cdn": "Cloudflare", "security": {...},
 "conditional": {"tested": False}}
```

- [ ] **Step 1: Write the failing test**

Create `tests/test_collect_http.py`:

```python
import gzip

import pytest

from wj.collect import http as http_collect

RAW_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Encoding: gzip\r\n"
    b"Cache-Control: max-age=300\r\n"
    b"\r\n"
)


def test_parse_response_splits_status_headers_and_body():
    raw = RAW_200 + b"BODYBYTES"
    parsed = http_collect.parse_response(raw)
    assert parsed["protocol"] == "HTTP/1.1"
    assert parsed["status"] == 200
    assert parsed["reason"] == "OK"
    assert ("Content-Type", "text/html; charset=utf-8") in parsed["headers"]
    assert parsed["body"] == b"BODYBYTES"


def test_parse_response_survives_a_truncated_status_line():
    parsed = http_collect.parse_response(b"")
    assert parsed["status"] is None
    assert parsed["headers"] == []


def test_header_value_is_case_insensitive():
    headers = [("Content-Type", "text/html")]
    assert http_collect.header_value(headers, "content-type") == "text/html"
    assert http_collect.header_value(headers, "missing") is None


def test_dechunk_reassembles_chunked_body():
    chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    assert http_collect.dechunk(chunked) == b"hello world"


def test_decode_body_inflates_gzip_and_reports_encoding():
    payload = b"<html>" + b"x" * 500 + b"</html>"
    headers = [("Content-Encoding", "gzip")]
    decoded, encoding = http_collect.decode_body(headers, gzip.compress(payload))
    assert decoded == payload
    assert encoding == "gzip"


def test_decode_body_passes_plain_bodies_through():
    decoded, encoding = http_collect.decode_body([], b"plain")
    assert decoded == b"plain"
    assert encoding is None


def test_decode_body_dechunks_before_inflating():
    payload = b"y" * 40
    blob = gzip.compress(payload)
    chunked = b"%x\r\n" % len(blob) + blob + b"\r\n0\r\n\r\n"
    headers = [("Transfer-Encoding", "chunked"), ("Content-Encoding", "gzip")]
    decoded, encoding = http_collect.decode_body(headers, chunked)
    assert decoded == payload


def test_parse_cookies_reads_flags():
    headers = [("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"),
               ("Set-Cookie", "tracking=1; Path=/")]
    cookies = http_collect.parse_cookies(headers)
    assert cookies[0] == {"name": "session", "secure": True,
                          "httponly": True, "samesite": "Lax"}
    assert cookies[1] == {"name": "tracking", "secure": False,
                          "httponly": False, "samesite": None}


def test_grade_security_full_house_scores_a():
    headers = [
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    ]
    result = http_collect.grade_security(headers, "https")
    assert result["grade"] == "A"
    assert result["missing"] == []


def test_grade_security_names_what_is_missing():
    result = http_collect.grade_security([("X-Content-Type-Options", "nosniff")], "https")
    assert result["grade"] == "F"
    assert "Content-Security-Policy" in result["missing"]
    assert "X-Content-Type-Options" not in result["missing"]


def test_cache_state_reads_cdn_hit_and_age():
    headers = [("cf-cache-status", "HIT"), ("Age", "412"),
               ("Cache-Control", "max-age=300")]
    state = http_collect.cache_state(headers)
    assert state["state"] == "HIT"
    assert state["age"] == 412
    assert state["header"] == "cf-cache-status"
    assert state["directives"] == "max-age=300"


def test_cache_state_when_nothing_is_advertised():
    state = http_collect.cache_state([])
    assert state["state"] is None
    assert state["age"] is None


def test_detect_cdn_from_signature_headers():
    assert http_collect.detect_cdn([("cf-ray", "8a2b")]) == "Cloudflare"
    assert http_collect.detect_cdn([("x-amz-cf-id", "abc")]) == "CloudFront"
    assert http_collect.detect_cdn([("x-served-by", "cache-fra-1"),
                                    ("x-cache", "HIT")]) == "Fastly"
    assert http_collect.detect_cdn([("server", "nginx")]) is None


def test_collect_follows_a_redirect_chain(monkeypatch):
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}

    pages = {
        "https://example.com/": {
            "protocol": "HTTP/1.1", "status": 301, "reason": "Moved Permanently",
            "headers": [("Location", "https://www.example.com/")], "body": b"",
            "ttfb_ms": 40.0, "total_ms": 41.0, "wire_bytes": 200},
        "https://www.example.com/": {
            "protocol": "HTTP/1.1", "status": 200, "reason": "OK",
            "headers": [("Content-Type", "text/html")], "body": b"<html></html>",
            "ttfb_ms": 60.0, "total_ms": 70.0, "wire_bytes": 13},
    }

    section = http_collect.collect(ctx, fetch=lambda url, sock: pages[url])
    assert section["observed"] is True
    assert len(section["hops"]) == 1
    assert section["hops"][0]["status"] == 301
    assert section["final"]["status"] == 200
    assert section["final"]["url"] == "https://www.example.com/"
    assert section["final"]["decoded_bytes"] == 13


def test_collect_stops_at_the_redirect_limit():
    from wj import capabilities
    from wj.context import Context

    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "_socket": object()}

    def always_redirect(url, sock):
        return {"protocol": "HTTP/1.1", "status": 302, "reason": "Found",
                "headers": [("Location", "https://example.com/next")], "body": b"",
                "ttfb_ms": 1.0, "total_ms": 1.0, "wire_bytes": 10}

    section = http_collect.collect(ctx, fetch=always_redirect)
    assert len(section["hops"]) <= http_collect.MAX_REDIRECTS
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_collect_http.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.collect.http'`

- [ ] **Step 3: Write `wj/collect/http.py`**

```python
"""Layer 7: the request, every redirect it took, and what the response tells you."""

import gzip
import time
import zlib
from urllib.parse import urljoin, urlsplit

from wj.schema import observed, unobserved

MAX_REDIRECTS = 10
DEFAULT_PORTS = {"http": 80, "https": 443}

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
)

GRADE_THRESHOLDS = ((6, "A"), (5, "B"), (4, "C"), (3, "D"), (2, "E"))

CDN_SIGNATURES = (
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "CloudFront"),
    ("x-served-by", "Fastly"),
    ("x-akamai-transformed", "Akamai"),
    ("x-vercel-id", "Vercel"),
)

CACHE_HEADERS = ("cf-cache-status", "x-cache", "x-drupal-cache", "x-vercel-cache")


def header_value(headers, name):
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None


def parse_response(raw):
    blob, _, body = raw.partition(b"\r\n\r\n")
    lines = blob.decode("latin-1", errors="replace").split("\r\n")
    protocol = status = reason = None
    if lines and lines[0]:
        parts = lines[0].split(" ", 2)
        protocol = parts[0] if parts else None
        if len(parts) > 1:
            try:
                status = int(parts[1])
            except ValueError:
                status = None
        reason = parts[2] if len(parts) > 2 else ""

    headers = []
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers.append((key.strip(), value.strip()))

    return {"protocol": protocol, "status": status, "reason": reason,
            "headers": headers, "body": body}


def dechunk(body):
    out = bytearray()
    rest = body
    while rest:
        size_line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        rest = rest[size:].lstrip(b"\r\n")
    return bytes(out)


def decode_body(headers, body):
    if (header_value(headers, "transfer-encoding") or "").lower() == "chunked":
        body = dechunk(body)

    encoding = (header_value(headers, "content-encoding") or "").lower() or None
    if encoding == "gzip":
        try:
            return gzip.decompress(body), "gzip"
        except OSError:
            return body, "gzip"
    if encoding == "deflate":
        try:
            return zlib.decompress(body), "deflate"
        except zlib.error:
            return body, "deflate"
    if encoding == "br":
        try:
            import brotli
            return brotli.decompress(body), "br"
        except Exception:
            return body, "br"
    return body, encoding


def parse_cookies(headers):
    cookies = []
    for key, value in headers:
        if key.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in value.split(";")]
        name = parts[0].split("=", 1)[0] if parts else ""
        flags = [p.lower() for p in parts[1:]]
        samesite = None
        for part in parts[1:]:
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1]
        cookies.append({"name": name,
                        "secure": "secure" in flags,
                        "httponly": "httponly" in flags,
                        "samesite": samesite})
    return cookies


def grade_security(headers, scheme):
    present = {}
    missing = []
    for name in SECURITY_HEADERS:
        value = header_value(headers, name)
        if value:
            present[name] = value
        else:
            missing.append(name)

    score = len(present)
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return {"grade": grade, "present": present, "missing": missing,
            "cookies": parse_cookies(headers), "scheme": scheme}


def cache_state(headers):
    state = header_name = None
    for name in CACHE_HEADERS:
        value = header_value(headers, name)
        if value:
            state = value.split()[0].upper()
            header_name = name
            break

    age = header_value(headers, "age")
    try:
        age = int(age) if age is not None else None
    except ValueError:
        age = None

    return {"state": state, "age": age, "header": header_name,
            "directives": header_value(headers, "cache-control")}


def detect_cdn(headers):
    for name, cdn in CDN_SIGNATURES:
        if header_value(headers, name):
            return cdn
    server = (header_value(headers, "server") or "").lower()
    if "cloudflare" in server:
        return "Cloudflare"
    return None


def _open(split, ctx):
    """Open a connection for a redirect hop, matching the URL's own scheme."""
    import socket
    import ssl

    port = split.port or DEFAULT_PORTS.get(split.scheme, 443)
    sock = socket.create_connection((split.hostname, port), timeout=ctx.budget_for(ctx.timeout))
    if split.scheme == "https":
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        sock = context.wrap_socket(sock, server_hostname=split.hostname)
    return sock


def _socket_fetch(ctx):
    def fetch(url, sock):
        split = urlsplit(url)
        if sock is None:
            # Each redirect hop needs a fresh connection: the first one was opened by
            # the TCP/TLS collectors and closes after this response (Connection: close).
            sock = _open(split, ctx)
        path = split.path or "/"
        if split.query:
            path += "?" + split.query
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {split.hostname}\r\n"
            f"User-Agent: webpage-journey/2.0\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        sock.settimeout(ctx.budget_for(ctx.timeout))
        started = time.perf_counter()
        sock.sendall(request)

        chunks = []
        ttfb = None
        while True:
            try:
                data = sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            if ttfb is None:
                ttfb = round((time.perf_counter() - started) * 1000, 1)
            chunks.append(data)

        raw = b"".join(chunks)
        parsed = parse_response(raw)
        parsed["ttfb_ms"] = ttfb
        parsed["total_ms"] = round((time.perf_counter() - started) * 1000, 1)
        parsed["wire_bytes"] = len(parsed["body"])
        return parsed

    return fetch


def collect(ctx, fetch=None):
    tls = ctx.results.get("tls", {})
    tcp = ctx.results.get("tcp", {})
    sock = tls.get("_socket") or tcp.get("_socket")
    if sock is None:
        return unobserved("no connection to send a request over")

    fetch = fetch or _socket_fetch(ctx)

    url = f"{ctx.scheme}://{ctx.host}{ctx.path}"
    hops = []
    response = None

    for _ in range(MAX_REDIRECTS):
        try:
            response = fetch(url, sock)
        except OSError as exc:
            section = unobserved(f"request failed: {exc}")
            section["hops"] = hops
            return section

        status = response.get("status")
        location = header_value(response["headers"], "location")
        if status is None:
            section = unobserved("no response received before the timeout")
            section["hops"] = hops
            return section

        if 300 <= status < 400 and location:
            hops.append({"url": url, "status": status,
                         "location": urljoin(url, location),
                         "protocol": response.get("protocol"),
                         "ttfb_ms": response.get("ttfb_ms")})
            url = urljoin(url, location)
            sock = None  # fetch opens a fresh connection for the next hop
            continue
        break

    decoded, encoding = decode_body(response["headers"], response["body"])
    wire = response.get("wire_bytes") or len(response["body"])
    ratio = round(len(decoded) / wire, 2) if wire and encoding else None
    content_type = (header_value(response["headers"], "content-type") or "").split(";")[0]

    return observed(
        hops=hops,
        final={"url": url, "status": response["status"], "reason": response.get("reason"),
               "protocol": response.get("protocol"), "headers": response["headers"],
               "ttfb_ms": response.get("ttfb_ms"), "total_ms": response.get("total_ms"),
               "wire_bytes": wire, "decoded_bytes": len(decoded),
               "encoding": encoding, "ratio": ratio, "content_type": content_type},
        cache=cache_state(response["headers"]),
        cdn=detect_cdn(response["headers"]),
        security=grade_security(response["headers"], ctx.scheme),
        conditional={"tested": False},
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_collect_http.py -v`
Expected: PASS, 15 tests

- [ ] **Step 5: Commit**

```bash
git add wj/collect/http.py tests/test_collect_http.py
git commit -m "feat: HTTP collector with redirect chain, decoding and security grading"
```

---

## Task 9: Network path collector

**Files:**
- Create: `wj/collect/path.py`
- Test: `tests/test_collect_path.py`, `tests/fixtures/traceroute_darwin.txt`, `tests/fixtures/traceroute_linux.txt`

**Interfaces:**
- Consumes: `wj.context.Context`; reads `ctx.results["tcp"]["chosen"]["ip"]`.
- Produces:
  - `parse_traceroute(text: str) -> list[dict]` → `[{"ttl", "ip", "rdns", "rtt_ms"}]`, unresponsive hops have `ip=None`
  - `parse_cymru_txt(value: str) -> dict` → `{"asn": int | None, "prefix": str | None, "country": str | None}`
  - `cymru_name(ip: str) -> str` → the reversed-nibble query name for `origin.asn.cymru.com`
  - `asn_path(hops: list[dict]) -> list[int]` — ASNs in order, duplicates collapsed, `None` dropped
  - `collect(ctx, run=None, asn_lookup=None) -> dict`

  Section shape:

```python
{"observed": True, "source": "traceroute",
 "hops": [{"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan",
           "rtt_ms": 1.23, "asn": None, "as_name": None}],
 "asn_path": [8708, 13335], "path_mtu": None}
```

- [ ] **Step 1: Create the traceroute fixtures**

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
cat > tests/fixtures/traceroute_darwin.txt <<'EOF'
traceroute to example.com (93.184.216.34), 64 hops max, 52 byte packets
 1  router.lan (192.168.1.1)  1.234 ms  1.100 ms  1.050 ms
 2  * * *
 3  10.20.30.1 (10.20.30.1)  8.123 ms  7.990 ms  8.200 ms
 4  ae-1.border.example.net (203.0.113.9)  14.502 ms  14.110 ms  13.980 ms
 5  93.184.216.34 (93.184.216.34)  15.001 ms  14.880 ms  14.920 ms
EOF
cat > tests/fixtures/traceroute_linux.txt <<'EOF'
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  0.512 ms  0.489 ms  0.470 ms
 2  * * *
 3  ae-1.border.example.net (203.0.113.9)  12.004 ms  11.880 ms  11.910 ms
 4  93.184.216.34 (93.184.216.34)  13.220 ms  13.100 ms  13.050 ms
EOF
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_collect_path.py`:

```python
from pathlib import Path

import pytest

from wj import capabilities
from wj.collect import path as path_collect
from wj.context import Context

FIXTURES = Path(__file__).parent / "fixtures"


def make_ctx(has_traceroute=True, no_path=False):
    caps = capabilities.Capabilities(
        libs={"dns": True},
        tools={"traceroute": "/usr/sbin/traceroute" if has_traceroute else None},
        privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, no_path=no_path, results={})
    ctx.results["tcp"] = {"observed": True,
                          "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443}}
    return ctx


def test_parse_traceroute_darwin_reads_every_hop():
    hops = path_collect.parse_traceroute((FIXTURES / "traceroute_darwin.txt").read_text())
    assert len(hops) == 5
    assert hops[0] == {"ttl": 1, "ip": "192.168.1.1",
                       "rdns": "router.lan", "rtt_ms": 1.234}
    assert hops[4]["ip"] == "93.184.216.34"


def test_parse_traceroute_marks_unresponsive_hops():
    hops = path_collect.parse_traceroute((FIXTURES / "traceroute_darwin.txt").read_text())
    assert hops[1] == {"ttl": 2, "ip": None, "rdns": None, "rtt_ms": None}


def test_parse_traceroute_linux_gateway_alias():
    hops = path_collect.parse_traceroute((FIXTURES / "traceroute_linux.txt").read_text())
    assert hops[0]["rdns"] == "_gateway"
    assert hops[0]["ip"] == "192.168.1.1"
    assert len(hops) == 4


def test_parse_traceroute_ignores_the_banner_line():
    hops = path_collect.parse_traceroute("traceroute to example.com (1.2.3.4), 64 hops max\n")
    assert hops == []


def test_cymru_name_reverses_the_octets():
    assert path_collect.cymru_name("93.184.216.34") == "34.216.184.93.origin.asn.cymru.com"


def test_parse_cymru_txt_reads_asn_and_prefix():
    out = path_collect.parse_cymru_txt("15133 | 93.184.216.0/24 | US | arin | 2008-06-02")
    assert out == {"asn": 15133, "prefix": "93.184.216.0/24", "country": "US"}


def test_parse_cymru_txt_handles_multi_origin_answers():
    out = path_collect.parse_cymru_txt("3356 1299 | 203.0.113.0/24 | EU | ripencc | 2010-01-01")
    assert out["asn"] == 3356


def test_asn_path_collapses_repeats_and_drops_unknowns():
    hops = [{"asn": None}, {"asn": 8708}, {"asn": 8708}, {"asn": 1299}, {"asn": None}]
    assert path_collect.asn_path(hops) == [8708, 1299]


def test_collect_annotates_hops_with_asn():
    ctx = make_ctx()

    def fake_run(cmd, timeout):
        return (FIXTURES / "traceroute_darwin.txt").read_text()

    def fake_asn(ip):
        return {"asn": 13335, "prefix": "93.184.216.0/24", "country": "US"} \
            if ip == "93.184.216.34" else {"asn": None, "prefix": None, "country": None}

    section = path_collect.collect(ctx, run=fake_run, asn_lookup=fake_asn)
    assert section["observed"] is True
    assert section["source"] == "traceroute"
    assert section["hops"][4]["asn"] == 13335
    assert section["asn_path"] == [13335]


def test_collect_skipped_by_flag():
    section = path_collect.collect(make_ctx(no_path=True))
    assert section == {"observed": False, "why_not": "skipped with --no-path"}


def test_collect_without_traceroute_explains_itself():
    section = path_collect.collect(make_ctx(has_traceroute=False))
    assert section["observed"] is False
    assert "traceroute not on PATH" in section["why_not"]
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_collect_path.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.collect.path'`

- [ ] **Step 4: Write `wj/collect/path.py`**

```python
"""Layer 3: the hops between you and the destination, and whose networks they belong to."""

import re
import subprocess

from wj.schema import observed, unobserved

HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
ADDR_RE = re.compile(r"([\w.\-]+)\s+\(([\d.:a-fA-F]+)\)")
BARE_IP_RE = re.compile(r"^([\d.]+|[0-9a-fA-F:]+)\s")
RTT_RE = re.compile(r"([\d.]+)\s*ms")


def parse_traceroute(text):
    """Parse traceroute output from either macOS or Linux into ordered hops."""
    hops = []
    for line in text.splitlines():
        if line.lower().startswith("traceroute"):
            continue
        match = HOP_RE.match(line)
        if not match:
            continue

        ttl = int(match.group(1))
        rest = match.group(2).strip()

        if rest.startswith("*"):
            hops.append({"ttl": ttl, "ip": None, "rdns": None, "rtt_ms": None})
            continue

        addr = ADDR_RE.search(rest)
        if addr:
            rdns, ip = addr.group(1), addr.group(2)
            if rdns == ip:
                rdns = None
        else:
            bare = BARE_IP_RE.match(rest)
            if not bare:
                continue
            ip, rdns = bare.group(1), None

        rtt = RTT_RE.search(rest)
        hops.append({"ttl": ttl, "ip": ip, "rdns": rdns,
                     "rtt_ms": float(rtt.group(1)) if rtt else None})

    return hops


def cymru_name(ip):
    return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"


def parse_cymru_txt(value):
    parts = [p.strip() for p in value.strip('"').split("|")]
    asn = None
    if parts and parts[0]:
        try:
            asn = int(parts[0].split()[0])
        except (ValueError, IndexError):
            asn = None
    return {"asn": asn,
            "prefix": parts[1] if len(parts) > 1 else None,
            "country": parts[2] if len(parts) > 2 else None}


def asn_path(hops):
    out = []
    for hop in hops:
        asn = hop.get("asn")
        if asn and (not out or out[-1] != asn):
            out.append(asn)
    return out


def _dns_asn_lookup(ctx):
    def lookup(ip):
        if ":" in ip:  # Cymru's IPv6 origin zone uses a different nibble format
            return {"asn": None, "prefix": None, "country": None}
        try:
            import dns.resolver
            answer = dns.resolver.resolve(cymru_name(ip), "TXT", lifetime=3.0)
            return parse_cymru_txt(str(answer[0]))
        except Exception:
            return {"asn": None, "prefix": None, "country": None}

    return lookup


def _run_traceroute(ctx):
    def run(cmd, timeout):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout

    return run


def collect(ctx, run=None, asn_lookup=None):
    if ctx.no_path:
        return unobserved("skipped with --no-path")

    tcp = ctx.results.get("tcp", {})
    target_ip = (tcp.get("chosen") or {}).get("ip")
    if not target_ip:
        return unobserved("no destination address to trace towards")

    if not ctx.caps.has_tool("traceroute"):
        return unobserved("traceroute not on PATH")

    run = run or _run_traceroute(ctx)
    asn_lookup = asn_lookup or _dns_asn_lookup(ctx)

    budget = ctx.budget_for(20.0)
    cmd = ["traceroute", "-w", "1", "-q", "1", "-m", "20", target_ip]
    try:
        out = run(cmd, timeout=budget)
    except Exception as exc:
        return unobserved(f"traceroute failed: {exc}")

    hops = parse_traceroute(out)
    if not hops:
        return unobserved("traceroute returned no parseable hops")

    for hop in hops:
        if hop["ip"]:
            info = asn_lookup(hop["ip"])
            hop["asn"] = info.get("asn")
            hop["as_name"] = info.get("prefix")
        else:
            hop["asn"] = None
            hop["as_name"] = None

    return observed(source="traceroute", hops=hops,
                    asn_path=asn_path(hops), path_mtu=None)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_collect_path.py -v`
Expected: PASS, 11 tests

- [ ] **Step 6: Commit**

```bash
git add wj/collect/path.py tests/test_collect_path.py tests/fixtures/traceroute_*.txt
git commit -m "feat: path collector with traceroute parsing and per-hop ASN lookup"
```

---

## Task 10: Local network collector

**Files:**
- Create: `wj/collect/local.py`
- Test: `tests/test_collect_local.py`, fixtures `route_get_darwin.txt`, `ifconfig_en0.txt`, `arp_gateway.txt`, `ipconfig_getpacket.txt`, `ip_route_get.txt`, `ip_addr_show.txt`, `ip_neigh.txt`

**Interfaces:**
- Consumes: `wj.context.Context`; reads `ctx.results["tcp"]["chosen"]["ip"]`.
- Produces:
  - `parse_route_get_darwin(text) -> dict` → `{"interface", "gateway"}`
  - `parse_ip_route_get(text) -> dict` → `{"interface", "gateway", "src"}`
  - `parse_ifconfig(text) -> dict` → `{"mac", "ipv4", "mtu", "status"}`
  - `parse_ip_addr(text) -> dict` → same keys
  - `parse_arp(text) -> str | None`
  - `parse_ip_neigh(text) -> str | None`
  - `parse_ipconfig_getpacket(text) -> dict` → `{"server", "lease_seconds", "dns"}`
  - `is_private(ip: str) -> bool`
  - `collect(ctx, run=None, public_ip=None) -> dict`

  Section shape:

```python
{"observed": True, "interface": "en0", "link": "Wi-Fi", "mtu": 1500,
 "local_ip": "192.168.1.23", "local_mac": "aa:bb:cc:dd:ee:ff",
 "gateway_ip": "192.168.1.1", "gateway_mac": "11:22:33:44:55:66",
 "dhcp": {"server": "192.168.1.1", "lease_seconds": 86400, "dns": ["192.168.1.1"]},
 "public_ip": "81.180.20.7", "nat": True}
```

- [ ] **Step 1: Create the fixtures**

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
cat > tests/fixtures/route_get_darwin.txt <<'EOF'
   route to: 93.184.216.34
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
EOF
cat > tests/fixtures/ifconfig_en0.txt <<'EOF'
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether aa:bb:cc:dd:ee:ff
	inet6 fe80::1cbf:6dff:fe1a:2b3c%en0 prefixlen 64 secured scopeid 0xb
	inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
EOF
cat > tests/fixtures/arp_gateway.txt <<'EOF'
? (192.168.1.1) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
EOF
cat > tests/fixtures/ipconfig_getpacket.txt <<'EOF'
op = BOOTREPLY
htype = 1
server_identifier (ip): 192.168.1.1
lease_time (uint32): 0x15180
domain_name_server (ip_mult): {192.168.1.1, 1.1.1.1}
router (ip_mult): {192.168.1.1}
EOF
cat > tests/fixtures/ip_route_get.txt <<'EOF'
93.184.216.34 via 192.168.1.1 dev wlan0 src 192.168.1.23 uid 1000
    cache
EOF
cat > tests/fixtures/ip_addr_show.txt <<'EOF'
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0
       valid_lft 84980sec preferred_lft 84980sec
EOF
cat > tests/fixtures/ip_neigh.txt <<'EOF'
192.168.1.1 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE
EOF
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_collect_local.py`:

```python
from pathlib import Path

from wj import capabilities
from wj.collect import local as local_collect
from wj.context import Context

FIXTURES = Path(__file__).parent / "fixtures"


def read(name):
    return (FIXTURES / name).read_text()


def test_parse_route_get_darwin():
    assert local_collect.parse_route_get_darwin(read("route_get_darwin.txt")) == {
        "interface": "en0", "gateway": "192.168.1.1"}


def test_parse_ip_route_get():
    assert local_collect.parse_ip_route_get(read("ip_route_get.txt")) == {
        "interface": "wlan0", "gateway": "192.168.1.1", "src": "192.168.1.23"}


def test_parse_ifconfig_reads_mac_ip_mtu_and_status():
    out = local_collect.parse_ifconfig(read("ifconfig_en0.txt"))
    assert out == {"mac": "aa:bb:cc:dd:ee:ff", "ipv4": "192.168.1.23",
                   "mtu": 1500, "status": "active"}


def test_parse_ip_addr_reads_mac_ip_and_mtu():
    out = local_collect.parse_ip_addr(read("ip_addr_show.txt"))
    assert out["mac"] == "aa:bb:cc:dd:ee:ff"
    assert out["ipv4"] == "192.168.1.23"
    assert out["mtu"] == 1500


def test_parse_arp_extracts_the_gateway_mac():
    assert local_collect.parse_arp(read("arp_gateway.txt")) == "11:22:33:44:55:66"


def test_parse_arp_returns_none_when_incomplete():
    assert local_collect.parse_arp("? (192.168.1.1) at (incomplete) on en0") is None


def test_parse_ip_neigh_extracts_the_gateway_mac():
    assert local_collect.parse_ip_neigh(read("ip_neigh.txt")) == "11:22:33:44:55:66"


def test_parse_ipconfig_getpacket_reads_lease_and_dns():
    out = local_collect.parse_ipconfig_getpacket(read("ipconfig_getpacket.txt"))
    assert out["server"] == "192.168.1.1"
    assert out["lease_seconds"] == 86400
    assert out["dns"] == ["192.168.1.1", "1.1.1.1"]


def test_is_private_covers_rfc1918_and_loopback():
    assert local_collect.is_private("192.168.1.23") is True
    assert local_collect.is_private("10.0.2.14") is True
    assert local_collect.is_private("172.16.4.1") is True
    assert local_collect.is_private("127.0.0.1") is True
    assert local_collect.is_private("93.184.216.34") is False


def test_collect_assembles_a_section_from_injected_commands():
    caps = capabilities.Capabilities(
        libs={}, tools={"route": "/sbin/route", "ifconfig": "/sbin/ifconfig",
                        "arp": "/usr/sbin/arp", "ipconfig": "/usr/sbin/ipconfig"},
        privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "chosen": {"ip": "93.184.216.34"}}

    outputs = {
        "route": read("route_get_darwin.txt"),
        "ifconfig": read("ifconfig_en0.txt"),
        "arp": read("arp_gateway.txt"),
        "ipconfig": read("ipconfig_getpacket.txt"),
    }

    section = local_collect.collect(
        ctx, run=lambda cmd, timeout: outputs[cmd[0]],
        public_ip=lambda: "81.180.20.7")

    assert section["observed"] is True
    assert section["interface"] == "en0"
    assert section["local_mac"] == "aa:bb:cc:dd:ee:ff"
    assert section["gateway_mac"] == "11:22:33:44:55:66"
    assert section["mtu"] == 1500
    assert section["nat"] is True
    assert section["public_ip"] == "81.180.20.7"
    assert section["dhcp"]["lease_seconds"] == 86400


def test_collect_without_any_tooling_is_unobserved():
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    section = local_collect.collect(ctx, run=lambda cmd, timeout: "",
                                    public_ip=lambda: None)
    assert section["observed"] is False
    assert "route" in section["why_not"]
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_collect_local.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.collect.local'`

- [ ] **Step 4: Write `wj/collect/local.py`**

```python
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
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


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
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_collect_local.py -v`
Expected: PASS, 11 tests

- [ ] **Step 6: Commit**

```bash
git add wj/collect/local.py tests/test_collect_local.py tests/fixtures/
git commit -m "feat: local network collector exposing L1/L2 for the first time"
```

---

## Task 11: Redaction and findings analysis

**Files:**
- Create: `wj/redact.py`, `wj/findings.py`
- Test: `tests/test_redact.py`, `tests/test_findings.py`

**Interfaces:**
- Consumes: a complete trace dict.
- Produces:
  - `redact.REDACTED: str = "[redacted at export]"`
  - `redact.redact_trace(trace: dict) -> dict` — returns a deep-copied, redacted document with `redacted: True`
  - `findings.analyse(trace: dict) -> None` — appends notes in place, using `schema.add_note`

- [ ] **Step 1: Write the failing redaction test**

Create `tests/test_redact.py`:

```python
import copy

from wj import redact


def sample_trace():
    return {
        "schema": "webpage-journey-trace/1",
        "redacted": False,
        "local": {"observed": True, "interface": "en0",
                  "local_ip": "192.168.1.23", "local_mac": "aa:bb:cc:dd:ee:ff",
                  "gateway_ip": "192.168.1.1", "gateway_mac": "11:22:33:44:55:66",
                  "public_ip": "81.180.20.7", "mtu": 1500,
                  "dhcp": {"server": "192.168.1.1", "lease_seconds": 86400,
                           "dns": ["192.168.1.1"]}},
        "tcp": {"observed": True, "local": {"ip": "192.168.1.23", "port": 54213},
                "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443}},
        "path": {"observed": True, "hops": [
            {"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan", "rtt_ms": 1.2},
            {"ttl": 2, "ip": "93.184.216.34", "rdns": None, "rtt_ms": 12.0}]},
    }


def test_redacts_local_identifiers():
    out = redact.redact_trace(sample_trace())
    assert out["local"]["local_mac"] == redact.REDACTED
    assert out["local"]["local_ip"] == redact.REDACTED
    assert out["local"]["gateway_mac"] == redact.REDACTED
    assert out["local"]["public_ip"] == redact.REDACTED
    assert out["tcp"]["local"]["ip"] == redact.REDACTED


def test_keeps_facts_that_are_not_identifying():
    out = redact.redact_trace(sample_trace())
    assert out["local"]["interface"] == "en0"
    assert out["local"]["mtu"] == 1500
    assert out["local"]["dhcp"]["lease_seconds"] == 86400
    assert out["tcp"]["local"]["port"] == 54213
    assert out["tcp"]["chosen"]["ip"] == "93.184.216.34"


def test_redacts_private_hops_but_keeps_public_ones():
    out = redact.redact_trace(sample_trace())
    assert out["path"]["hops"][0]["ip"] == redact.REDACTED
    assert out["path"]["hops"][0]["rdns"] == redact.REDACTED
    assert out["path"]["hops"][1]["ip"] == "93.184.216.34"


def test_marks_the_document_redacted_and_does_not_mutate_the_original():
    original = sample_trace()
    snapshot = copy.deepcopy(original)
    out = redact.redact_trace(original)
    assert out["redacted"] is True
    assert original == snapshot


def test_redacting_an_unobserved_section_is_a_no_op():
    trace = {"local": {"observed": False, "why_not": "no route tool"},
             "tcp": {"observed": False, "why_not": "x"},
             "path": {"observed": False, "why_not": "x"}, "redacted": False}
    out = redact.redact_trace(trace)
    assert out["local"] == {"observed": False, "why_not": "no route tool"}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_redact.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.redact'`

- [ ] **Step 3: Write `wj/redact.py`**

```python
"""Strip identifying detail from a trace before it is exported and shared."""

import copy

from wj.collect.local import is_private

REDACTED = "[redacted at export]"

LOCAL_FIELDS = ("local_ip", "local_mac", "gateway_ip", "gateway_mac", "public_ip")


def redact_trace(trace):
    out = copy.deepcopy(trace)
    out["redacted"] = True

    local = out.get("local", {})
    if local.get("observed"):
        for field in LOCAL_FIELDS:
            if local.get(field):
                local[field] = REDACTED
        dhcp = local.get("dhcp") or {}
        if dhcp.get("server"):
            dhcp["server"] = REDACTED
        if dhcp.get("dns"):
            dhcp["dns"] = [REDACTED for _ in dhcp["dns"]]

    tcp = out.get("tcp", {})
    if tcp.get("observed") and tcp.get("local", {}).get("ip"):
        tcp["local"]["ip"] = REDACTED

    path = out.get("path", {})
    if path.get("observed"):
        for hop in path.get("hops", []):
            if hop.get("ip") and is_private(hop["ip"]):
                hop["ip"] = REDACTED
                if hop.get("rdns"):
                    hop["rdns"] = REDACTED

    return out
```

- [ ] **Step 4: Run it to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_redact.py -v`
Expected: PASS, 5 tests

- [ ] **Step 5: Write the failing findings test**

Create `tests/test_findings.py`:

```python
from wj import findings, schema


def base_trace():
    trace = schema.new_trace(
        target={"input": "example.com", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.0.0", generated_at="2026-08-20T00:00:00Z",
        capabilities={}, redacted=False)
    return trace


def texts(trace):
    return [n["text"] for n in trace["notes"]]


def test_flags_a_certificate_expiring_soon():
    trace = base_trace()
    trace["tls"] = {"observed": True, "chain": [{"days_left": 9, "subject_cn": "example.com"}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    assert any("expires in 9 days" in t for t in texts(trace))
    assert trace["notes"][0]["severity"] == "warn"


def test_flags_an_expired_certificate_as_critical():
    trace = base_trace()
    trace["tls"] = {"observed": True, "chain": [{"days_left": -2, "subject_cn": "x"}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    assert trace["notes"][0]["severity"] == "critical"


def test_flags_legacy_tls_versions_as_critical():
    trace = base_trace()
    trace["tls"] = {"observed": True, "chain": [{"days_left": 90}],
                    "legacy_versions_accepted": ["TLSv1.1"]}
    findings.analyse(trace)
    assert any("TLSv1.1" in t for t in texts(trace))
    assert any(n["severity"] == "critical" for n in trace["notes"])


def test_flags_insecure_dnssec_and_missing_aaaa():
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "insecure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}], "AAAA": []},
                    "alpn_advertised": []}
    findings.analyse(trace)
    joined = " ".join(texts(trace))
    assert "DNSSEC" in joined
    assert "AAAA" in joined
    assert "HTTP/3" in joined


def test_flags_a_plaintext_redirect_hop():
    trace = base_trace()
    trace["http"] = {"observed": True,
                     "hops": [{"url": "http://example.com/", "status": 301,
                               "location": "https://example.com/"}],
                     "final": {"status": 200},
                     "security": {"grade": "A", "missing": [], "cookies": []}}
    findings.analyse(trace)
    assert any("plaintext" in t for t in texts(trace))


def test_flags_a_poor_security_grade_and_insecure_cookies():
    trace = base_trace()
    trace["http"] = {"observed": True, "hops": [], "final": {"status": 200},
                     "security": {"grade": "F",
                                  "missing": ["Strict-Transport-Security"],
                                  "cookies": [{"name": "session", "secure": False,
                                               "httponly": True, "samesite": None}]}}
    findings.analyse(trace)
    joined = " ".join(texts(trace))
    assert "grade F" in joined
    assert "session" in joined


def test_a_clean_trace_produces_no_notes():
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h3", "h2"]}
    trace["tls"] = {"observed": True, "chain": [{"days_left": 80}],
                    "legacy_versions_accepted": []}
    trace["http"] = {"observed": True, "hops": [], "final": {"status": 200},
                     "security": {"grade": "A", "missing": [],
                                  "cookies": [{"name": "s", "secure": True,
                                               "httponly": True, "samesite": "Lax"}]}}
    findings.analyse(trace)
    assert trace["notes"] == []


def test_unobserved_sections_are_skipped_silently():
    trace = base_trace()
    findings.analyse(trace)
    assert trace["notes"] == []
```

- [ ] **Step 6: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_findings.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.findings'`

- [ ] **Step 7: Write `wj/findings.py`**

```python
"""Turn a completed trace into the short list of things worth acting on."""

from wj.collect.tls import grade_expiry
from wj.schema import add_note

POOR_GRADES = ("D", "E", "F")


def analyse(trace):
    _analyse_dns(trace)
    _analyse_tls(trace)
    _analyse_http(trace)


def _analyse_dns(trace):
    dns = trace.get("dns", {})
    if not dns.get("observed"):
        return

    if dns.get("dnssec") == "insecure":
        add_note(trace, "info", "dns",
                 "DNSSEC is not signed for this zone — answers cannot be authenticated")

    records = dns.get("records", {})
    if records.get("A") and not records.get("AAAA"):
        add_note(trace, "info", "dns",
                 "no AAAA record — this host is unreachable over IPv6-only networks")

    if "h3" not in (dns.get("alpn_advertised") or []):
        add_note(trace, "info", "dns",
                 "no HTTP/3 advertised in the HTTPS record — clients cannot use QUIC on the first connection")


def _analyse_tls(trace):
    tls = trace.get("tls", {})
    if not tls.get("observed"):
        return

    chain = tls.get("chain") or []
    if chain and chain[0].get("days_left") is not None:
        graded = grade_expiry(chain[0]["days_left"])
        if graded:
            severity, message = graded
            add_note(trace, severity, "tls", message)

    for version in tls.get("legacy_versions_accepted") or []:
        add_note(trace, "critical", "tls",
                 f"{version} is still accepted — clients can be downgraded to it")

    if tls.get("caa_match") is False:
        add_note(trace, "warn", "tls",
                 "the presented issuer is not listed in the zone's CAA records")


def _analyse_http(trace):
    http = trace.get("http", {})
    if not http.get("observed"):
        return

    for hop in http.get("hops") or []:
        if str(hop.get("url", "")).startswith("http://"):
            add_note(trace, "warn", "http",
                     f"redirect hop {hop['url']} travelled in plaintext before the upgrade")

    security = http.get("security") or {}
    grade = security.get("grade")
    if grade in POOR_GRADES:
        missing = ", ".join(security.get("missing") or [])
        add_note(trace, "warn", "http",
                 f"security header grade {grade} — missing: {missing}")

    for cookie in security.get("cookies") or []:
        problems = []
        if not cookie.get("secure"):
            problems.append("Secure")
        if not cookie.get("samesite"):
            problems.append("SameSite")
        if problems:
            add_note(trace, "warn", "http",
                     f"cookie {cookie['name']} is missing {' and '.join(problems)}")
```

- [ ] **Step 8: Run it to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_findings.py -v`
Expected: PASS, 8 tests

- [ ] **Step 9: Commit**

```bash
git add wj/redact.py wj/findings.py tests/test_redact.py tests/test_findings.py
git commit -m "feat: export redaction and findings analysis"
```

---

## Task 12: OSI assembly

**Files:**
- Modify: `wj/schema.py` (append `build_osi` and its helpers)
- Test: `tests/test_build_osi.py`

**Interfaces:**
- Consumes: a completed trace dict.
- Produces: `schema.build_osi(trace: dict) -> dict` returning keys `l1`…`l7`, each
  `{"observed": bool, "facts": list[str], "why_not": str | None, "test_command": str | None}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_build_osi.py`:

```python
from wj import schema


def full_trace():
    trace = schema.new_trace(
        target={"input": "example.com", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/dashboard"},
        tool_version="2.0.0", generated_at="2026-08-20T00:00:00Z",
        capabilities={}, redacted=False)
    trace["local"] = {"observed": True, "interface": "en0", "link": "active",
                      "mtu": 1500, "local_ip": "192.168.1.23",
                      "local_mac": "aa:bb:cc:dd:ee:ff", "gateway_ip": "192.168.1.1",
                      "gateway_mac": "11:22:33:44:55:66", "public_ip": "81.180.20.7",
                      "nat": True, "dhcp": {}}
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "resolver": {"servers": ["1.1.1.1"], "source": "scutil"},
                    "records": {"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": []},
                    "alpn_advertised": ["h2"], "timing_ms": {"cold": 41.2, "warm": 1.1}}
    trace["tcp"] = {"observed": True, "winner_family": "ipv4",
                    "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443},
                    "local": {"ip": "192.168.1.23", "port": 54213},
                    "kernel": {"rtt_ms": 12.4, "mss": 1460, "retransmits": 0,
                               "source": "TCP_INFO"}}
    trace["tls"] = {"observed": True, "version": "TLSv1.3", "alpn": "h2",
                    "cipher": "TLS_AES_128_GCM_SHA256", "handshake_ms": 38.2,
                    "chain": [{"subject_cn": "example.com", "issuer_cn": "R3"}],
                    "trust_root": "ISRG Root X1", "resumption": {"tested": False}}
    trace["http"] = {"observed": True, "hops": [],
                     "final": {"url": "https://example.com/dashboard", "status": 200,
                               "protocol": "HTTP/1.1", "encoding": "gzip", "ratio": 4.4,
                               "wire_bytes": 14000, "decoded_bytes": 61000,
                               "content_type": "text/html"}}
    trace["path"] = {"observed": True, "hops": [{"ttl": 1, "ip": "192.168.1.1"}],
                     "asn_path": [8708, 13335], "path_mtu": None}
    return trace


def test_every_layer_is_present():
    osi = schema.build_osi(full_trace())
    assert set(osi) == {"l1", "l2", "l3", "l4", "l5", "l6", "l7"}


def test_layer_two_names_the_gateway_mac():
    osi = schema.build_osi(full_trace())
    assert osi["l2"]["observed"] is True
    joined = " ".join(osi["l2"]["facts"])
    assert "11:22:33:44:55:66" in joined
    assert "aa:bb:cc:dd:ee:ff" in joined


def test_layer_three_reports_nat_and_the_as_path():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l3"]["facts"])
    assert "NAT" in joined
    assert "AS8708" in joined and "AS13335" in joined


def test_layer_four_reports_ports_rtt_and_mss():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l4"]["facts"])
    assert ":54213" in joined and ":443" in joined
    assert "12.4" in joined
    assert "1460" in joined


def test_layer_six_reports_tls_and_compression():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l6"]["facts"])
    assert "TLSv1.3" in joined
    assert "gzip" in joined


def test_layer_seven_reports_the_request_and_dns():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l7"]["facts"])
    assert "200" in joined
    assert "93.184.216.34" in joined


def test_test_commands_are_filled_with_this_hosts_values():
    osi = schema.build_osi(full_trace())
    assert osi["l3"]["test_command"] == "ping 93.184.216.34"
    assert osi["l4"]["test_command"] == "nc -vz example.com 443"
    assert "openssl s_client" in osi["l6"]["test_command"]
    assert "curl -sSI https://example.com/dashboard" == osi["l7"]["test_command"]


def test_unobserved_sections_propagate_their_reason():
    trace = full_trace()
    trace["local"] = {"observed": False, "why_not": "neither route nor ip is on PATH"}
    osi = schema.build_osi(trace)
    assert osi["l1"]["observed"] is False
    assert osi["l1"]["why_not"] == "neither route nor ip is on PATH"
    assert osi["l1"]["facts"] == []


def test_empty_trace_yields_seven_unobserved_layers():
    trace = schema.new_trace(
        target={"input": "x", "host": "x", "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.0.0", generated_at="t", capabilities={}, redacted=False)
    osi = schema.build_osi(trace)
    assert all(layer["observed"] is False for layer in osi.values())
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_build_osi.py -v`
Expected: FAIL with `AttributeError: module 'wj.schema' has no attribute 'build_osi'`

- [ ] **Step 3: Append `build_osi` to `wj/schema.py`**

```python
def _layer(section, facts, test_command=None):
    if not section.get("observed"):
        return {"observed": False, "facts": [],
                "why_not": section.get("why_not", "not collected"),
                "test_command": test_command}
    return {"observed": True, "facts": [f for f in facts if f],
            "why_not": None, "test_command": test_command}


def build_osi(trace):
    """Map a completed trace onto the seven layers, using only measured values."""
    local = trace.get("local", {})
    dns = trace.get("dns", {})
    tcp = trace.get("tcp", {})
    tls = trace.get("tls", {})
    http = trace.get("http", {})
    path = trace.get("path", {})

    host = trace.get("target", {}).get("host", "")
    port = trace.get("target", {}).get("port", 443)
    scheme = trace.get("target", {}).get("scheme", "https")
    url = f"{scheme}://{host}{trace.get('target', {}).get('path', '/')}"
    target_ip = (tcp.get("chosen") or {}).get("ip")

    l1_facts = [
        f"interface {local.get('interface')}" if local.get("interface") else None,
        f"link {local.get('link')}" if local.get("link") else None,
        f"MTU {local.get('mtu')}" if local.get("mtu") else None,
    ]

    l2_facts = [
        f"your MAC {local.get('local_mac')}" if local.get("local_mac") else None,
        f"→ gateway MAC {local.get('gateway_mac')} ({local.get('gateway_ip')})"
        if local.get("gateway_mac") else None,
        "every frame to this server is addressed to your router, not to the server",
    ]

    l3_facts = []
    if local.get("local_ip") and target_ip:
        l3_facts.append(f"{local['local_ip']} → {target_ip}")
    if local.get("nat"):
        l3_facts.append(f"NAT: {local.get('local_ip')} appears as {local.get('public_ip')}")
    if path.get("observed"):
        l3_facts.append(f"{len(path.get('hops', []))} hops")
        as_path = path.get("asn_path") or []
        if as_path:
            l3_facts.append(" → ".join(f"AS{n}" for n in as_path))

    kernel = tcp.get("kernel") or {}
    l4_facts = []
    if tcp.get("observed"):
        l4_facts.append(f"TCP :{(tcp.get('local') or {}).get('port')} → :{port}")
        if kernel.get("rtt_ms") is not None:
            l4_facts.append(f"RTT {kernel['rtt_ms']} ms")
        if kernel.get("mss"):
            l4_facts.append(f"MSS {kernel['mss']}")
        if kernel.get("retransmits") is not None:
            l4_facts.append(f"{kernel['retransmits']} retransmits")
        if tcp.get("winner_family"):
            l4_facts.append(f"{tcp['winner_family']} won the connection race")

    l5_facts = []
    if tls.get("observed"):
        l5_facts.append("TLS session established")
        if (tls.get("resumption") or {}).get("resumed"):
            l5_facts.append("resumed from a session ticket")
    if http.get("observed"):
        l5_facts.append(f"{len(http.get('hops', [])) + 1} request(s) over this connection")

    final = http.get("final") or {}
    l6_facts = []
    if tls.get("observed"):
        l6_facts.append(f"{tls.get('version')} · {tls.get('cipher')}")
        if tls.get("alpn"):
            l6_facts.append(f"ALPN {tls['alpn']}")
    if final.get("encoding"):
        l6_facts.append(
            f"{final['encoding']}: {final.get('wire_bytes')} → {final.get('decoded_bytes')} bytes"
            + (f" ({final['ratio']}:1)" if final.get("ratio") else ""))
    if final.get("content_type"):
        l6_facts.append(final["content_type"])

    l7_facts = []
    if http.get("observed"):
        l7_facts.append(f"{final.get('protocol')} → {final.get('status')}")
        if http.get("hops"):
            l7_facts.append(f"{len(http['hops'])} redirect(s) followed")
    if dns.get("observed"):
        l7_facts.append(f"DNS: {host} → {target_ip}")
        resolver = (dns.get("resolver") or {}).get("servers") or []
        if resolver:
            l7_facts.append(f"resolved via {resolver[0]}, DNSSEC {dns.get('dnssec')}")

    return {
        "l1": _layer(local, l1_facts, f"ifconfig {local.get('interface')}"
                     if local.get("interface") else None),
        "l2": _layer(local, l2_facts, f"arp -n {local.get('gateway_ip')}"
                     if local.get("gateway_ip") else None),
        "l3": _layer(tcp if not path.get("observed") else path, l3_facts,
                     f"ping {target_ip}" if target_ip else None),
        "l4": _layer(tcp, l4_facts, f"nc -vz {host} {port}"),
        "l5": _layer(tls if tls.get("observed") else http, l5_facts, None),
        "l6": _layer(tls if tls.get("observed") else http, l6_facts,
                     f"openssl s_client -connect {host}:{port} -servername {host}"),
        "l7": _layer(http, l7_facts, f"curl -sSI {url}"),
    }
```

- [ ] **Step 4: Run it to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_build_osi.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add wj/schema.py tests/test_build_osi.py
git commit -m "feat: assemble the OSI section from measured values only"
```

---

## Task 13: Orchestrator, CLI, and export

**Files:**
- Create: `wj/run.py`
- Modify: `trace.py` (full CLI surface)
- Test: `tests/test_run.py`

**Interfaces:**
- Consumes: every collector, `wj.schema`, `wj.findings`, `wj.redact`.
- Produces:
  - `run.COLLECTORS: dict[str, callable]` keyed by section name
  - `run.build_timings(trace: dict) -> dict` → `{"waterfall": [{"label", "start_ms", "end_ms"}], "total_ms": float}`
  - `run.close_sockets(trace: dict) -> None`
  - `run.strip_private(trace: dict) -> dict` — removes every `_`-prefixed key
  - `run.orchestrate(ctx, collectors=None, now=time.monotonic) -> dict`
  - `run.EXIT_OK = 0`, `run.EXIT_UNRESOLVABLE = 1`, `run.EXIT_USAGE = 2`

**Note on the entry-point name:** orchestration lives in `wj/run.py`, not in `trace.py`, because Python's standard library already owns the module name `trace` — importing the CLI from tests would shadow it. `trace.py` stays the user-facing entry point and only parses arguments.

- [ ] **Step 1: Write the failing test**

Create `tests/test_run.py`:

```python
import pytest

from wj import capabilities, run, schema
from wj.context import Context


def make_ctx(deadline=1e9):
    caps = capabilities.Capabilities(libs={"dns": True}, tools={},
                                     privileged=False, can_sudo=False)
    return Context(host="example.com", scheme="https", port=443, path="/",
                   timeout=5.0, deadline=deadline, caps=caps, results={})


def fake_collectors(**overrides):
    base = {
        "local": lambda ctx: schema.observed(interface="en0"),
        "dns": lambda ctx: schema.observed(
            records={"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": []},
            timing_ms={"cold": 40.0, "warm": 1.0}, dnssec="secure",
            resolver={"servers": [], "source": "none"}, alpn_advertised=[]),
        "tcp": lambda ctx: schema.observed(
            chosen={"ip": "93.184.216.34", "family": "ipv4", "port": 443},
            candidates=[{"ip": "93.184.216.34", "family": "ipv4",
                         "connect_ms": 12.0, "error": None}],
            local={"ip": "192.168.1.5", "port": 51000}, kernel={}, winner_family="ipv4"),
        "tls": lambda ctx: schema.observed(
            version="TLSv1.3", cipher="X", alpn="h2", handshake_ms=30.0,
            chain=[], trust_root=None, verified=True, caa_match=None,
            resumption={"tested": False}, legacy_versions_accepted=[]),
        "http": lambda ctx: schema.observed(
            hops=[], final={"url": "https://example.com/", "status": 200,
                            "protocol": "HTTP/1.1", "ttfb_ms": 80.0, "total_ms": 95.0,
                            "wire_bytes": 100, "decoded_bytes": 100, "encoding": None,
                            "ratio": None, "content_type": "text/html"},
            cache={}, cdn=None,
            security={"grade": "A", "present": {}, "missing": [], "cookies": []},
            conditional={"tested": False}),
        "path": lambda ctx: schema.observed(source="traceroute", hops=[],
                                            asn_path=[], path_mtu=None),
    }
    base.update(overrides)
    return base


def test_orchestrate_fills_every_section():
    trace = run.orchestrate(make_ctx(), collectors=fake_collectors())
    for name in schema.SECTIONS:
        assert trace[name]["observed"] is True
    assert schema.validate(trace) == []


def test_orchestrate_records_a_collector_failure_without_aborting():
    def explode(ctx):
        raise RuntimeError("boom")

    trace = run.orchestrate(make_ctx(), collectors=fake_collectors(tls=explode))
    assert trace["tls"]["observed"] is False
    assert "boom" in trace["tls"]["why_not"]
    assert trace["http"]["observed"] is True


def test_orchestrate_skips_dependents_when_dns_fails():
    def no_dns(ctx):
        return schema.unobserved("did not resolve")

    trace = run.orchestrate(make_ctx(), collectors=fake_collectors(dns=no_dns))
    assert trace["dns"]["observed"] is False
    assert trace["tcp"]["observed"] is False
    assert "dns" in trace["tcp"]["why_not"]


def test_orchestrate_marks_unstarted_collectors_when_the_budget_is_gone():
    ctx = make_ctx(deadline=0.0)
    trace = run.orchestrate(ctx, collectors=fake_collectors(), now=lambda: 100.0)
    assert trace["http"]["observed"] is False
    assert "budget exhausted" in trace["http"]["why_not"]


def test_build_timings_produces_a_cumulative_waterfall():
    trace = run.orchestrate(make_ctx(), collectors=fake_collectors())
    timings = trace["timings"]
    labels = [row["label"] for row in timings["waterfall"]]
    assert labels == ["DNS", "TCP", "TLS", "TTFB", "Download"]
    starts = [row["start_ms"] for row in timings["waterfall"]]
    assert starts == sorted(starts)
    assert timings["waterfall"][1]["start_ms"] == pytest.approx(40.0)
    assert timings["total_ms"] > 0


def test_strip_private_removes_socket_handles():
    trace = {"tcp": {"observed": True, "_socket": object(), "chosen": {}},
             "tls": {"observed": True, "_socket": object()}}
    out = run.strip_private(trace)
    assert "_socket" not in out["tcp"]
    assert "_socket" not in out["tls"]
    assert out["tcp"]["chosen"] == {}


def test_orchestrate_attaches_findings_and_osi():
    trace = run.orchestrate(make_ctx(), collectors=fake_collectors())
    assert set(trace["osi"]) == {"l1", "l2", "l3", "l4", "l5", "l6", "l7"}
    assert isinstance(trace["notes"], list)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_run.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'wj.run'`

- [ ] **Step 3: Write `wj/run.py`**

```python
"""Run the collectors on a budgeted dependency graph and assemble the document."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from wj import findings, schema
from wj.collect import dns as dns_collect
from wj.collect import http as http_collect
from wj.collect import local as local_collect
from wj.collect import path as path_collect
from wj.collect import tcp as tcp_collect
from wj.collect import tls as tls_collect

EXIT_OK = 0
EXIT_UNRESOLVABLE = 1
EXIT_USAGE = 2

COLLECTORS = {
    "local": local_collect.collect,
    "dns": dns_collect.collect,
    "tcp": tcp_collect.collect,
    "tls": tls_collect.collect,
    "http": http_collect.collect,
    "path": path_collect.collect,
}

# section -> the section it needs to have observed before it can run
DEPENDS_ON = {"tcp": "dns", "tls": "tcp", "http": "tcp", "path": "tcp"}


def _run_one(name, collector, ctx, now):
    if ctx.expired(now()):
        return schema.unobserved("budget exhausted")

    dependency = DEPENDS_ON.get(name)
    if dependency and not ctx.results.get(dependency, {}).get("observed"):
        return schema.unobserved(
            f"skipped because {dependency} was not observed")

    try:
        return collector(ctx)
    except Exception as exc:
        return schema.unobserved(f"{type(exc).__name__}: {exc}")


def build_timings(trace):
    dns = trace.get("dns", {})
    tcp = trace.get("tcp", {})
    tls = trace.get("tls", {})
    http = trace.get("http", {})
    final = http.get("final") or {}

    dns_ms = (dns.get("timing_ms") or {}).get("cold", 0.0) if dns.get("observed") else 0.0
    chosen_ip = (tcp.get("chosen") or {}).get("ip")
    tcp_ms = 0.0
    for candidate in tcp.get("candidates") or []:
        if candidate.get("ip") == chosen_ip and candidate.get("connect_ms"):
            tcp_ms = candidate["connect_ms"]
    tls_ms = tls.get("handshake_ms", 0.0) if tls.get("observed") else 0.0
    ttfb_ms = final.get("ttfb_ms") or 0.0
    download_ms = max((final.get("total_ms") or 0.0) - ttfb_ms, 0.0)

    rows = []
    cursor = 0.0
    for label, duration in (("DNS", dns_ms), ("TCP", tcp_ms), ("TLS", tls_ms),
                            ("TTFB", ttfb_ms), ("Download", download_ms)):
        rows.append({"label": label, "start_ms": round(cursor, 1),
                     "end_ms": round(cursor + duration, 1)})
        cursor += duration

    return {"waterfall": rows, "total_ms": round(cursor, 1)}


def close_sockets(trace):
    for name in ("tls", "tcp"):
        sock = trace.get(name, {}).get("_socket")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def strip_private(trace):
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if not str(k).startswith("_")}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    return clean(trace)


def orchestrate(ctx, collectors=None, now=time.monotonic):
    collectors = collectors or COLLECTORS

    trace = schema.new_trace(
        target={"input": f"{ctx.scheme}://{ctx.host}{ctx.path}", "host": ctx.host,
                "scheme": ctx.scheme, "port": ctx.port, "path": ctx.path},
        tool_version=_tool_version(),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        capabilities=ctx.caps.to_dict(),
        redacted=False,
    )

    # local is independent of everything; dns gates the rest.
    with ThreadPoolExecutor(max_workers=2) as pool:
        local_future = pool.submit(_run_one, "local", collectors["local"], ctx, now)
        ctx.results["dns"] = _run_one("dns", collectors["dns"], ctx, now)
        ctx.results["local"] = local_future.result()

    ctx.results["tcp"] = _run_one("tcp", collectors["tcp"], ctx, now)

    # path runs on its own socket, concurrently with the tls -> http chain.
    with ThreadPoolExecutor(max_workers=2) as pool:
        path_future = pool.submit(_run_one, "path", collectors["path"], ctx, now)
        ctx.results["tls"] = _run_one("tls", collectors["tls"], ctx, now)
        ctx.results["http"] = _run_one("http", collectors["http"], ctx, now)
        ctx.results["path"] = path_future.result()

    for name in schema.SECTIONS:
        trace[name] = ctx.results.get(name, schema.unobserved("not collected"))

    trace["timings"] = build_timings(trace)
    findings.analyse(trace)
    trace["osi"] = schema.build_osi(trace)
    return trace


def _tool_version():
    from wj import __version__
    return __version__
```

- [ ] **Step 4: Run it to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_run.py -v`
Expected: PASS, 7 tests

- [ ] **Step 5: Extend `trace.py` with the full CLI**

Replace the body of `trace.py` with:

```python
#!/usr/bin/env python3
"""trace.py — trace one webpage request end to end and map it onto the OSI model."""

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
        epilog="Trace only hosts you are authorised to probe. --deep sends extra "
               "requests that constitute mild active scanning.",
    )
    p.add_argument("target", nargs="?", help="Domain or URL, e.g. example.com")
    p.add_argument("--port", type=int, default=None, help="Override the port")
    p.add_argument("--no-tls", action="store_true", help="Use plain HTTP instead of HTTPS")
    p.add_argument("--timeout", type=float, default=8.0, help="Per-operation timeout (default 8)")
    p.add_argument("--budget", type=float, default=25.0, help="Total wall-clock cap (default 25)")
    p.add_argument("--json", dest="json_path", metavar="PATH",
                   help="Export the trace document; '-' writes to stdout")
    p.add_argument("--deep", action="store_true",
                   help="Extra probes: TLS downgrade, session resumption, 304 replay")
    p.add_argument("--privileged", action="store_true",
                   help="Allow sudo for traceroute, path MTU, and Wi-Fi detail")
    p.add_argument("--no-path", action="store_true", help="Skip traceroute entirely")
    p.add_argument("--geo-hops", action="store_true",
                   help="Geolocate every hop, not only the destination")
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
    p.add_argument("--insecure", action="store_true",
                   help="Continue past certificate validation failure and still report the cert")
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
                  caps=caps, deep=args.deep, privileged=args.privileged,
                  no_path=args.no_path, geo_hops=args.geo_hops, results={})

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
```

- [ ] **Step 6: Verify usage and exit codes**

Run:

```bash
.venv/bin/python trace.py; echo "exit=$?"
.venv/bin/python trace.py --osi; echo "exit=$?"
```

Expected: the first prints `No target given.` and `exit=2`; the second prints the reference table and `exit=0`. (A real trace will fail until Task 14 adds `render_trace`.)

- [ ] **Step 7: Commit**

```bash
git add wj/run.py trace.py tests/test_run.py
git commit -m "feat: budgeted orchestration DAG, full CLI, and trace export"
```

---

## Task 14: Terminal rendering of a trace

**Files:**
- Modify: `wj/render.py` (append the trace renderers)
- Test: `tests/test_render.py`

**Interfaces:**
- Consumes: a completed trace dict.
- Produces:
  - `render_local(console, trace)`, `render_dns(console, trace)`, `render_tcp(console, trace)`, `render_tls(console, trace)`, `render_path(console, trace)`, `render_http(console, trace)`
  - `render_findings(console, trace)`
  - `render_waterfall(console, trace)`
  - `render_osi_stack(console, trace)`
  - `render_ladder(console, trace)`
  - `render_trace(console, trace)` — calls all of the above in order
  - `SEVERITY_STYLE: dict[str, str]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_render.py`:

```python
import io

from rich.console import Console

from wj import render, schema
from tests.test_build_osi import full_trace


def capture(fn, trace, width=110):
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, force_terminal=False, no_color=True)
    fn(console, trace)
    return buffer.getvalue()


def test_render_trace_mentions_every_layer():
    out = capture(render.render_trace, full_trace())
    for n in range(1, 8):
        assert f"L{n}" in out


def test_render_osi_stack_shows_measured_values_not_apologies():
    out = capture(render.render_osi_stack, full_trace())
    assert "11:22:33:44:55:66" in out
    assert "not visible to a userspace socket" not in out


def test_render_osi_stack_explains_an_unobserved_layer():
    trace = full_trace()
    trace["local"] = {"observed": False, "why_not": "neither route nor ip is on PATH"}
    trace["osi"] = schema.build_osi(trace)
    out = capture(render.render_osi_stack, trace)
    assert "neither route nor ip is on PATH" in out


def test_render_waterfall_rows_are_cumulative():
    trace = full_trace()
    trace["timings"] = {"waterfall": [
        {"label": "DNS", "start_ms": 0.0, "end_ms": 40.0},
        {"label": "TCP", "start_ms": 40.0, "end_ms": 52.0},
    ], "total_ms": 52.0}
    out = capture(render.render_waterfall, trace)
    assert "DNS" in out and "TCP" in out
    assert "52.0" in out


def test_render_findings_lists_notes_by_severity():
    trace = full_trace()
    trace["notes"] = [
        {"severity": "info", "section": "dns", "text": "no AAAA record"},
        {"severity": "critical", "section": "tls", "text": "certificate expired"},
    ]
    out = capture(render.render_findings, trace)
    assert out.index("certificate expired") < out.index("no AAAA record")


def test_render_findings_says_so_when_there_is_nothing_to_report():
    trace = full_trace()
    trace["notes"] = []
    out = capture(render.render_findings, trace)
    assert "Nothing" in out or "No findings" in out


def test_render_ladder_prints_this_hosts_commands():
    out = capture(render.render_ladder, full_trace())
    assert "ping 93.184.216.34" in out
    assert "nc -vz example.com 443" in out


def test_render_trace_survives_a_fully_unobserved_document():
    trace = schema.new_trace(
        target={"input": "x", "host": "x.test", "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.0.0", generated_at="t", capabilities={}, redacted=False)
    trace["timings"] = {"waterfall": [], "total_ms": 0.0}
    trace["osi"] = schema.build_osi(trace)
    out = capture(render.render_trace, trace)
    assert "not collected" in out
```

Also create `tests/__init__.py` so `from tests.test_build_osi import full_trace` resolves:

```bash
touch tests/__init__.py
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_render.py -v`
Expected: FAIL with `AttributeError: module 'wj.render' has no attribute 'render_trace'`

- [ ] **Step 3: Append the trace renderers to `wj/render.py`**

```python
from rich.text import Text

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


def render_local(console, trace):
    section = trace.get("local", {})
    if not section.get("observed"):
        return _unobserved_panel(console, section, "1 · Your local network", (1, 2), "medium_purple")

    body = _kv_table([
        ("Interface", f"{section.get('interface')}  ({section.get('link')})"),
        ("MTU", section.get("mtu")),
        ("Your address", f"{section.get('local_ip')}  ({section.get('local_mac')})"),
        ("Gateway", f"{section.get('gateway_ip')}  ({section.get('gateway_mac')})"),
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

    tree = Tree(f"[bold]{trace['target']['host']}[/bold]  "
                f"[dim]({(section.get('timing_ms') or {}).get('cold')} ms cold, "
                f"{(section.get('timing_ms') or {}).get('warm')} ms warm)[/dim]")
    for rtype, records in (section.get("records") or {}).items():
        if not records:
            continue
        branch = tree.add(f"[cyan]{rtype}[/cyan]")
        for record in records[:5]:
            branch.add(f"{record['data']}  [dim]ttl {record['ttl']}[/dim]")
        if len(records) > 5:
            branch.add(f"[dim]… {len(records) - 5} more[/dim]")

    resolver = section.get("resolver") or {}
    tree.add(f"[dim]resolved via {', '.join(resolver.get('servers') or ['unknown'])} "
             f"({resolver.get('source')}) · DNSSEC {section.get('dnssec')}[/dim]")
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

    text = Text()
    text.append("Client  ")
    text.append(f"{local.get('ip')}:{local.get('port')}", style="bold")
    text.append("  →  Server  ")
    text.append(f"{chosen.get('ip')}:{chosen.get('port')}\n", style="bold")
    text.append("        └─ ephemeral port your OS picked\n", style="dim")
    text.append("                              └─ well-known port for this service\n", style="dim")
    text.append(f"\n{section.get('winner_family')} won the connection race", style="dim")

    rows = [(f"{c['family']}  {c['ip']}",
             f"{c['connect_ms']} ms" if c.get("connect_ms") is not None else c.get("error"))
            for c in section.get("candidates") or []]
    if kernel:
        rows.append(("Kernel", f"RTT {kernel.get('rtt_ms')} ms · MSS {kernel.get('mss')} · "
                               f"{kernel.get('retransmits')} retransmits ({kernel.get('source')})"))

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
        ("Handshake", f"{section.get('handshake_ms')} ms"),
        ("Trusted via", section.get("trust_root")),
        ("CAA", {True: "issuer is authorised", False: "issuer is NOT listed",
                 None: "no comparable CAA record"}[section.get("caa_match")]),
    ]
    for i, cert in enumerate(chain):
        rows.append((f"Cert {i}", f"{cert.get('subject_cn')} ← {cert.get('issuer_cn')} · "
                                  f"{cert.get('key', {}).get('type')}"
                                  f"{cert.get('key', {}).get('bits')} · "
                                  f"{cert.get('days_left')} days left"))
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
    status = final.get("status") or 0
    colour = "green" if 200 <= status < 300 else "yellow" if status < 400 else "red"

    rows = []
    for hop in section.get("hops") or []:
        rows.append((f"{hop['status']} redirect", f"{hop['url']} → {hop['location']}"))
    rows += [
        ("Status", f"[{colour} bold]{final.get('protocol')} {status}[/{colour} bold]"),
        ("URL", final.get("url")),
        ("TTFB", f"{final.get('ttfb_ms')} ms"),
        ("Total", f"{final.get('total_ms')} ms"),
        ("Body", f"{final.get('wire_bytes')} bytes on the wire → "
                 f"{final.get('decoded_bytes')} decoded"
                 + (f" ({final.get('encoding')}, {final.get('ratio')}:1)"
                    if final.get("encoding") else "")),
        ("Content type", final.get("content_type")),
        ("CDN", section.get("cdn")),
        ("Cache", f"{(section.get('cache') or {}).get('state')} · "
                  f"age {(section.get('cache') or {}).get('age')} · "
                  f"{(section.get('cache') or {}).get('directives')}"),
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
    osi = trace.get("osi") or {}
    wide = console.width >= 100

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Layer", no_wrap=True)
    if wide:
        table.add_column("What happens here")
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
    osi = trace.get("osi") or {}
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
```

Add the `Tree` import at the top of `wj/render.py`, beside the existing imports:

```python
from rich.tree import Tree
```

- [ ] **Step 4: Run it to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_render.py -v`
Expected: PASS, 8 tests

- [ ] **Step 5: Run a real trace end to end**

Run: `.venv/bin/python trace.py example.com`
Expected: panels for local network, DNS, TCP, TLS, path, HTTP, then the waterfall, findings, the seven-layer finale with measured values at L1–L2, and the per-layer test commands. No traceback.

- [ ] **Step 6: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add wj/render.py tests/test_render.py tests/__init__.py
git commit -m "feat: terminal rendering with findings, waterfall and observed OSI finale"
```

---

## Task 15: Golden traces and the opt-in network test

**Files:**
- Create: `tests/fixtures/make_golden.py`, `tests/fixtures/golden/cdn-host.json`, `tests/fixtures/golden/plain-host.json`, `tests/fixtures/golden/partial-unprivileged.json`
- Create: `tests/test_golden.py`, `tests/test_network.py`, `pytest.ini`
- Test: as above

**Interfaces:**
- Consumes: `wj.run.orchestrate`, `wj.schema.validate`.
- Produces: three committed trace documents used as both Python regression inputs and HTML import fixtures.

- [ ] **Step 1: Register the network marker**

Create `pytest.ini`:

```ini
[pytest]
markers =
    network: hits the real network; opt in with -m network
addopts = -m "not network"
```

- [ ] **Step 2: Write the golden generator**

Create `tests/fixtures/make_golden.py`:

```python
"""Regenerate the golden trace documents. Deterministic — no network involved."""

import json
from pathlib import Path

from wj import capabilities, schema
from wj.context import Context
from wj.run import orchestrate

OUT = Path(__file__).parent / "golden"


def ctx_for(host, tools):
    caps = capabilities.Capabilities(libs={"dns": True, "cryptography": True},
                                     tools=tools, privileged=False, can_sudo=False)
    return Context(host=host, scheme="https", port=443, path="/",
                   timeout=8.0, deadline=1e9, caps=caps, results={})


def collectors(cdn=True, with_path=True, with_local=True):
    def local(ctx):
        if not with_local:
            return schema.unobserved("neither route nor ip is on PATH")
        return schema.observed(
            interface="en0", link="active", mtu=1500,
            local_ip="192.168.1.23", local_mac="aa:bb:cc:dd:ee:ff",
            gateway_ip="192.168.1.1", gateway_mac="11:22:33:44:55:66",
            dhcp={"server": "192.168.1.1", "lease_seconds": 86400,
                  "dns": ["192.168.1.1"]},
            public_ip="81.180.20.7", nat=True)

    def dns(ctx):
        return schema.observed(
            records={"A": [{"data": "104.16.132.229", "ttl": 300}],
                     "AAAA": [{"data": "2606:4700::6810:84e5", "ttl": 300}] if cdn else [],
                     "CNAME": [], "MX": [], "NS": [{"data": "ns1.example.net", "ttl": 3600}],
                     "TXT": [{"data": "v=spf1 -all", "ttl": 3600}],
                     "SOA": [], "CAA": [{"data": '0 issue "letsencrypt.org"', "ttl": 3600}],
                     "HTTPS": [{"data": '1 . alpn="h3,h2"', "ttl": 300}] if cdn else []},
            resolver={"servers": ["1.1.1.1"], "source": "scutil"},
            dnssec="secure" if cdn else "insecure",
            delegation=[{"level": "root", "server": "198.41.0.4",
                         "referral": ["a.gtld-servers.net"], "answer": []},
                        {"level": "tld", "server": "192.5.6.30",
                         "referral": ["ns1.example.net"], "answer": []},
                        {"level": "authoritative", "server": "203.0.113.9",
                         "referral": [], "answer": ["ns1.example.net"]}],
            alpn_advertised=["h3", "h2"] if cdn else [],
            ech=False, timing_ms={"cold": 41.2, "warm": 1.1})

    def tcp(ctx):
        return schema.observed(
            candidates=[{"ip": "104.16.132.229", "family": "ipv4",
                         "connect_ms": 12.4, "error": None}],
            chosen={"ip": "104.16.132.229", "family": "ipv4", "port": 443},
            winner_family="ipv4", local={"ip": "192.168.1.23", "port": 54213},
            kernel={"rtt_ms": 12.4, "mss": 1460, "retransmits": 0, "source": "TCP_INFO"})

    def tls(ctx):
        return schema.observed(
            version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256",
            alpn="h2" if cdn else "http/1.1", handshake_ms=38.2,
            chain=[{"subject_cn": "example.com", "issuer_cn": "letsencrypt.org R3",
                    "not_before": "2026-06-01T00:00:00+00:00",
                    "not_after": "2026-08-30T00:00:00+00:00", "days_left": 10,
                    "key": {"type": "EC", "bits": 256}, "sig_algo": "ecdsa-with-SHA256",
                    "sans": ["example.com", "www.example.com"], "scts": 2,
                    "ocsp": ["http://r3.o.lencr.org"], "is_ca": False}],
            trust_root="ISRG Root X1", verified=True, caa_match=True,
            resumption={"tested": False}, legacy_versions_accepted=[])

    def http(ctx):
        return schema.observed(
            hops=[{"url": "http://example.com/", "status": 301,
                   "location": "https://example.com/", "protocol": "HTTP/1.1",
                   "ttfb_ms": 40.1}],
            final={"url": "https://example.com/", "status": 200, "reason": "OK",
                   "protocol": "HTTP/2" if cdn else "HTTP/1.1",
                   "headers": [["content-type", "text/html; charset=utf-8"],
                               ["cache-control", "max-age=300"]],
                   "ttfb_ms": 88.0, "total_ms": 109.0, "wire_bytes": 14000,
                   "decoded_bytes": 61000, "encoding": "gzip", "ratio": 4.36,
                   "content_type": "text/html"},
            cache={"state": "HIT", "age": 412, "header": "cf-cache-status",
                   "directives": "max-age=300"} if cdn else
                  {"state": None, "age": None, "header": None, "directives": "max-age=300"},
            cdn="Cloudflare" if cdn else None,
            security={"grade": "B" if cdn else "F",
                      "present": {"Strict-Transport-Security": "max-age=63072000"},
                      "missing": ["Content-Security-Policy"] if cdn else
                                 ["Strict-Transport-Security", "Content-Security-Policy",
                                  "X-Content-Type-Options", "Referrer-Policy",
                                  "Permissions-Policy", "Cross-Origin-Opener-Policy"],
                      "cookies": [{"name": "session", "secure": True,
                                   "httponly": True, "samesite": "Lax"}],
                      "scheme": "https"},
            conditional={"tested": False})

    def path_collect(ctx):
        if not with_path:
            return schema.unobserved("traceroute not on PATH")
        return schema.observed(
            source="traceroute",
            hops=[{"ttl": 1, "ip": "192.168.1.1", "rdns": "router.lan",
                   "rtt_ms": 1.2, "asn": None, "as_name": None},
                  {"ttl": 2, "ip": None, "rdns": None, "rtt_ms": None,
                   "asn": None, "as_name": None},
                  {"ttl": 3, "ip": "203.0.113.9", "rdns": "ae-1.border.example.net",
                   "rtt_ms": 14.5, "asn": 8708, "as_name": "203.0.113.0/24"},
                  {"ttl": 4, "ip": "104.16.132.229", "rdns": None,
                   "rtt_ms": 15.0, "asn": 13335, "as_name": "104.16.0.0/12"}],
            asn_path=[8708, 13335], path_mtu=1500)

    return {"local": local, "dns": dns, "tcp": tcp, "tls": tls,
            "http": http, "path": path_collect}


def write(name, ctx, collectors_map):
    trace = orchestrate(ctx, collectors=collectors_map)
    trace["generated_at"] = "2026-08-20T09:31:02+00:00"  # keep the fixtures stable
    problems = schema.validate(trace)
    assert not problems, problems
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(json.dumps(trace, indent=2, default=str) + "\n")
    print(f"wrote {name}")


if __name__ == "__main__":
    tools = {"traceroute": "/usr/sbin/traceroute", "route": "/sbin/route",
             "ifconfig": "/sbin/ifconfig", "arp": "/usr/sbin/arp"}
    write("cdn-host.json", ctx_for("example.com", tools), collectors())
    write("plain-host.json", ctx_for("plain.example.net", tools),
          collectors(cdn=False))
    write("partial-unprivileged.json", ctx_for("example.com", {}),
          collectors(with_path=False, with_local=False))
```

Run it:

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
.venv/bin/python -m tests.fixtures.make_golden
```

Expected: three `wrote …` lines and three files under `tests/fixtures/golden/`.

- [ ] **Step 3: Write the golden test**

Create `tests/test_golden.py`:

```python
import json
from pathlib import Path

import pytest

from wj import schema

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
NAMES = ["cdn-host.json", "plain-host.json", "partial-unprivileged.json"]


@pytest.mark.parametrize("name", NAMES)
def test_golden_trace_validates(name):
    trace = json.loads((GOLDEN / name).read_text())
    assert schema.validate(trace) == []


@pytest.mark.parametrize("name", NAMES)
def test_golden_trace_has_all_seven_osi_layers(name):
    trace = json.loads((GOLDEN / name).read_text())
    assert set(trace["osi"]) == {"l1", "l2", "l3", "l4", "l5", "l6", "l7"}


def test_cdn_golden_observes_every_section():
    trace = json.loads((GOLDEN / "cdn-host.json").read_text())
    for name in schema.SECTIONS:
        assert trace[name]["observed"] is True, name
    assert trace["osi"]["l2"]["observed"] is True


def test_partial_golden_explains_what_it_could_not_see():
    trace = json.loads((GOLDEN / "partial-unprivileged.json").read_text())
    assert trace["local"]["observed"] is False
    assert trace["path"]["observed"] is False
    assert trace["osi"]["l1"]["why_not"]
    assert trace["osi"]["l3"]["observed"] is True


def test_golden_traces_carry_findings():
    trace = json.loads((GOLDEN / "cdn-host.json").read_text())
    texts = " ".join(n["text"] for n in trace["notes"])
    assert "expires in 10 days" in texts
```

- [ ] **Step 4: Write the opt-in network test**

Create `tests/test_network.py`:

```python
import time

import pytest

from wj import capabilities, schema
from wj.context import Context
from wj.run import orchestrate

pytestmark = pytest.mark.network


def test_real_trace_of_example_com_validates():
    caps = capabilities.detect()
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=8.0, deadline=time.monotonic() + 25.0, caps=caps, results={})
    trace = orchestrate(ctx)
    assert schema.validate(trace) == []
    assert trace["dns"]["observed"] is True
    assert trace["tcp"]["observed"] is True
    assert trace["http"]["observed"] is True
    assert trace["http"]["final"]["status"] in (200, 301, 302)
```

- [ ] **Step 5: Run the suites**

Run: `.venv/bin/python -m pytest -q`
Expected: all tests pass, network tests deselected.

Run: `.venv/bin/python -m pytest -m network -q`
Expected: PASS (requires internet; skip this command if offline and note it).

- [ ] **Step 6: Commit**

```bash
git add pytest.ini tests/fixtures/make_golden.py tests/fixtures/golden tests/test_golden.py tests/test_network.py
git commit -m "test: golden trace fixtures and opt-in network integration test"
```

---

## Task 16: HTML structural fixes — theme, contrast, expansion, escaping, accessibility

**Files:**
- Move: `~/Projects/webpage-journey.html` → `webpage-journey/webpage-journey.html`
- Modify: that file's `<style>` block and the card-building JS

**Interfaces:**
- Produces (JS, used by later tasks): `escapeHtml(str) -> string`, `LAYER_COLOR_VARS: {1..7: string}`, `applyTheme(name)`, `REDUCED_MOTION: boolean`, `cardEls: HTMLElement[]`, `setExpanded(idx, open)`.

- [ ] **Step 1: Move the page into the project and commit the starting point**

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
mv ~/Projects/webpage-journey.html ./webpage-journey.html
git add webpage-journey.html
git commit -m "chore: move the walkthrough page into the project"
```

- [ ] **Step 2: Replace the three `:root` colour blocks with a dark-first, contrast-safe palette**

Delete the existing `:root { … }`, `@media (prefers-color-scheme: dark) { … }`, and `:root[data-theme="dark"] { … }` blocks entirely and put this in their place:

```css
  /* Dark-first, matching the Learning Hub convention: :root is dark, body.light overrides.
     Layer chip backgrounds are shared by both themes and all clear 4.5:1 against white text. */
  :root {
    color-scheme: dark;
    --surface-1:      #1a1a19;
    --page:           #0d0d0d;
    --text-primary:   #ffffff;
    --text-secondary: #c3c2b7;
    --text-muted:     #8f8d86;
    --gridline:       #2c2c2a;
    --border:         rgba(255,255,255,0.12);
    --card-bg:        #212120;

    --l7: #1f5fae;  /* Application  — 6.4:1 on white */
    --l6: #b4491b;  /* Presentation — 5.5:1 */
    --l5: #0e7a55;  /* Session      — 5.3:1 */
    --l4: #8a5a00;  /* Transport    — 6.0:1 */
    --l3: #a8306b;  /* Network      — 6.4:1 */
    --l2: #16711f;  /* Data Link    — 6.1:1 */
    --l1: #4a3aa7;  /* Physical     — 8.6:1 */

    --l7-accent: #6aa6ee;
    --l6-accent: #f08a5d;
    --l5-accent: #3fc79a;
    --l4-accent: #e0a72e;
    --l3-accent: #e97fb0;
    --l2-accent: #4fbf58;
    --l1-accent: #9085e9;

    --good: #3fbf5a;
    --critical: #e66767;
    --warn: #e0a72e;
  }
  body.light {
    color-scheme: light;
    --surface-1:      #fcfcfb;
    --page:           #f9f9f7;
    --text-primary:   #0b0b0b;
    --text-secondary: #52514e;
    --text-muted:     #6d6b66;
    --gridline:       #e1e0d9;
    --border:         rgba(11,11,11,0.12);
    --card-bg:        #ffffff;

    --l7-accent: #1f5fae;
    --l6-accent: #b4491b;
    --l5-accent: #0e7a55;
    --l4-accent: #8a5a00;
    --l3-accent: #a8306b;
    --l2-accent: #16711f;
    --l1-accent: #4a3aa7;

    --good: #0a7d24;
    --critical: #c02b2b;
    --warn: #8a5a00;
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
    }
  }
```

- [ ] **Step 3: Replace the clipping expansion rule**

Delete these two rules:

```css
  .step-body { max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }
  .step-card.expanded .step-body { max-height: 600px; }
```

and put this in their place:

```css
  /* grid-template-rows animates to true auto height — max-height would clip taller content */
  .step-body {
    display: grid;
    grid-template-rows: 0fr;
    transition: grid-template-rows 0.3s ease;
  }
  .step-card.expanded .step-body { grid-template-rows: 1fr; }
  .step-body > .step-body-inner { min-height: 0; overflow: hidden; }
```

- [ ] **Step 4: Add the accessibility styles**

Append to the `<style>` block:

```css
  .step-head {
    width: 100%;
    background: none;
    border: none;
    font-family: inherit;
    color: inherit;
    text-align: left;
    padding: 0;
    cursor: pointer;
  }
  .step-head:focus-visible,
  .osi-layer:focus-visible,
  .theme-btn:focus-visible,
  .btn-primary:focus-visible,
  .btn-ghost:focus-visible {
    outline: 3px solid var(--l7-accent);
    outline-offset: 2px;
  }
  .visually-hidden {
    position: absolute; width: 1px; height: 1px;
    padding: 0; margin: -1px; overflow: hidden;
    clip: rect(0 0 0 0); white-space: nowrap; border: 0;
  }
```

- [ ] **Step 5: Rewrite the card markup so the header is a real button**

In the `JOURNEY.forEach` block, replace the `card.innerHTML = …` assignment with:

```js
    var headId = "step-head-" + idx;
    var bodyId = "step-body-" + idx;

    card.innerHTML =
      '<button class="step-head" type="button" id="' + headId + '"' +
              ' aria-expanded="false" aria-controls="' + bodyId + '">' +
        '<span class="step-num">' + (idx + 1) + '</span>' +
        '<span class="step-titles">' +
          '<span class="step-phase">' + escapeHtml(step.phase) + '</span>' +
          '<span class="step-title">' + escapeHtml(step.title) + '</span>' +
        '</span>' +
        '<span class="step-chips">' + chips + '</span>' +
        '<span class="step-caret" aria-hidden="true">&#9656;</span>' +
      '</button>' +
      '<div class="step-body" id="' + bodyId + '" role="region" aria-labelledby="' + headId + '">' +
        '<div class="step-body-inner"></div>' +
      '</div>';
```

Update the `.step-head` flex styles so the spans still lay out — change the existing `.step-titles`, `.step-phase`, `.step-title`, `.step-chips` selectors' contents from `p`/`div` assumptions by adding `display: block;` to `.step-phase` and `.step-title`, and `display: flex;` to `.step-head`, `.step-titles`, `.step-chips`.

Replace the click handler registration with one that also drives ARIA:

```js
    card.querySelector(".step-head").addEventListener("click", function () {
      setExpanded(idx, !card.classList.contains("expanded"));
    });
```

- [ ] **Step 6: Add the expansion, keyboard, and theme helpers**

Add near the other helpers in the IIFE:

```js
  var REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function setExpanded(idx, open) {
    cardEls.forEach(function (c, i) {
      var isTarget = i === idx;
      var shouldOpen = isTarget && open;
      c.classList.toggle("expanded", shouldOpen);
      c.querySelector(".step-head").setAttribute("aria-expanded", shouldOpen ? "true" : "false");
    });
    if (open) {
      renderStepBody(cardEls[idx], JOURNEY[idx]);
      setActiveStep(idx, false);
    } else {
      highlightLayers([]);
      setTrack(null);
    }
  }

  function focusStep(idx) {
    var visible = visibleIndices();
    if (!visible.length) return;
    var pos = Math.max(0, Math.min(visible.length - 1, idx));
    cardEls[visible[pos]].querySelector(".step-head").focus();
  }

  stepsContainer.addEventListener("keydown", function (e) {
    var head = e.target.closest(".step-head");
    if (!head) return;
    var current = cardEls.findIndex(function (c) { return c.contains(head); });
    var visible = visibleIndices();
    var pos = visible.indexOf(current);

    if (e.key === "ArrowDown") { e.preventDefault(); focusStep(pos + 1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); focusStep(pos - 1); }
    else if (e.key === "Home") { e.preventDefault(); focusStep(0); }
    else if (e.key === "End") { e.preventDefault(); focusStep(visible.length - 1); }
    else if (e.key === "Escape") { setExpanded(current, false); }
  });
```

Replace the whole theme-toggle block with:

```js
  var themeBtn = document.getElementById("themeToggle");

  function applyTheme(name) {
    document.body.classList.toggle("light", name === "light");
    themeBtn.textContent = name === "light" ? "Dark mode" : "Light mode";
    themeBtn.setAttribute("aria-pressed", name === "light" ? "false" : "true");
    try { localStorage.setItem("wj-theme", name); } catch (e) {}
  }

  var storedTheme = null;
  try { storedTheme = localStorage.getItem("wj-theme"); } catch (e) {}
  applyTheme(storedTheme ||
    (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));

  themeBtn.addEventListener("click", function () {
    applyTheme(document.body.classList.contains("light") ? "dark" : "light");
  });
```

- [ ] **Step 7: Enforce the single escaping contract**

In the `JOURNEY` array, remove every hand-written HTML entity from the `code:` strings — write `<link rel="stylesheet">` and `<html>...</html>` as literal characters. Then in `renderStepBody`, make the code block the only place escaping happens:

```js
    if (levelState === "technical" && codeContent) {
      html += '<p class="label">On the wire</p><code class="block">' +
              escapeHtml(codeContent) + "</code>";
    }
```

and delete the `escapeHtml(...)` calls from the return values of `buildDnsCode` and `buildTcpCode` so they return plain text like every other code source.

- [ ] **Step 8: Verify in a browser**

Open `webpage-journey/webpage-journey.html` and confirm all of the following:

1. The page loads dark by default (or light if your OS is set to light), and the toggle flips it and survives a reload.
2. `Tab` reaches every step header; `Enter` expands one; `↑`/`↓` move between headers; `Esc` collapses.
3. Expand the "TCP Connection" step in Technical view — the code block is fully visible with no cut-off at the bottom.
4. The code block shows `<link rel="stylesheet" …>` as visible text, not as a rendered tag and not as `&lt;link&gt;`.
5. Layer chips are legible in both themes.

- [ ] **Step 9: Commit**

```bash
git add webpage-journey.html
git commit -m "fix: dark-first theme, AA-contrast layers, unclipped cards, keyboard access"
```

---

## Task 17: HTML data layer — trace import, provenance, live fallback

**Files:**
- Modify: `webpage-journey.html`

**Interfaces:**
- Produces:
  - `LIVE_LOOKUPS_ENABLED: boolean` (single constant that makes the page fully offline)
  - `TRACE_SCHEMA_MAJOR: number`
  - `state: {trace, live, level, https, layerFilter, failure}`
  - `fact(value, source) -> {value, source}` where `source` is `"measured" | "live" | "illustrative" | "redacted"`
  - `renderFact(fact) -> string` (value plus provenance badge)
  - `importTraceText(text) -> {ok: boolean, trace?: object, error?: string}`
  - `traceSection(name) -> object | null`

- [ ] **Step 1: Add the provenance and import styles**

Append to `<style>`:

```css
  .prov { font-size: 10px; margin-left: 5px; vertical-align: 1px; cursor: help; }
  .prov-measured    { color: var(--good); }
  .prov-live        { color: var(--l7-accent); }
  .prov-illustrative{ color: var(--text-muted); }
  .prov-redacted    { color: var(--warn); }

  .prov-legend {
    display: flex; flex-wrap: wrap; gap: 14px;
    font-size: 12px; color: var(--text-muted); margin: 0 0 18px;
  }

  .trace-bar {
    display: none;
    background: var(--card-bg); border: 1px solid var(--border);
    border-left: 4px solid var(--good); border-radius: 4px;
    padding: 12px 16px; margin-bottom: 18px; font-size: 13px;
  }
  .trace-bar.show { display: block; }
  .trace-bar.mismatch { border-left-color: var(--warn); }
  .trace-bar .meta { color: var(--text-muted); font-size: 12px; margin-top: 4px; }

  .drop-hint {
    border: 1px dashed var(--border); border-radius: 4px;
    padding: 10px 14px; font-size: 12.5px; color: var(--text-muted);
    margin-bottom: 18px;
  }
  body.dragging .drop-hint { border-color: var(--good); color: var(--text-primary); }
```

- [ ] **Step 2: Add the markup**

Immediately after the `.live-hint` paragraph, insert:

```html
  <p class="prov-legend">
    <span><span class="prov prov-measured">●</span> measured — from an imported trace</span>
    <span><span class="prov prov-live">◐</span> live — fetched by this page just now</span>
    <span><span class="prov prov-illustrative">○</span> illustrative — a teaching example</span>
    <span><span class="prov prov-redacted">◍</span> redacted at export</span>
  </p>

  <div class="drop-hint" id="dropHint">
    Drop a <code>trace.json</code> here (or <label class="visually-hidden" for="traceFile">choose a trace file</label><input type="file" id="traceFile" accept=".json,application/json">) to replace the illustrative values with real measurements from
    <code>python3 trace.py example.com --json trace.json</code>.
  </div>

  <div class="trace-bar" id="traceBar"></div>
```

- [ ] **Step 3: Add the data layer JS**

Insert near the top of the IIFE, after the `LAYERS` array:

```js
  // Flip this to false to make the page fully offline and file:// clean —
  // that single change is the whole Learning Hub migration.
  var LIVE_LOOKUPS_ENABLED = true;
  var TRACE_SCHEMA_MAJOR = 1;
  var TRACE_STORAGE_KEY = "wj-trace";

  var state = {
    trace: null,
    live: null,
    level: "simple",
    https: true,
    layerFilter: null,
    failure: null
  };

  var PROV_GLYPH = {
    measured: "●", live: "◐", illustrative: "○", redacted: "◍"
  };
  var PROV_LABEL = {
    measured: "measured — from the imported trace",
    live: "live — fetched by this page just now",
    illustrative: "illustrative — a teaching example, not your data",
    redacted: "redacted at export"
  };

  function fact(value, source) {
    if (value === "[redacted at export]") return { value: "redacted", source: "redacted" };
    return { value: value, source: source };
  }

  function renderFact(f) {
    if (!f || f.value === null || f.value === undefined || f.value === "") return "";
    return escapeHtml(String(f.value)) +
      '<span class="prov prov-' + f.source + '" title="' + escapeHtml(PROV_LABEL[f.source]) +
      '">' + PROV_GLYPH[f.source] + "</span>";
  }

  function traceSection(name) {
    if (!state.trace) return null;
    var section = state.trace[name];
    return section && section.observed ? section : null;
  }

  function traceWhyNot(name) {
    if (!state.trace) return null;
    var section = state.trace[name];
    return section && !section.observed ? section.why_not : null;
  }

  function importTraceText(text) {
    var parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      return { ok: false, error: "That file isn't valid JSON." };
    }
    var schema = parsed && parsed.schema;
    if (typeof schema !== "string" || schema.indexOf("webpage-journey-trace/") !== 0) {
      return { ok: false, error: "That JSON isn't a webpage-journey trace document." };
    }
    var major = parseInt(schema.split("/")[1], 10);
    if (major !== TRACE_SCHEMA_MAJOR) {
      return { ok: false, error: "This trace is schema version " + major +
               "; this page reads version " + TRACE_SCHEMA_MAJOR +
               ". Re-run trace.py, or open the matching version of this page." };
    }
    return { ok: true, trace: parsed };
  }

  function adoptTrace(trace) {
    state.trace = trace;
    try { localStorage.setItem(TRACE_STORAGE_KEY, JSON.stringify(trace)); } catch (e) {}
    renderTraceBar();
    refreshAllBodies();
  }

  function renderTraceBar() {
    var bar = document.getElementById("traceBar");
    if (!state.trace) { bar.classList.remove("show"); return; }

    var t = state.trace;
    var host = (t.target || {}).host || "unknown host";
    var typed = parseHostFromInput(urlInput.value);
    var mismatch = typed && typed !== host;

    var unobserved = [];
    ["local", "dns", "tcp", "tls", "http", "path"].forEach(function (name) {
      var why = traceWhyNot(name);
      if (why) unobserved.push(name + ": " + why);
    });

    bar.classList.add("show");
    bar.classList.toggle("mismatch", !!mismatch);
    bar.innerHTML =
      "<strong>Trace loaded for " + escapeHtml(host) + "</strong>" +
      (mismatch ? ' <span style="color:var(--warn)">— the box above says ' +
                  escapeHtml(typed) + ", so those two disagree. Values below come from the trace.</span>" : "") +
      '<div class="meta">captured ' + escapeHtml(t.generated_at || "?") +
      " by " + escapeHtml((t.tool || {}).name || "trace.py") + " " +
      escapeHtml((t.tool || {}).version || "") +
      (t.redacted ? " · exported with redaction" : "") +
      (unobserved.length ? "<br>not observed — " + escapeHtml(unobserved.join(" · ")) : "") +
      "</div>";
  }

  function wireTraceImport() {
    var hint = document.getElementById("dropHint");
    var input = document.getElementById("traceFile");

    function load(file) {
      var reader = new FileReader();
      reader.onload = function () {
        var result = importTraceText(String(reader.result));
        if (result.ok) {
          adoptTrace(result.trace);
        } else {
          hint.innerHTML = '<span style="color:var(--critical)">' +
                           escapeHtml(result.error) + "</span>";
        }
      };
      reader.readAsText(file);
    }

    input.addEventListener("change", function () {
      if (input.files && input.files[0]) load(input.files[0]);
    });

    ["dragenter", "dragover"].forEach(function (name) {
      document.addEventListener(name, function (e) {
        e.preventDefault();
        document.body.classList.add("dragging");
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      document.addEventListener(name, function (e) {
        e.preventDefault();
        document.body.classList.remove("dragging");
      });
    });
    document.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        load(e.dataTransfer.files[0]);
      }
    });
  }
```

- [ ] **Step 4: Restore a stored trace and honour the deep link on load**

Replace the `// init` block at the bottom of the IIFE with:

```js
  // init
  httpsToggle.checked = true;
  wireTraceImport();

  try {
    var stored = localStorage.getItem(TRACE_STORAGE_KEY);
    if (stored) {
      var restored = importTraceText(stored);
      if (restored.ok) { state.trace = restored.trace; renderTraceBar(); }
    }
  } catch (e) {}

  var deepLinkHost = new URLSearchParams(window.location.search).get("host");
  if (deepLinkHost) {
    urlInput.value = (httpsOn ? "https://" : "http://") + deepLinkHost;
    if (LIVE_LOOKUPS_ENABLED) goBtn.click();
  }
```

- [ ] **Step 5: Gate every live fetch behind the constant**

At the top of `performLiveLookup`, insert:

```js
    if (!LIVE_LOOKUPS_ENABLED) {
      liveState = "error";
      liveError = "Live lookups are disabled in this build. Drop a trace file for real data.";
      renderLivePanel();
      refreshAllBodies();
      return;
    }
```

- [ ] **Step 6: Verify in a browser**

1. Load the page, drop `tests/fixtures/golden/cdn-host.json` on it. The trace bar appears naming `example.com` and the capture time.
2. Reload the page — the trace bar is still there (restored from `localStorage`).
3. Drop `tests/fixtures/golden/partial-unprivileged.json`. The bar lists `local: neither route nor ip is on PATH` and `path: traceroute not on PATH`.
4. Edit a copy of a golden file, change `"webpage-journey-trace/1"` to `/2`, and drop it. The hint shows the version refusal and the previous trace stays loaded.
5. Drop a non-JSON file. The hint shows "That file isn't valid JSON."
6. Type a different host in the URL box with a trace loaded — the bar shows the mismatch warning.

- [ ] **Step 7: Commit**

```bash
git add webpage-journey.html
git commit -m "feat: trace import, provenance badges, and offline-capable data layer"
```

---

## Task 18: The fifteen-stage journey

**Files:**
- Modify: `webpage-journey.html` (the `JOURNEY` array and `renderStepBody`)

**Interfaces:**
- Each `JOURNEY` entry gains: `key: string`, `bind(): Array<[label, fact]>`, `testYourself(): string`, `whatBreaks: string[]`.
- Produces: `renderFactGrid(rows) -> string`.

- [ ] **Step 1: Add the styles for the new blocks**

Append to `<style>`:

```css
  .fact-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 10px 18px;
    margin: 12px 0 4px;
  }
  .fact-grid .k {
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--text-muted); margin-bottom: 2px;
  }
  .fact-grid .v {
    font-family: ui-monospace, monospace; font-size: 12px;
    color: var(--text-primary); word-break: break-word;
  }
  .breaks { margin: 10px 0 0; padding-left: 18px; font-size: 12.5px; }
  .breaks li { margin-bottom: 3px; }
  .copy-row { display: flex; gap: 8px; align-items: flex-start; }
  .copy-row code.block { flex: 1; margin-top: 4px; }
  .copy-btn {
    border: 1px solid var(--border); background: var(--surface-1);
    color: var(--text-secondary); border-radius: 4px;
    font-size: 11px; padding: 4px 8px; cursor: pointer; margin-top: 4px;
    white-space: nowrap;
  }
```

- [ ] **Step 2: Add the three new stages and the per-stage blocks**

Replace the entire `JOURNEY` array with the version below. Existing stages keep their `simple` and `technical` strings verbatim — only `key`, `pos`, `bind`, `testYourself`, and `whatBreaks` are added, and the `code` strings lose their hand-written HTML entities (Task 16, Step 7).

```js
  function host() {
    return (state.trace && state.trace.target && state.trace.target.host) ||
           (liveData && liveData.host) || parseHostFromInput(urlInput.value) || "example.com";
  }

  function targetIp() {
    var tcp = traceSection("tcp");
    if (tcp && tcp.chosen) return tcp.chosen.ip;
    if (liveData && liveData.targetIp) return liveData.targetIp;
    return "93.184.216.34";
  }

  var JOURNEY = [
    {
      key: "enter",
      phase: "Before anything leaves your machine",
      title: "You hit Enter",
      simple: "Your browser checks whether it already knows the answer before doing any network work at all.",
      technical: "The browser checks its HTTP cache for a fresh, unexpired response to this exact URL, checks the HSTS preload list to see if it must force HTTPS, and — if a Service Worker is registered for this origin — may let that script answer from its own cache with zero network traffic.",
      layers: [],
      pos: 2,
      bind: function () { return []; },
      testYourself: function () {
        return "# In DevTools: Network tab → disable cache, then compare load times\n" +
               "# Chrome's HSTS state:  chrome://net-internals/#hsts";
      },
      whatBreaks: [
        "A stale cached response keeps serving after a deploy — usually a Cache-Control mistake, not a network fault.",
        "A buggy Service Worker answers from its own cache and the network is never consulted at all."
      ]
    },
    {
      key: "local",
      phase: "Leaving your machine",
      title: "Your local network",
      simple: "Before anything can travel, your computer has to hand the data to the one device on your local network that knows how to reach the outside world: your router.",
      technical: "Your OS looks up the route for the destination address and picks an egress interface. Because the destination is not on your subnet, the packet is addressed at Layer 3 to the server, but the Ethernet or Wi-Fi frame carrying it is addressed at Layer 2 to your <strong>default gateway's MAC address</strong>, which ARP resolved and cached. That is the single most useful thing to understand about L2: frames are addressed hop by hop, packets end to end. Your DHCP lease is what told your machine its address, its gateway, and which resolver to ask. Almost every home and office network then applies NAT, so your private RFC 1918 address is rewritten to one public address on the way out.",
      code: "Route for 93.184.216.34:\n  interface en0, gateway 192.168.1.1\n\nFrame leaving your NIC:\n  dst MAC 11:22:33:44:55:66   <- your router, NOT the server\n  src MAC aa:bb:cc:dd:ee:ff\n    IP packet inside:\n      src 192.168.1.23  dst 93.184.216.34\n\nNAT rewrites the source on the way out:\n  192.168.1.23  ->  81.180.20.7",
      layers: [ {n:2,w:"primary"}, {n:1,w:"primary"}, {n:3,w:"secondary"} ],
      pos: 6,
      bind: function () {
        var s = traceSection("local");
        if (!s) return [];
        return [
          ["Interface", fact(s.interface, "measured")],
          ["Link", fact(s.link, "measured")],
          ["MTU", fact(s.mtu, "measured")],
          ["Your address", fact(s.local_ip, "measured")],
          ["Your MAC", fact(s.local_mac, "measured")],
          ["Gateway", fact(s.gateway_ip, "measured")],
          ["Gateway MAC", fact(s.gateway_mac, "measured")],
          ["Public address", fact(s.public_ip, "measured")],
          ["NAT", fact(s.nat ? "yes" : "no", "measured")]
        ];
      },
      testYourself: function () {
        var s = traceSection("local");
        var gw = (s && s.gateway_ip) || "192.168.1.1";
        return "route -n get " + targetIp() + "     # macOS: which interface and gateway\n" +
               "ip route get " + targetIp() + "     # Linux: the same question\n" +
               "arp -n " + gw + "            # the MAC your frames are actually addressed to";
      },
      whatBreaks: [
        "Cable unplugged or Wi-Fi dropped — L1. Nothing above this can work.",
        "No DHCP lease, so no address and no gateway — you are on the network but cannot address anyone.",
        "Wrong gateway or a poisoned ARP cache — frames leave, but to the wrong device.",
        "MTU mismatch on a VPN: small requests work, large responses hang."
      ]
    },
    {
      key: "dns",
      phase: "Finding the address",
      title: "DNS Resolution",
      simple: "Your computer translates the human-readable domain name into a numeric IP address, the same way you'd look up a phone number by a name.",
      technical: "Checks cascade in order: browser DNS cache → OS resolver cache → hosts file → configured recursive resolver (your ISP, or a public one like 1.1.1.1 / 8.8.8.8). If nothing is cached, the resolver walks the hierarchy: root server → TLD server (.com) → authoritative nameserver for the domain, which returns the A record (IPv4) or AAAA record (IPv6). The result is cached locally for its TTL, so a second visit within that window skips the lookup entirely. Two records worth knowing beyond A/AAAA: <strong>CAA</strong> names which certificate authorities may issue for this domain, and the <strong>HTTPS/SVCB</strong> record advertises HTTP/3 support and Encrypted Client Hello before the first connection is even made. If the answer is signed and your resolver validates it, <strong>DNSSEC</strong> sets the AD bit — otherwise the answer is simply trusted.",
      layers: [ {n:7,w:"primary"}, {n:4,w:"secondary"}, {n:3,w:"secondary"} ],
      pos: 12,
      bind: function () {
        var s = traceSection("dns");
        if (!s) return [];
        var rows = [];
        Object.keys(s.records || {}).forEach(function (rtype) {
          var list = s.records[rtype];
          if (list && list.length) {
            rows.push([rtype, fact(list.map(function (r) { return r.data; }).join(", "), "measured")]);
          }
        });
        rows.push(["TTL", fact(((s.records.A || [])[0] || {}).ttl + "s", "measured")]);
        rows.push(["Resolver", fact(((s.resolver || {}).servers || []).join(", "), "measured")]);
        rows.push(["DNSSEC", fact(s.dnssec, "measured")]);
        rows.push(["Advertised ALPN", fact((s.alpn_advertised || []).join(", ") || "none", "measured")]);
        rows.push(["Lookup time", fact((s.timing_ms || {}).cold + " ms cold, " +
                                       (s.timing_ms || {}).warm + " ms warm", "measured")]);
        return rows;
      },
      testYourself: function () {
        return "dig +short " + host() + " A AAAA\n" +
               "dig +dnssec " + host() + " | grep -q ' ad ' && echo signed\n" +
               "dig " + host() + " HTTPS      # HTTP/3 and ECH advertisement\n" +
               "dig +trace " + host() + "     # walk root -> TLD -> authoritative";
      },
      whatBreaks: [
        "NXDOMAIN — the name does not exist. Check spelling and registration before anything else.",
        "The name resolves but to a stale IP: someone changed a record and the old TTL is still cached.",
        "Split-horizon DNS or a VPN resolver returns an internal address you cannot reach.",
        "The resolver itself is unreachable — everything fails at once, and it looks like the whole internet is down."
      ]
    },
    {
      key: "address",
      phase: "Picking a route",
      title: "Choosing an address",
      simple: "A domain often resolves to several addresses. Your browser races them and uses whichever answers first.",
      technical: "This is <strong>Happy Eyeballs</strong> (RFC 8305). Given both AAAA and A records, the client starts an IPv6 connection first, then starts an IPv4 attempt a short time later rather than waiting for IPv6 to time out — and uses whichever completes first. It is why a broken IPv6 path costs you milliseconds instead of thirty seconds. When a domain returns several addresses, they are usually <strong>anycast</strong> edges of a CDN: the same address is announced from many locations, and routing decides which one you actually reach. Comparing connect times across the returned addresses tells you whether you are hitting one origin server or a distributed edge.",
      layers: [ {n:4,w:"primary"}, {n:3,w:"primary"} ],
      pos: 18,
      bind: function () {
        var s = traceSection("tcp");
        if (!s) return [];
        var rows = (s.candidates || []).map(function (c) {
          return [c.family + " " + c.ip,
                  fact(c.error ? c.error : c.connect_ms + " ms", "measured")];
        });
        rows.push(["Winner", fact(s.winner_family + " " + (s.chosen || {}).ip, "measured")]);
        return rows;
      },
      testYourself: function () {
        return "curl -sS -o /dev/null -w '%{time_connect}s via %{remote_ip}\\n' -6 https://" + host() + "/\n" +
               "curl -sS -o /dev/null -w '%{time_connect}s via %{remote_ip}\\n' -4 https://" + host() + "/";
      },
      whatBreaks: [
        "IPv6 is advertised but unroutable on your network — Happy Eyeballs hides it, so it stays broken and invisible for years.",
        "One anycast edge is unhealthy: some users see failures and others do not, from the same address.",
        "A host publishes only an A record, so IPv6-only clients cannot reach it at all."
      ]
    },
    {
      key: "path",
      phase: "Crossing the internet",
      title: "Crossing the internet",
      simple: "Your request is passed from router to router across many separate networks until it reaches the one that hosts the site.",
      technical: "No single organisation carries your packet end to end. It crosses a sequence of <strong>autonomous systems</strong> — your ISP, one or more transit providers, then the destination's network or CDN — each making its own independent routing decision with BGP. Traceroute reveals that sequence by sending packets with deliberately small TTLs and reading who sends back the expiry message. Two things matter operationally: the RTT growth between hops tells you where latency is actually introduced, and the AS numbers tell you whose network to contact when a hop is the problem. The <strong>path MTU</strong> is the smallest link along the way; exceed it with the don't-fragment bit set and packets vanish silently.",
      layers: [ {n:3,w:"primary"}, {n:2,w:"secondary"} ],
      pos: 26,
      bind: function () {
        var s = traceSection("path");
        if (!s) return [];
        var rows = (s.hops || []).map(function (h) {
          return ["Hop " + h.ttl,
                  fact((h.ip || "* no reply") +
                       (h.rtt_ms ? "  " + h.rtt_ms + " ms" : "") +
                       (h.asn ? "  AS" + h.asn : ""), "measured")];
        });
        if ((s.asn_path || []).length) {
          rows.push(["AS path", fact(s.asn_path.map(function (n) { return "AS" + n; }).join(" → "), "measured")]);
        }
        if (s.path_mtu) rows.push(["Path MTU", fact(s.path_mtu, "measured")]);
        return rows;
      },
      testYourself: function () {
        return "traceroute " + host() + "\n" +
               "mtr " + host() + "            # traceroute plus continuous loss statistics\n" +
               "ping -D -s 1472 " + host() + " # probe path MTU (macOS)";
      },
      whatBreaks: [
        "A transit provider has a bad link: latency triples for some users and is fine for others.",
        "Asymmetric routing means the return path differs from the outbound one — traceroute only shows you half the story.",
        "A firewall drops ICMP, so hops show as `* * *` while real traffic passes fine. Missing hops are not necessarily a fault.",
        "Path MTU black holes: the handshake succeeds and the first large response hangs forever."
      ]
    },
    {
      key: "tcp",
      phase: "Opening the pipe",
      title: "TCP Connection",
      simple: "Your browser and the server do a quick three-step handshake to confirm they're both ready to talk reliably.",
      technical: "SYN → SYN-ACK → ACK. This establishes a reliable, ordered, bidirectional byte stream on top of unreliable IP: lost packets are retransmitted, and out-of-order packets are reassembled before your app ever sees them. Your OS picks a random unused local <strong>ephemeral port</strong> (roughly 32768–60999) for the client side, while the server listens on a well-known port — 443 for HTTPS, 80 for HTTP. That client-IP:port + server-IP:port pair is a full TCP connection; the same client can hold thousands of simultaneous connections to different servers because each pair is unique.<br><br><strong>TCP vs. UDP:</strong> TCP trades speed for reliability, so it's the default for HTTP/1.1 and HTTP/2. UDP has no handshake, ordering, or retransmission — it just fires packets and hopes. That statelessness is exactly why DNS queries typically use UDP and why QUIC, the transport under HTTP/3, is built on UDP too: it re-implements reliability itself, but avoids TCP's head-of-line blocking, where one lost packet stalls every stream on the connection.",
      layers: [ {n:4,w:"primary"}, {n:3,w:"secondary"} ],
      pos: 32,
      bind: function () {
        var s = traceSection("tcp");
        if (!s) return [];
        var k = s.kernel || {};
        return [
          ["Client", fact((s.local || {}).ip + ":" + (s.local || {}).port, "measured")],
          ["Server", fact((s.chosen || {}).ip + ":" + (s.chosen || {}).port, "measured")],
          ["Round-trip time", fact(k.rtt_ms != null ? k.rtt_ms + " ms" : null, "measured")],
          ["Segment size (MSS)", fact(k.mss, "measured")],
          ["Retransmits", fact(k.retransmits, "measured")],
          ["Source", fact(k.source, "measured")]
        ];
      },
      testYourself: function () {
        return "nc -vz " + host() + " 443       # is the port open at all?\n" +
               "ss -ti  # Linux: live RTT, MSS and retransmits per connection";
      },
      whatBreaks: [
        "Connection refused — something answered and said no. The host is reachable; the service is not listening.",
        "Connection times out — a firewall is dropping silently. Refused and timed-out are very different diagnoses.",
        "Retransmits climbing means packet loss; throughput collapses long before the connection drops.",
        "Ephemeral port exhaustion on a busy client: new connections fail while existing ones are fine."
      ]
    },
    {
      key: "tls",
      phase: "Locking the pipe",
      title: "TLS Handshake",
      httpsOnly: true,
      simple: "Before any real data is sent, the browser and server agree on encryption keys so nobody in between can read or tamper with the traffic.",
      technical: "ClientHello (supported cipher suites + <strong>SNI</strong> hostname, so a server hosting many sites on one IP knows which certificate to present, plus the <strong>ALPN</strong> list saying which HTTP version the client speaks) → ServerHello + certificate chain → the browser validates the chain against trusted CAs, checking signature, expiry, hostname match and revocation → key exchange (typically ECDHE over x25519) derives a shared session key that never travels over the wire → Finished messages confirm both sides derived the same key. TLS 1.3 does this in one round trip; TLS 1.2 needs two. The chain matters: your browser trusts the leaf because an intermediate signed it, and it trusts that intermediate because a <strong>root already in your operating system's trust store</strong> signed it. The domain's CAA record is the zone owner's statement about which CAs were allowed to issue in the first place.",
      layers: [ {n:6,w:"primary"}, {n:5,w:"secondary"} ],
      pos: 38,
      bind: function () {
        var s = traceSection("tls");
        if (!s) return [];
        var rows = [
          ["Protocol", fact(s.version, "measured")],
          ["Cipher", fact(s.cipher, "measured")],
          ["ALPN", fact(s.alpn, "measured")],
          ["Handshake", fact(s.handshake_ms + " ms", "measured")],
          ["Trusted via", fact(s.trust_root, "measured")],
          ["CAA", fact(s.caa_match === true ? "issuer authorised" :
                       s.caa_match === false ? "issuer NOT listed" : "no comparable record",
                       "measured")]
        ];
        (s.chain || []).forEach(function (c, i) {
          rows.push(["Cert " + i, fact(c.subject_cn + " ← " + c.issuer_cn +
                                       " (" + c.days_left + " days left)", "measured")]);
        });
        return rows;
      },
      testYourself: function () {
        return "openssl s_client -connect " + host() + ":443 -servername " + host() + " -showcerts\n" +
               "curl -sS --tlsv1.3 -o /dev/null -w '%{ssl_verify_result}\\n' https://" + host() + "/";
      },
      whatBreaks: [
        "Expired certificate — the single most common outage with a fixed, known date.",
        "Missing intermediate: works in your browser (which caches intermediates) and fails in curl and on mobile.",
        "Hostname mismatch — the certificate is valid but not for the name you asked for.",
        "Clock skew on the client makes a perfectly good certificate look not-yet-valid."
      ]
    },
    {
      key: "request",
      phase: "Asking for the page",
      title: "HTTP Request Sent",
      simple: "Your browser sends a structured request: which page it wants, plus context like your browser type and any login cookies.",
      technical: "Sent over the now-established (and, if HTTPS, encrypted) TCP stream. HTTP/1.1 sends plain text and can only work on one request at a time per connection. HTTP/2 frames everything in binary and multiplexes many requests over one connection, so a page's stylesheet, script, and images share the connection you already paid the handshake for. HTTP/3 does the same over QUIC and UDP, which removes TCP's head-of-line blocking. Which one you get was decided back in the TLS handshake by ALPN.",
      layers: [ {n:7,w:"primary"} ],
      pos: 45,
      bind: function () {
        var s = traceSection("http");
        if (!s) return [];
        return [["Negotiated protocol", fact((s.final || {}).protocol, "measured")],
                ["Requested URL", fact((s.final || {}).url, "measured")]];
      },
      testYourself: function () {
        return "curl -sSv --http2 https://" + host() + "/ -o /dev/null 2>&1 | grep -i 'ALPN\\|HTTP/'";
      },
      whatBreaks: [
        "A request header too large for the server's limit returns 431 or a bare connection reset.",
        "A missing or wrong Host header on a shared IP reaches the wrong site entirely.",
        "Cookies not sent because of SameSite or a domain mismatch — you look logged out for no visible reason."
      ]
    },
    {
      key: "redirects",
      phase: "Being sent elsewhere",
      title: "Redirects",
      simple: "The server may answer 'not here, go there instead' — and your browser starts over at the new address.",
      technical: "Each redirect costs a full round trip, and often a fresh DNS lookup, TCP handshake, and TLS handshake if the new location is on a different host. The common chains are worth recognising: <code>http://</code> → <code>https://</code> (an upgrade, but the first hop already travelled in the clear — which is exactly what HSTS preloading exists to prevent), apex → <code>www</code> or the reverse, and locale or region redirects. <strong>301</strong> is permanent and gets cached by browsers, sometimes stubbornly; <strong>302</strong> and <strong>307</strong> are temporary; <strong>308</strong> is a permanent redirect that preserves the method and body. A chain of three redirects before the real page is three round trips of latency every visitor pays.",
      layers: [ {n:7,w:"primary"} ],
      pos: 50,
      bind: function () {
        var s = traceSection("http");
        if (!s) return [];
        var rows = (s.hops || []).map(function (h, i) {
          return ["Hop " + (i + 1) + " · " + h.status,
                  fact(h.url + " → " + h.location, "measured")];
        });
        if (!rows.length) rows.push(["Redirects", fact("none — served directly", "measured")]);
        return rows;
      },
      testYourself: function () {
        return "curl -sSIL http://" + host() + "/ | grep -i '^HTTP/\\|^location:'";
      },
      whatBreaks: [
        "A redirect loop: A points to B and B points back to A. The browser gives up after ~20 hops.",
        "A cached 301 to a wrong destination is close to unfixable for users who already have it.",
        "Redirecting to http:// from https:// downgrades the connection and usually breaks mixed-content rules."
      ]
    },
    {
      key: "edge",
      phase: "Arriving at the edge",
      title: "Request Reaches Your Infrastructure",
      simple: "The request lands on infrastructure your team controls — often a CDN or load balancer — before it ever reaches application code.",
      technical: "A CDN edge node may serve a cached response immediately (cache HIT — the journey effectively ends here). Otherwise: an <strong>L4 load balancer</strong> routes purely by IP:port with no visibility into request content, or an <strong>L7 load balancer / ingress controller</strong> reads the Host header and URL path to pick the right backend service — e.g. /api/* to one service, everything else to another. A WAF or rate limiter may inspect and reject the request before your app ever sees it. Once past the load balancer, the request typically moves into a private subnet: this is where the CIDR block a platform team provisions actually gets used.",
      layers: [ {n:7,w:"primary"}, {n:4,w:"primary"}, {n:3,w:"secondary"} ],
      pos: 58,
      bind: function () {
        var s = traceSection("http");
        if (!s) return [];
        var cache = s.cache || {};
        return [
          ["CDN", fact(s.cdn || "none detected", "measured")],
          ["Cache state", fact(cache.state, "measured")],
          ["Age", fact(cache.age != null ? cache.age + "s" : null, "measured")],
          ["Cache header", fact(cache.header, "measured")]
        ];
      },
      testYourself: function () {
        return "curl -sSI https://" + host() + "/ | grep -i 'server\\|cf-\\|x-cache\\|age\\|via'";
      },
      whatBreaks: [
        "502 Bad Gateway — the load balancer reached your app and got nonsense back. The LB is fine; the app is not.",
        "503 — no healthy backends in the target group. Check the health-check path before the app logs.",
        "A cache key that ignores a header serves one user's content to another. Rare, severe, and always a Vary mistake.",
        "A WAF rule rejects legitimate traffic and never reaches your logs at all."
      ]
    },
    {
      key: "server",
      phase: "Doing the work",
      title: "Server-Side Processing",
      simple: "Your application code runs: checking who you are, fetching data, applying business logic, and preparing a response.",
      technical: "Middleware runs (auth, logging, rate limiting) → router matches the path to a handler → handler queries a database or cache (Redis/Memcached) → business logic executes → response body is assembled (server-rendered HTML, or a JSON payload for a client-rendered app). This step is pure application logic — it's what happens after Layer 7 delivers the request, not a layer itself.",
      layers: [],
      pos: 68,
      bind: function () {
        var s = traceSection("http");
        if (!s) return [];
        var ttfb = (s.final || {}).ttfb_ms;
        return [["Time to first byte", fact(ttfb != null ? ttfb + " ms" : null, "measured")],
                ["Note", fact("TTFB includes network time — it is an upper bound on server time, not a measurement of it", "illustrative")]];
      },
      testYourself: function () {
        return "curl -sS -o /dev/null -w 'connect %{time_connect}s  ttfb %{time_starttransfer}s  total %{time_total}s\\n' https://" + host() + "/";
      },
      whatBreaks: [
        "500 — your code threw. The stack trace is in your logs, not in the response.",
        "A slow database query dominates TTFB while every network layer below is healthy.",
        "Connection-pool exhaustion: fast under light load, cliff-edge failure under real load."
      ]
    },
    {
      key: "response",
      phase: "Sending the answer",
      title: "HTTP Response Sent Back",
      simple: "The server sends back a status code (did it work?), some headers (metadata), and the actual content.",
      technical: "Travels back over the same TCP/TLS connection that's still open, avoiding a fresh handshake. The status code is the first thing worth reading — it tells you which of five broad outcomes happened before you even look at the body. Three header families decide what happens next: <strong>caching</strong> (Cache-Control, ETag, Age, Vary) determines whether the next visit needs the network at all; <strong>compression</strong> (Content-Encoding) is why a 61 KB page arrives as 14 KB; and the <strong>security headers</strong> (HSTS, CSP, X-Content-Type-Options, cookie flags) decide what the browser will allow the page to do. That last group is worth grading, because everything in it is opt-in and silently absent by default.",
      layers: [ {n:7,w:"primary"} ],
      pos: 76,
      bind: function () {
        var s = traceSection("http");
        if (!s) return [];
        var f = s.final || {}, sec = s.security || {};
        return [
          ["Status", fact(f.protocol + " " + f.status, "measured")],
          ["Content type", fact(f.content_type, "measured")],
          ["On the wire", fact(f.wire_bytes != null ? f.wire_bytes + " bytes" : null, "measured")],
          ["Decoded", fact(f.decoded_bytes != null ? f.decoded_bytes + " bytes" : null, "measured")],
          ["Compression", fact(f.encoding ? f.encoding + " " + f.ratio + ":1" : "none", "measured")],
          ["Security grade", fact(sec.grade, "measured")],
          ["Missing headers", fact((sec.missing || []).join(", ") || "none", "measured")],
          ["Cookies", fact((sec.cookies || []).map(function (c) {
            return c.name + (c.secure ? " +Secure" : " -Secure") +
                   (c.httponly ? " +HttpOnly" : "") +
                   (c.samesite ? " SameSite=" + c.samesite : " -SameSite");
          }).join("; ") || "none", "measured")]
        ];
      },
      testYourself: function () {
        return "curl -sSI https://" + host() + "/\n" +
               "curl -sS -H 'Accept-Encoding: gzip' -o /dev/null -w '%{size_download} bytes\\n' https://" + host() + "/";
      },
      whatBreaks: [
        "404 for an asset that exists — almost always a path or base-URL mistake, not a server fault.",
        "304 Not Modified when you expected fresh content: your ETag or Last-Modified logic is answering for you.",
        "Missing HSTS means the first plaintext hop stays exploitable forever.",
        "A cookie without Secure travels in the clear on any accidental http:// request."
      ]
    },
    {
      key: "render",
      phase: "Turning bytes into pixels",
      title: "Browser Parses & Renders",
      simple: "Your browser reads the HTML and progressively builds the page you see, fetching extra files like images and stylesheets along the way.",
      technical: "HTML is parsed incrementally into the DOM. CSS is parsed into the CSSOM (render-blocking by default). Synchronous script tags block HTML parsing unless marked async/defer. DOM + CSSOM merge into a Render Tree → Layout computes exact geometry → Paint fills in pixels → Compositing assembles layers, often GPU-accelerated, into the final frame. Referenced images, fonts, and scripts trigger their own requests — over HTTP/2 or HTTP/3 these are typically multiplexed over the connection that's already open, reusing the same TCP/TLS session instead of repeating the handshake steps for every single file.",
      layers: [],
      pos: 86,
      bind: function () { return []; },
      testYourself: function () {
        return "# DevTools → Performance: record a reload and read the flame chart\n" +
               "# DevTools → Network: sort by 'Connection ID' to see reuse";
      },
      whatBreaks: [
        "A render-blocking stylesheet in the head delays first paint for every visitor.",
        "A synchronous third-party script stalls parsing until that third party responds.",
        "A missing font falls back mid-load and the whole layout shifts."
      ]
    },
    {
      key: "interactive",
      phase: "Ready for you",
      title: "Page Becomes Interactive",
      simple: "JavaScript finishes running and the page starts responding to your clicks and scrolls.",
      technical: "Deferred and async scripts finish executing, event listeners attach, and the browser fires events like DOMContentLoaded and load. Frameworks may then hydrate server-rendered markup into a fully interactive client-side app. This is what Core Web Vitals like Time to Interactive (TTI) and Largest Contentful Paint (LCP) are measuring.",
      layers: [],
      pos: 94,
      bind: function () { return []; },
      testYourself: function () {
        return "# DevTools → Lighthouse: LCP, TTI, CLS for this page";
      },
      whatBreaks: [
        "The page looks finished but does not respond — hydration has not completed.",
        "A JavaScript exception during startup leaves half the listeners unattached and no visible error."
      ]
    },
    {
      key: "teardown",
      phase: "Afterwards",
      title: "Teardown & what's cached now",
      simple: "The connection closes, but your machine keeps enough of what it learned that the next visit is much faster.",
      technical: "Three caches were populated on the way through, and each one removes a step from the next visit. The <strong>DNS answer</strong> is held for its TTL, so the whole resolution step is skipped. The <strong>TLS session ticket</strong> lets the next handshake resume in a single round trip instead of a full negotiation. The <strong>HTTP cache</strong> may let the browser skip the request entirely, or send a conditional request with If-None-Match and get a 304 with no body at all. Meanwhile the connection itself is usually kept alive briefly rather than closed, so an immediate second request reuses it outright. This is why the second load of a site feels instant and why a cold measurement is the only honest one.",
      code: "First visit:\n  DNS 41 ms + TCP 12 ms + TLS 38 ms + request 88 ms  =  179 ms\n\nSecond visit, within the DNS TTL:\n  DNS   0 ms  (cached for the remaining TTL)\n  TCP  12 ms\n  TLS   9 ms  (resumed from a session ticket)\n  GET  ->  304 Not Modified, no body\n           =  ~21 ms",
      layers: [ {n:5,w:"primary"}, {n:7,w:"secondary"} ],
      pos: 98,
      bind: function () {
        var dns = traceSection("dns");
        var tls = traceSection("tls");
        var http = traceSection("http");
        var rows = [];
        if (dns) rows.push(["DNS cached for", fact(((dns.records.A || [])[0] || {}).ttl + "s", "measured")]);
        if (tls) rows.push(["Session resumption", fact((tls.resumption || {}).tested ?
          ((tls.resumption.resumed ? "resumed in " + tls.resumption.handshake_ms + " ms" : "not offered")) :
          "not tested (run with --deep)", "measured")]);
        if (http) rows.push(["Cache directives", fact((http.cache || {}).directives || "none", "measured")]);
        return rows;
      },
      testYourself: function () {
        return "curl -sSI https://" + host() + "/ | grep -i 'cache-control\\|etag\\|age\\|expires'\n" +
               "# then repeat with:  -H 'If-None-Match: <the etag>'   and expect 304";
      },
      whatBreaks: [
        "Cache-Control: no-store on everything — every visit pays the full cost, forever.",
        "An immutable asset cached for a year without a content hash in its name can never be updated.",
        "Session tickets disabled means every connection pays a full handshake."
      ]
    }
  ];
```

- [ ] **Step 3: Render the new blocks**

In `renderStepBody`, after the descriptive text and before the code block, insert:

```js
    var rows = typeof step.bind === "function" ? step.bind() : [];
    if (rows.length) {
      html += '<p class="label">Measured for this request</p><div class="fact-grid">' +
        rows.map(function (r) {
          return '<div><div class="k">' + escapeHtml(r[0]) + '</div>' +
                 '<div class="v">' + renderFact(r[1]) + "</div></div>";
        }).join("") + "</div>";
    } else if (state.trace && step.key && traceWhyNot(SECTION_FOR_STEP[step.key])) {
      html += '<p class="label">Measured for this request</p><p style="color:var(--text-muted)">' +
        "not observed — " + escapeHtml(traceWhyNot(SECTION_FOR_STEP[step.key])) + "</p>";
    }
```

and after the code block, insert:

```js
    if (typeof step.testYourself === "function") {
      html += '<p class="label">Test this yourself</p><div class="copy-row">' +
        '<code class="block">' + escapeHtml(step.testYourself()) + "</code>" +
        '<button class="copy-btn" type="button" data-copy="' +
        escapeHtml(step.testYourself()) + '">Copy</button></div>';
    }
    if (step.whatBreaks && step.whatBreaks.length) {
      html += '<p class="label">What breaks here</p><ul class="breaks">' +
        step.whatBreaks.map(function (b) { return "<li>" + escapeHtml(b) + "</li>"; }).join("") +
        "</ul>";
    }
```

Add the section map and the copy handler beside the other helpers:

```js
  var SECTION_FOR_STEP = {
    local: "local", dns: "dns", address: "tcp", path: "path", tcp: "tcp",
    tls: "tls", request: "http", redirects: "http", edge: "http",
    server: "http", response: "http", teardown: "http"
  };

  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".copy-btn");
    if (!btn) return;
    navigator.clipboard.writeText(btn.dataset.copy).then(function () {
      var original = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = original; }, 1200);
    });
  });
```

- [ ] **Step 4: Verify in a browser**

1. With no trace loaded, every stage shows its text, its "Test this yourself" commands, and its "What breaks here" list, with no measured grid.
2. Drop `tests/fixtures/golden/cdn-host.json`. "Your local network" now shows the gateway MAC with a green ● badge; "Crossing the internet" shows four hops and the AS path; "Redirects" shows the 301 hop.
3. Drop `partial-unprivileged.json`. "Your local network" says `not observed — neither route nor ip is on PATH` instead of showing invented values.
4. Copy buttons put the command on the clipboard.
5. The commands name the trace's host, not `example.com`, when a trace for another host is loaded.

- [ ] **Step 5: Commit**

```bash
git add webpage-journey.html
git commit -m "feat: fifteen-stage journey with measured bindings, test commands and failure modes"
```

---

## Task 19: Findings and timing waterfall panels

**Files:**
- Modify: `webpage-journey.html`

**Interfaces:**
- Produces: `renderFindings()`, `renderWaterfall()`, both called from `adoptTrace` and no-ops when no trace is loaded.

- [ ] **Step 1: Add the styles**

Append to `<style>`:

```css
  .trace-panels { display: none; margin-bottom: 22px; }
  .trace-panels.show { display: block; }

  .findings-panel, .waterfall-panel {
    background: var(--card-bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 14px 16px; margin-bottom: 14px;
  }
  .findings-panel h3, .waterfall-panel h3 {
    font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em;
    margin: 0 0 10px; color: var(--text-muted);
  }
  .finding { display: flex; gap: 10px; align-items: baseline;
             font-size: 13px; padding: 5px 0;
             border-top: 1px solid var(--border); }
  .finding:first-of-type { border-top: none; }
  .sev {
    font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.04em; padding: 2px 6px; border-radius: 3px;
    color: #fff; flex: none; min-width: 58px; text-align: center;
  }
  .sev-critical { background: var(--critical); }
  .sev-warn     { background: var(--l4); }
  .sev-info     { background: var(--l7); }
  .finding .where { color: var(--text-muted); font-size: 11px; flex: none; }

  .waterfall-scroll { overflow-x: auto; }
  .waterfall-svg { display: block; min-width: 420px; }
  .waterfall-svg text { font-size: 11px; fill: var(--text-secondary); }
  .waterfall-svg text.total { fill: var(--text-primary); font-weight: 600; }
```

- [ ] **Step 2: Add the markup**

Immediately after the `<div class="trace-bar" id="traceBar"></div>` element, insert:

```html
  <div class="trace-panels" id="tracePanels">
    <div class="findings-panel" id="findingsPanel"></div>
    <div class="waterfall-panel" id="waterfallPanel"></div>
  </div>
```

- [ ] **Step 3: Add the renderers**

```js
  var WATERFALL_COLOURS = {
    DNS: "--l7", TCP: "--l4", TLS: "--l6", TTFB: "--l3", Download: "--l5"
  };

  function renderFindings() {
    var panel = document.getElementById("findingsPanel");
    var notes = ((state.trace && state.trace.notes) || []).slice();
    var order = { critical: 0, warn: 1, info: 2 };
    notes.sort(function (a, b) { return (order[a.severity] || 9) - (order[b.severity] || 9); });

    if (!notes.length) {
      panel.innerHTML = "<h3>Findings</h3>" +
        '<p style="font-size:13px;color:var(--good);margin:0">' +
        "Nothing worth flagging in this trace.</p>";
      return;
    }

    panel.innerHTML = "<h3>Findings (" + notes.length + ")</h3>" +
      notes.map(function (n) {
        return '<div class="finding">' +
          '<span class="sev sev-' + escapeHtml(n.severity) + '">' + escapeHtml(n.severity) + "</span>" +
          '<span class="where">' + escapeHtml(n.section) + "</span>" +
          "<span>" + escapeHtml(n.text) + "</span></div>";
      }).join("");
  }

  function renderWaterfall() {
    var panel = document.getElementById("waterfallPanel");
    var timings = (state.trace && state.trace.timings) || {};
    var rows = timings.waterfall || [];
    var total = timings.total_ms || 0;

    if (!rows.length || total <= 0) { panel.innerHTML = ""; return; }

    var rowH = 24, labelW = 90, timeW = 74, barW = 360;
    var height = rows.length * rowH + 34;
    var width = labelW + barW + timeW;

    var bars = rows.map(function (r, i) {
      var y = i * rowH + 6;
      var x = labelW + (r.start_ms / total) * barW;
      var w = Math.max(2, ((r.end_ms - r.start_ms) / total) * barW);
      var colour = "var(" + (WATERFALL_COLOURS[r.label] || "--l7") + ")";
      return '<text x="0" y="' + (y + 13) + '">' + escapeHtml(r.label) + "</text>" +
             '<rect x="' + x.toFixed(1) + '" y="' + y + '" width="' + w.toFixed(1) +
             '" height="14" rx="2" fill="' + colour + '"></rect>' +
             '<text x="' + (labelW + barW + 8) + '" y="' + (y + 13) + '">' +
             (r.end_ms - r.start_ms).toFixed(1) + " ms</text>";
    }).join("");

    panel.innerHTML = "<h3>Timing waterfall</h3>" +
      '<div class="waterfall-scroll"><svg class="waterfall-svg" width="' + width +
      '" height="' + height + '" role="img" aria-label="Timing waterfall, total ' +
      total + ' milliseconds">' + bars +
      '<text class="total" x="0" y="' + (height - 6) + '">Total ' + total + " ms</text>" +
      "</svg></div>";
  }
```

- [ ] **Step 4: Call them when a trace is adopted**

In `adoptTrace`, and in the `localStorage` restore block in the init section, after `renderTraceBar()` add:

```js
    document.getElementById("tracePanels").classList.add("show");
    renderFindings();
    renderWaterfall();
```

In the reset handler, add `document.getElementById("tracePanels").classList.remove("show");` and clear `state.trace`, plus `localStorage.removeItem(TRACE_STORAGE_KEY)`.

- [ ] **Step 5: Verify in a browser**

1. Drop `cdn-host.json`: the findings panel lists the certificate expiry as `warn` above the informational notes, and the waterfall shows five cumulative bars whose offsets increase left to right.
2. Narrow the window to 375px — the waterfall scrolls inside its own box and the page body does not scroll sideways.
3. Drop `plain-host.json`: the findings list is longer (grade F, missing headers) and ordered with criticals first.
4. Click Reset: both panels disappear and a reload does not bring the trace back.

- [ ] **Step 6: Commit**

```bash
git add webpage-journey.html
git commit -m "feat: findings list and SVG timing waterfall for imported traces"
```

---

## Task 20: Failure simulator and bidirectional layer filter

**Files:**
- Modify: `webpage-journey.html`

**Interfaces:**
- Produces: `FAILURES: Array<{key, label, layer, stopsAt, browserError, command, explain}>`, `applyFailure(key)`, `setLayerFilter(n)`.

- [ ] **Step 1: Add the styles**

Append to `<style>`:

```css
  .step-card.failed {
    border-left-color: var(--critical) !important;
    box-shadow: 0 0 0 2px var(--critical);
  }
  .step-card.unreached { opacity: 0.35; }
  .step-card.filtered-out { display: none; }

  .failure-banner {
    display: none;
    background: var(--card-bg);
    border: 1px solid var(--critical);
    border-left: 4px solid var(--critical);
    border-radius: 4px; padding: 12px 16px; margin-bottom: 18px;
    font-size: 13px; line-height: 1.55;
  }
  .failure-banner.show { display: block; }
  .failure-banner code {
    background: var(--surface-1); border: 1px solid var(--border);
    padding: 1px 5px; border-radius: 3px;
  }
  .osi-layer.dimmed { opacity: 0.18; }
  .osi-layer.failing { box-shadow: 0 0 0 2px var(--critical); opacity: 1; }
  .filter-note {
    font-size: 12px; color: var(--text-muted); margin: 8px 0 0;
  }
```

- [ ] **Step 2: Add the control and banner markup**

Inside the `.controls` bar, after the HTTPS toggle label, insert:

```html
    <div class="control-group">
      <label for="failureSelect">Break something:</label>
      <select id="failureSelect">
        <option value="">nothing — healthy request</option>
      </select>
    </div>
```

And immediately after the `.trace-panels` div, insert:

```html
  <div class="failure-banner" id="failureBanner"></div>
```

Add matching styles for `select` by appending to `<style>`:

```css
  .control-group select {
    font-family: inherit; font-size: 13px; padding: 6px 8px;
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 4px;
  }
```

- [ ] **Step 3: Add the failure model and behaviour**

```js
  var FAILURES = [
    {
      key: "cable", label: "Cable unplugged / Wi-Fi off", layer: 1, stopsAt: "local",
      browserError: "ERR_INTERNET_DISCONNECTED",
      command: "ifconfig en0 | grep status   # then: ping your gateway",
      explain: "Nothing above Layer 1 can run. Every other symptom you might chase — DNS, TLS, 500s — is downstream of a dead link, which is why checking the physical layer first is not a joke."
    },
    {
      key: "nxdomain", label: "DNS name does not exist", layer: 7, stopsAt: "dns",
      browserError: "DNS_PROBE_FINISHED_NXDOMAIN",
      command: "dig +short <host>   # empty output means no answer at all",
      explain: "The network is healthy and the name is not. No connection is ever attempted, so a firewall or certificate is not the cause no matter how it looks."
    },
    {
      key: "blocked", label: "Port 443 blocked by a firewall", layer: 4, stopsAt: "tcp",
      browserError: "ERR_CONNECTION_TIMED_OUT",
      command: "nc -vz <host> 443   # hangs, rather than saying 'refused'",
      explain: "Timed out means dropped silently; refused means something answered and declined. Those two point at completely different causes, and the distinction is the single most useful thing at Layer 4."
    },
    {
      key: "cert", label: "Certificate expired", layer: 6, stopsAt: "tls",
      browserError: "NET::ERR_CERT_DATE_INVALID",
      command: "openssl s_client -connect <host>:443 -servername <host> 2>/dev/null | openssl x509 -noout -dates",
      explain: "TCP succeeded, so the server is reachable and listening. The failure is in validation, not connectivity — and unlike most outages it had a known date in advance."
    },
    {
      key: "gateway", label: "502 from the load balancer", layer: 7, stopsAt: "edge",
      browserError: "502 Bad Gateway",
      command: "curl -sSI https://<host>/   # read the Server and Via headers",
      explain: "The load balancer is healthy enough to answer you; it is the backend behind it that returned nothing usable. Look at application logs and health checks, not at the network."
    },
    {
      key: "js", label: "JavaScript exception on load", layer: null, stopsAt: "interactive",
      browserError: "Uncaught TypeError in the console",
      command: "# DevTools → Console, then reload with 'Pause on exceptions' enabled",
      explain: "Every network layer succeeded — the page arrived intact. This one belongs to no OSI layer at all, which is exactly why reaching for a network diagnosis here wastes time."
    }
  ];

  function stepIndexByKey(key) {
    return JOURNEY.findIndex(function (s) { return s.key === key; });
  }

  function applyFailure(key) {
    var failure = FAILURES.find(function (f) { return f.key === key; }) || null;
    state.failure = failure;

    var banner = document.getElementById("failureBanner");
    cardEls.forEach(function (c) { c.classList.remove("failed", "unreached"); });
    Object.keys(osiButtons).forEach(function (n) {
      osiButtons[n].classList.remove("failing", "dimmed");
    });

    if (!failure) {
      banner.classList.remove("show");
      banner.innerHTML = "";
      return;
    }

    var stopIdx = stepIndexByKey(failure.stopsAt);
    cardEls.forEach(function (card, idx) {
      if (idx === stopIdx) card.classList.add("failed");
      else if (idx > stopIdx) card.classList.add("unreached");
    });

    if (failure.layer) {
      Object.keys(osiButtons).forEach(function (n) {
        osiButtons[n].classList.add(Number(n) === failure.layer ? "failing" : "dimmed");
      });
    }

    var layerText = failure.layer
      ? "Layer " + failure.layer + " — " +
        LAYERS.find(function (l) { return l.n === failure.layer; }).name
      : "no OSI layer — this is application code";

    banner.classList.add("show");
    banner.innerHTML =
      "<strong>" + escapeHtml(failure.label) + "</strong> · " + escapeHtml(layerText) +
      "<br>What you see: <code>" + escapeHtml(failure.browserError) + "</code>" +
      "<br>" + escapeHtml(failure.explain) +
      '<br>Isolate it with: <code>' +
      escapeHtml(failure.command.replace(/<host>/g, host())) + "</code>" +
      "<br><span style='color:var(--text-muted)'>Stages after step " +
      (stopIdx + 1) + " never run.</span>";
  }

  var failureSelect = document.getElementById("failureSelect");
  FAILURES.forEach(function (f) {
    var option = document.createElement("option");
    option.value = f.key;
    option.textContent = f.label;
    failureSelect.appendChild(option);
  });
  failureSelect.addEventListener("change", function () {
    applyFailure(failureSelect.value);
  });
```

- [ ] **Step 4: Make the OSI panel filter the journey**

Replace the OSI layer button's click handler with:

```js
    btn.addEventListener("click", function () {
      showLayerDetail(layer, true);
      setLayerFilter(state.layerFilter === layer.n ? null : layer.n);
    });
```

and add:

```js
  function setLayerFilter(n) {
    state.layerFilter = n;
    cardEls.forEach(function (card, idx) {
      var step = JOURNEY[idx];
      var matches = n === null || (step.layers || []).some(function (l) {
        return l.n === n && l.w === "primary";
      });
      card.classList.toggle("filtered-out", !matches);
    });

    Object.keys(osiButtons).forEach(function (num) {
      osiButtons[num].setAttribute("aria-pressed", Number(num) === n ? "true" : "false");
    });

    var note = document.getElementById("filterNote");
    if (n === null) {
      note.textContent = "";
    } else {
      var shown = cardEls.filter(function (c) {
        return !c.classList.contains("filtered-out");
      }).length;
      note.textContent = "Showing the " + shown + " stage(s) where L" + n +
                         " does the work. Click L" + n + " again to show all.";
    }
  }
```

Add the note element after the OSI detail div in the markup:

```html
      <p class="filter-note" id="filterNote"></p>
```

Also make `visibleIndices()` respect the filter and the HTTPS toggle together:

```js
  function visibleIndices() {
    var out = [];
    JOURNEY.forEach(function (step, idx) {
      if (step.httpsOnly && !httpsOn) return;
      if (cardEls[idx].classList.contains("filtered-out")) return;
      out.push(idx);
    });
    return out;
  }
```

- [ ] **Step 5: Make autoplay respect reduced motion**

In `stepPlay`, replace the trailing timer line with:

```js
    playIdx++;
    playTimer = setTimeout(stepPlay, REDUCED_MOTION ? 0 : 1900);
```

and in the same function replace `scrollIntoView({ behavior: "smooth", block: "center" })` with:

```js
    cardEls[idx].scrollIntoView({
      behavior: REDUCED_MOTION ? "auto" : "smooth", block: "center" });
```

- [ ] **Step 6: Verify in a browser**

1. Choose "Certificate expired": the TLS card is outlined red, every later stage dims, L6 is highlighted while the other layers fade, and the banner names `NET::ERR_CERT_DATE_INVALID` plus an `openssl` command carrying the current host.
2. Choose "JavaScript exception on load": no OSI layer is highlighted and the banner says so explicitly.
3. Choose "nothing — healthy request": all styling clears.
4. Click **L3 · Network** in the OSI panel: only "Crossing the internet" and "Choosing an address" remain visible, and the note says so. Click it again to restore.
5. With a filter active, press Go — the animation walks only the visible stages.
6. Enable "Reduce motion" in your OS accessibility settings and press Go: stages advance without smooth scrolling or timed delay.

- [ ] **Step 7: Commit**

```bash
git add webpage-journey.html
git commit -m "feat: failure-mode simulator and layer-driven journey filter"
```

---

## Task 21: Verification pass, README, and removing the predecessor

**Files:**
- Create: `README.md`
- Delete: `~/Projects/webpage_journey.py`, `~/Projects/webpage_journey_osi.py`
- Test: full suite plus the browser checklist

- [ ] **Step 1: Run the full Python suite**

Run: `.venv/bin/python -m pytest -q`
Expected: all tests pass, network tests deselected.

Run: `.venv/bin/python -m pytest -m network -q`
Expected: PASS. If offline, record that this step was skipped and why.

- [ ] **Step 2: Run three real traces and export one**

```bash
.venv/bin/python trace.py example.com
.venv/bin/python trace.py https://cloudflare.com/ --json /tmp/cf.json
.venv/bin/python trace.py does-not-exist.invalid; echo "exit=$?"
```

Expected: the first two render every panel with no traceback; the third reports the resolution failure and exits `1`. Confirm `/tmp/cf.json` contains `"redacted": true` and that no MAC address or private IP appears in it:

```bash
grep -c "redacted at export" /tmp/cf.json
grep -E "([0-9a-f]{2}:){5}" /tmp/cf.json && echo "LEAK" || echo "no MACs in export"
```

- [ ] **Step 3: Work the browser checklist**

Open `webpage-journey.html` and confirm every line:

1. Loads dark by default; the toggle flips it; the choice survives a reload.
2. `Tab` reaches every step header, the OSI layers, and every button. Focus rings are visible.
3. `↑`/`↓`/`Home`/`End` move between step headers; `Enter` expands; `Esc` collapses.
4. No step card clips its content at the bottom, in either view level.
5. At 375px wide: no horizontal page scroll; the waterfall scrolls inside its own box.
6. Layer chips are legible in both themes.
7. Dropping each of the three golden traces works, and the partial one explains what it could not see.
8. A trace with a bumped major version is refused with a clear message.
9. `?host=example.com` triggers a live lookup on load.
10. Setting `LIVE_LOOKUPS_ENABLED = false` and reloading produces a page that issues no network requests at all — verify with the DevTools Network tab — and still renders every stage plus any imported trace.

Restore `LIVE_LOOKUPS_ENABLED = true` afterwards.

- [ ] **Step 4: Write the README**

Create `README.md`:

```markdown
# Webpage Journey

Two teaching artifacts that answer the same question — what actually happens when you
load a webpage — from opposite ends.

- **`trace.py`** opens real sockets and shells out to real tools, so it can measure the
  parts a browser will never show you: the gateway MAC your frames are addressed to, the
  negotiated cipher, the certificate chain up to the root in your trust store, the
  traceroute hops and their AS numbers, the redirect chain, and the compression ratio.
- **`webpage-journey.html`** is a self-contained interactive walkthrough of the same
  journey, mapped onto the OSI model. Drop a trace document on it and every stage swaps
  its teaching example for your real measurement.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/python -m pip install rich dnspython cryptography
.venv/bin/python trace.py example.com
```

Missing optional libraries install themselves on first run (quietly inside a virtualenv,
after asking against a system Python). `--offline` disables that.

## Feeding the page

```bash
.venv/bin/python trace.py example.com --json trace.json
```

Then open `webpage-journey.html` and drop `trace.json` onto it.

Exports are redacted by default: MAC addresses, your local IP, your public IP, and
private traceroute hops are replaced with a marker the page renders as
"redacted at export". Use `--no-redact` to keep them.

## The rule these tools follow

Every field is either measured or absent. When something could not be observed, both the
script and the page say so and say why — they never fill the gap with a plausible-looking
value. The page labels every fact as **measured** (from a trace), **live** (fetched by the
page just now) or **illustrative** (a teaching example).

## Useful flags

| Flag | What it does |
|---|---|
| `--json PATH` | Export the trace document (`-` writes to stdout) |
| `--deep` | Extra probes: TLS downgrade, session resumption, 304 replay |
| `--privileged` | Allow sudo for traceroute, path MTU, and Wi-Fi detail |
| `--no-path` | Skip traceroute |
| `--no-redact` | Keep identifying detail in the export |
| `--budget N` | Total wall-clock cap in seconds (default 25) |
| `--osi` | Print the OSI reference table alone |

`--deep` sends extra requests that constitute mild active scanning. Trace only hosts you
are authorised to probe.

## Tests

```bash
.venv/bin/python -m pytest          # offline unit tests
.venv/bin/python -m pytest -m network   # opt-in, hits the real network
```

Golden trace documents live in `tests/fixtures/golden/` and double as import fixtures for
the HTML page.

## Offline / Learning Hub build

Set `LIVE_LOOKUPS_ENABLED = false` near the top of the page's script. The page then makes
no network requests at all and works from `file://`, which is what the Learning Hub's
conventions require.
```

- [ ] **Step 5: Delete the superseded scripts**

```bash
rm ~/Projects/webpage_journey.py ~/Projects/webpage_journey_osi.py
ls ~/Projects/webpage_journey*.py 2>/dev/null || echo "predecessors removed"
```

- [ ] **Step 6: Final commit**

```bash
cd /Users/razvanbalsan/Projects/webpage-journey
git add README.md
git commit -m "docs: README covering usage, the trace contract, and the offline build"
git log --oneline | head -25
```

Expected: a commit per task, in order.

---

## Plan Self-Review

Run after completing the plan, before execution.

**Spec coverage.** Every spec section maps to a task: file layout and trace contract → Tasks 1, 2, 15; three data states → Tasks 2, 17; capability detection and auto-install → Task 3; the six collectors → Tasks 5–10; probe etiquette and the execution DAG → Task 13; CLI and redaction → Tasks 11, 13; terminal rendering, findings, waterfall, OSI finale, troubleshooting ladder → Tasks 12, 14; HTML data layer → Task 17; the fifteen stages → Task 18; UI, contrast, keyboard, theme → Task 16; trace-only panels → Task 19; failure simulator and layer filter → Task 20; error handling and degradation → Tasks 11, 13, 17; the fourteen recorded defects → Tasks 5–8 (Python 3–6), 13 (Python 7), 14 (Python 1), 7 (Python 2), 16 (HTML 1, 2, 4, 5, 6), 17 (HTML 7), 18 (HTML 3); testing → every task plus Task 15.

**Two deliberate deviations from the spec's layout**, both flagged where they occur: `wj/context.py` holds the run `Context` (the spec did not name a home for it), and orchestration lives in `wj/run.py` rather than `trace.py` because Python's standard library already owns the module name `trace`.

**Known follow-ups deferred inside the plan**, none of which block a working system: `--deep` is wired through the CLI and the schema (`resumption.tested`, `legacy_versions_accepted`, `conditional.tested` all carry honest `false` values) but its three probes are not implemented in Tasks 7 and 8; `--privileged` and `--geo-hops` likewise reach the context and are read by no collector yet; `path.path_mtu` is always `null`; and HTTP/2 is detected and reported but every request is sent over HTTP/1.1, since `h2` is declared as a capability rather than used as a transport. Each is an additive change behind an existing flag. **Raise these with the user before execution** so they can decide whether to fold them in now or ship the working system first.
