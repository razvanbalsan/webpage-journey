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
