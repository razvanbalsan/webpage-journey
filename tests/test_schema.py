import pytest

from wj import schema


def make_trace():
    return schema.new_trace(
        target={"input": "example.com", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.1.0",
        generated_at="2026-08-20T09:31:02Z",
        capabilities={"privileged": False, "tools": [], "libs": {}},
        redacted=True,
    )


def test_new_trace_carries_version_and_target():
    t = make_trace()
    assert t["schema"] == "webpage-journey-trace/1"
    assert t["tool"] == {"name": "trace.py", "version": "2.1.0"}
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
