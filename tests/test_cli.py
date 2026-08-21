"""Tests for the argument parser and entry point in wj/cli.py.

These exist to catch the prog="trace.py" bug and its return: an installed
`webpage-journey` console script must not tell the user to run a command
that doesn't exist on their system, in --help or in the no-target message.
"""

import sys

from rich.console import Console

from wj import run
from wj.cli import build_parser, main


def test_prog_is_not_hardcoded_to_trace_py():
    # The bug this guards against: prog="trace.py" was hardcoded, so an
    # installed `webpage-journey` invocation still showed "trace.py" in
    # --help and in the no-target message.
    assert build_parser().prog != "trace.py"


def test_prog_follows_the_clone_invocation(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["trace.py", "example.com"])
    assert build_parser().prog == "trace.py"


def test_prog_follows_the_installed_invocation(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/webpage-journey"])
    assert build_parser().prog == "webpage-journey"

    monkeypatch.setattr(sys, "argv", ["webpage-journey", "example.com"])
    assert build_parser().prog == "webpage-journey"


def test_help_documents_a_plain_trace_example():
    help_text = build_parser().format_help()
    assert "%(prog)s example.com" not in help_text  # substitution must happen
    assert "example.com" in help_text


def test_help_documents_the_json_export_and_page_round_trip():
    help_text = build_parser().format_help()
    assert "--json trace.json" in help_text
    assert "webpage-journey.html" in help_text


def test_help_documents_no_tls():
    help_text = build_parser().format_help()
    assert "--no-tls" in help_text


def test_help_documents_osi_alone():
    help_text = build_parser().format_help()
    assert "--osi" in help_text
    assert "OSI reference table" in help_text


def test_help_documents_stdout_piping():
    help_text = build_parser().format_help()
    assert "--json -" in help_text
    assert "stdout" in help_text


def test_help_documents_all_three_exit_codes():
    help_text = build_parser().format_help()
    assert "0  trace completed" in help_text
    assert "1  target unresolvable" in help_text
    assert "2  usage error" in help_text
    # And they must actually match the constants they document.
    assert run.EXIT_OK == 0
    assert run.EXIT_UNRESOLVABLE == 1
    assert run.EXIT_USAGE == 2


def test_help_documents_redaction_default():
    help_text = build_parser().format_help()
    assert "redacted by default" in help_text
    assert "--no-redact" in help_text


def test_help_documents_protocol_negotiation():
    help_text = build_parser().format_help()
    # Specific enough to actually fail if the epilog regresses back to the
    # old "speaks only HTTP/1.1" claim -- that older text also contained the
    # substrings "HTTP/1.1" and "ALPN" this test used to check for, so it
    # could never have caught its own removal.
    assert "offers h2 over ALPN" in help_text
    assert "falls back to HTTP/1.1" in help_text
    assert "speaks only HTTP/1.1" not in help_text
    # A re-review caught that this test's assertions all locked the FIRST
    # round's wording, which still overclaimed that every trace measures
    # negotiation.chosen -- untrue for a --no-tls run or a handshake that
    # completes without an ALPN selection (wj/collect/http.py only fills it
    # `if alpn`). Reverting just the qualifying sentence below, while
    # leaving the assertions above intact, would have passed unnoticed.
    assert "--no-tls run" in help_text
    assert "leaves it unmeasured" in help_text
    assert "every trace reports which protocol was used" not in help_text


def test_help_keeps_the_authorisation_line():
    help_text = build_parser().format_help()
    assert "Trace only hosts you are authorised to probe." in help_text


def test_help_fits_an_80_column_terminal():
    help_text = build_parser().format_help()
    # Usage line wrapping is argparse's own business; check the body we wrote.
    epilog_start = help_text.index("What it measures:")
    body = help_text[epilog_start:]
    for line in body.splitlines():
        assert len(line) <= 80, f"line exceeds 80 columns: {line!r}"


def test_no_target_exits_usage_and_does_not_hardcode_a_program_name(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["webpage-journey"])
    exit_code = main([])
    assert exit_code == run.EXIT_USAGE

    out = capsys.readouterr().out
    assert "trace.py" not in out
    assert "webpage-journey example.com" in out


def test_no_target_message_follows_clone_invocation(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["trace.py"])
    exit_code = main([])
    assert exit_code == run.EXIT_USAGE

    out = capsys.readouterr().out
    assert "trace.py example.com" in out


def test_bad_target_is_a_usage_error():
    # A target with no parseable hostname at all is a usage error, not a crash.
    exit_code = main(["http://"])
    assert exit_code == run.EXIT_USAGE
