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
