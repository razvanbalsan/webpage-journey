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
