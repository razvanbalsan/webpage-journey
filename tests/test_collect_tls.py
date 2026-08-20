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


# C3: bare CA codes are what real certificates actually carry as their issuer
# Common Name — cryptography's common_name() only falls back to Organization
# when the CN is entirely absent, and CAs almost always set both, so the CN
# alone is a bare code with no domain-like token to compare. Verified live
# against github.com, letsencrypt.org and google.com (2026-08-20): every one
# of these codes is a real issuer CN observed on the wire.
@pytest.mark.parametrize("cn", ["R3", "R10", "R11", "E1", "E5", "YE2"])
def test_caa_allows_a_bare_lets_encrypt_code_is_unknown_not_false(cn):
    caa = [{"data": '0 issue "letsencrypt.org"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, cn, "Let's Encrypt") is None


@pytest.mark.parametrize("cn", ["WR2", "WE1", "GTS CA 1C3", "WE2"])
def test_caa_allows_a_bare_google_trust_services_code_is_unknown_not_false(cn):
    # Google's own CAA domain is "pki.goog" -- the brand ("goog") is the SECOND
    # label, not the first. A first-label-only brand check still returns False
    # here; this is what verified google.com's own certificate against False.
    caa = [{"data": '0 issue "pki.goog"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, cn, "Google Trust Services") is None


def test_caa_allows_a_bare_code_with_no_organization_at_all_is_unknown():
    caa = [{"data": '0 issue "letsencrypt.org"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "R11", None) is None


def test_caa_allows_a_genuine_mismatch_still_returns_false():
    # The False branch must stay reachable: a real DigiCert-issued certificate
    # against a CAA set that authorises only Let's Encrypt is a real mismatch.
    caa = [{"data": '0 issue "letsencrypt.org"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "DigiCert SHA2 Secure Server CA",
                                  "DigiCert Inc") is False


def test_summarise_cert_reads_issuer_organization():
    info = tls_collect.summarise_cert(leaf_der())
    # The fixture leaf's issuer CN is present, so issuer_org may be absent —
    # this asserts the field exists on the returned dict at all.
    assert "issuer_org" in info


def test_grade_expiry_thresholds():
    assert tls_collect.grade_expiry(90) is None
    severity, message = tls_collect.grade_expiry(9)
    assert severity == "warn" and "9" in message
    severity, message = tls_collect.grade_expiry(-1)
    assert severity == "critical"
