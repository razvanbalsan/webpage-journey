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


@pytest.mark.parametrize("cn", ["WR2", "WE1", "GTS CA 1C3", "WE2"])
def test_caa_allows_a_bare_google_trust_services_code_with_no_org_is_unknown(cn):
    # Same codes as above but with NO Organization attached at all -- this is
    # the shape a re-review caught: "GTS CA 1C3" alone contains the 3-letter
    # run "gts", which used to satisfy the old comparability guard and fall
    # through the brand check (no label of "pki.goog" appears in "gtsca1c3")
    # to a spurious False. Multi-token bare codes made only of short,
    # code-like tokens must be judged incomparable regardless of Organization.
    caa = [{"data": '0 issue "pki.goog"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, cn, None) is None


def test_caa_allows_a_bare_code_with_no_organization_at_all_is_unknown():
    caa = [{"data": '0 issue "letsencrypt.org"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "R11", None) is None


def test_caa_allows_a_genuine_mismatch_still_returns_false():
    # The False branch must stay reachable: a real DigiCert-issued certificate
    # against a CAA set that authorises only Let's Encrypt is a real mismatch.
    caa = [{"data": '0 issue "letsencrypt.org"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "DigiCert SHA2 Secure Server CA",
                                  "DigiCert Inc") is False


@pytest.mark.parametrize("caa_domain,issuer_cn,issuer_org", [
    # Both fail SAFE today (None, not a false accusation) because the brand
    # check has no minimum label length -- "it" matches inside "...Limited",
    # "de" matches inside "IdenTrust". A minimum length of 3 closes both
    # while still keeping "goog" (4 chars). Kept here as parametrized cases so
    # the False branch stays demonstrably alive for a genuine mismatch against
    # a real two-letter-ccTLD CAA domain.
    ("actalis.it", "Sectigo RSA Domain Validation Secure Server CA", "Sectigo Limited"),
    ("telesec.de", "IdenTrust Commercial Root CA 1", "IdenTrust"),
])
def test_caa_allows_does_not_brand_match_on_a_bare_two_letter_cctld(caa_domain, issuer_cn, issuer_org):
    caa = [{"data": f'0 issue "{caa_domain}"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, issuer_cn, issuer_org) is False


def test_caa_allows_strips_rfc_8659_parameters_before_comparing():
    # RFC 8659 §4.2 allows semicolon-separated parameters after the issuer
    # domain -- "pki.goog; cansignhttpexchanges=yes" is real, live CAA data
    # (verified against cloudflare.com on 2026-08-20). Comparing the whole
    # quoted string, parameters included, normalises to noise that can never
    # brand-match -- a real certificate then reads as a misissuance warning.
    caa = [{"data": '0 issue "pki.goog; cansignhttpexchanges=yes"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "WE1", "Google Trust Services") is None

    # A genuine mismatch must still be caught with parameters present.
    assert tls_collect.caa_allows(caa, "DigiCert SHA2 Secure Server CA",
                                  "DigiCert Inc") is False


def test_caa_allows_strips_accounturi_and_validationmethods_parameters():
    # accounturi= (ACME account pinning, common for Let's Encrypt) and
    # validationmethods= are equally common in the wild -- not a corner case.
    caa = [{"data": '0 issue "letsencrypt.org; accounturi=https://acme-v02.'
                    'api.letsencrypt.org/acme/acct/12345678; '
                    'validationmethods=http-01"', "ttl": 300}]
    assert tls_collect.caa_allows(caa, "R11", "Let's Encrypt") is None


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
