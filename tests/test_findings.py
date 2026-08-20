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


def test_notes_when_host_advertises_a_protocol_we_did_not_negotiate():
    trace = base_trace()
    trace["dns"] = {"observed": True, "alpn_advertised": ["h2", "h3"]}
    trace["tls"] = {"observed": True, "alpn": "http/1.1",
                    "chain": [{"days_left": 90}], "legacy_versions_accepted": []}
    findings.analyse(trace)
    joined = " ".join(texts(trace))
    assert "advertises h2, h3" in joined
    assert "negotiated http/1.1" in joined
    note = next(n for n in trace["notes"] if "advertises" in n["text"])
    assert note["severity"] == "info"
    assert note["section"] == "tls"


def test_no_note_when_the_host_advertises_nothing_beyond_what_we_used():
    trace = base_trace()
    trace["dns"] = {"observed": True, "alpn_advertised": ["http/1.1"]}
    trace["tls"] = {"observed": True, "alpn": "http/1.1",
                    "chain": [{"days_left": 90}], "legacy_versions_accepted": []}
    findings.analyse(trace)
    assert not any("advertises" in t for t in texts(trace))


def test_flags_a_plaintext_redirect_hop():
    trace = base_trace()
    trace["http"] = {"observed": True,
                     "hops": [{"url": "http://example.com/", "status": 301,
                               "location": "https://example.com/"}],
                     "final": {"status": 200},
                     "security": {"grade": "A", "missing": [], "cookies": []}}
    findings.analyse(trace)
    assert any("plaintext" in t for t in texts(trace))


def test_flags_a_failed_decompression_instead_of_reporting_a_fake_ratio():
    # I4: a failed inflate leaves decoded_bytes/ratio absent (wj/collect/http.py)
    # rather than presenting wire==decoded as a measured ~1.0 compression ratio.
    trace = base_trace()
    trace["http"] = {"observed": True, "hops": [],
                     "final": {"status": 200, "encoding": "gzip",
                               "wire_bytes": 15, "decoded_bytes": None, "ratio": None},
                     "security": {"grade": "A", "missing": [], "cookies": []}}
    findings.analyse(trace)
    joined = " ".join(texts(trace))
    assert "gzip" in joined
    assert "could not decompress" in joined


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


def test_a_clean_trace_only_gets_the_alpn_gap_note():
    # A fully well-configured, HTTP/3-capable host trips no warning or critical
    # note. It still earns the informational ALPN-gap note, because this tool
    # only ever speaks HTTP/1.1 (see ALPN_PROTOCOLS in wj/collect/tls.py) while
    # the host advertises more — that is real, honest information, not a defect.
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h3", "h2"]}
    trace["tls"] = {"observed": True, "alpn": "http/1.1", "chain": [{"days_left": 80}],
                    "legacy_versions_accepted": []}
    trace["http"] = {"observed": True, "hops": [], "final": {"status": 200},
                     "security": {"grade": "A", "missing": [],
                                  "cookies": [{"name": "s", "secure": True,
                                               "httponly": True, "samesite": "Lax"}]}}
    findings.analyse(trace)
    assert trace["notes"] == [
        {"severity": "info", "section": "tls",
         "text": "this host advertises h3, h2, but this tool only offers HTTP/1.1 and negotiated http/1.1"},
    ]


def test_alpn_gap_note_does_not_claim_a_negotiation_that_did_not_happen():
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h2"]}
    trace["tls"] = {"observed": True, "alpn": None, "chain": [{"days_left": 80}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    joined = " ".join(n["text"] for n in trace["notes"])
    assert "negotiated http/1.1" not in joined
    assert "did not negotiate" in joined


def test_analyse_is_idempotent_not_cumulative():
    trace = base_trace()
    trace["tls"] = {"observed": True, "chain": [{"days_left": 9, "subject_cn": "example.com"}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    findings.analyse(trace)
    assert len(trace["notes"]) == 1


def test_unobserved_sections_are_skipped_silently():
    trace = base_trace()
    findings.analyse(trace)
    assert trace["notes"] == []
