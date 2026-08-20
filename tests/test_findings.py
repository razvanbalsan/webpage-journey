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
