from wj import findings, schema


def base_trace():
    trace = schema.new_trace(
        target={"input": "example.com", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.1.0", generated_at="2026-08-20T00:00:00Z",
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


def test_no_alpn_gap_note_when_we_offered_and_used_what_the_host_advertises():
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h2"]}
    trace["negotiation"] = {"observed": True, "advertised": ["h2"],
                            "offered": ["h2", "http/1.1"], "unavailable": [],
                            "chosen": "h2", "attempted": []}
    trace["tls"] = {"observed": True, "alpn": "h2", "chain": [{"days_left": 80}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    joined = " ".join(n["text"] for n in trace["notes"])
    assert "only offers HTTP/1.1" not in joined
    assert "advertises h2" not in joined


def test_alpn_gap_note_names_the_missing_library_when_that_is_the_reason():
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h2"]}
    trace["negotiation"] = {"observed": True, "advertised": ["h2"],
                            "offered": ["http/1.1"], "unavailable": ["h2"],
                            "chosen": "http/1.1", "attempted": []}
    trace["tls"] = {"observed": True, "alpn": "http/1.1", "chain": [{"days_left": 80}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    joined = " ".join(n["text"] for n in trace["notes"])
    assert "h2" in joined
    assert "not installed" in joined or "cannot speak" in joined


def test_alpn_gap_note_covers_a_protocol_this_build_never_offers():
    # h3 is advertised by much of the web and is Phase 2 work. Until then the
    # gap is real and should be stated, not silently ignored.
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h3", "h2"]}
    trace["negotiation"] = {"observed": True, "advertised": ["h3", "h2"],
                            "offered": ["h2", "http/1.1"], "unavailable": [],
                            "chosen": "h2", "attempted": []}
    trace["tls"] = {"observed": True, "alpn": "h2", "chain": [{"days_left": 80}],
                    "legacy_versions_accepted": []}
    findings.analyse(trace)
    joined = " ".join(n["text"] for n in trace["notes"])
    assert "h3" in joined
    assert "h2" not in joined.split("h3")[0]   # h2 is not listed as a gap


def test_alpn_gap_note_omits_the_used_clause_when_chosen_is_unmeasured():
    # chosen is None whenever the handshake never reported a negotiated
    # protocol -- a plain http:// run, or any run where TLS was not observed.
    # The note must not guess what was used just because a gap exists.
    trace = base_trace()
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "records": {"A": [{"data": "1.2.3.4", "ttl": 300}],
                                "AAAA": [{"data": "::1", "ttl": 300}]},
                    "alpn_advertised": ["h3", "h2"]}
    trace["negotiation"] = {"observed": True, "advertised": ["h3", "h2"],
                            "offered": ["h2", "http/1.1"], "unavailable": [],
                            "chosen": None, "attempted": []}
    findings.analyse(trace)
    joined = " ".join(n["text"] for n in trace["notes"])
    assert "h3" in joined
    assert "this trace used" not in joined


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
