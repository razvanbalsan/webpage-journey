from wj import schema


def full_trace():
    trace = schema.new_trace(
        target={"input": "example.com", "host": "example.com",
                "scheme": "https", "port": 443, "path": "/dashboard"},
        tool_version="2.1.0", generated_at="2026-08-20T00:00:00Z",
        capabilities={}, redacted=False)
    trace["local"] = {"observed": True, "interface": "en0", "link": "active",
                      "mtu": 1500, "local_ip": "192.168.1.23",
                      "local_mac": "aa:bb:cc:dd:ee:ff", "gateway_ip": "192.168.1.1",
                      "gateway_mac": "11:22:33:44:55:66", "public_ip": "81.180.20.7",
                      "nat": True, "dhcp": {}}
    trace["dns"] = {"observed": True, "dnssec": "secure",
                    "resolver": {"servers": ["1.1.1.1"], "source": "scutil"},
                    "records": {"A": [{"data": "93.184.216.34", "ttl": 300}], "AAAA": []},
                    "alpn_advertised": ["h2"], "timing_ms": {"cold": 41.2, "warm": 1.1}}
    trace["tcp"] = {"observed": True, "winner_family": "ipv4",
                    "chosen": {"ip": "93.184.216.34", "family": "ipv4", "port": 443},
                    "local": {"ip": "192.168.1.23", "port": 54213},
                    "kernel": {"rtt_ms": 12.4, "mss": 1460, "retransmits": 0,
                               "source": "TCP_INFO"}}
    trace["tls"] = {"observed": True, "version": "TLSv1.3", "alpn": "h2",
                    "cipher": "TLS_AES_128_GCM_SHA256", "handshake_ms": 38.2,
                    "chain": [{"subject_cn": "example.com", "issuer_cn": "R3"}],
                    "trust_root": "ISRG Root X1", "resumption": {"tested": False}}
    trace["http"] = {"observed": True, "hops": [],
                     "final": {"url": "https://example.com/dashboard", "status": 200,
                               "protocol": "HTTP/1.1", "encoding": "gzip", "ratio": 4.4,
                               "wire_bytes": 14000, "decoded_bytes": 61000,
                               "content_type": "text/html"}}
    trace["path"] = {"observed": True, "hops": [{"ttl": 1, "ip": "192.168.1.1"}],
                     "asn_path": [8708, 13335], "path_mtu": None}
    return trace


def test_every_layer_is_present():
    osi = schema.build_osi(full_trace())
    assert set(osi) == {"l1", "l2", "l3", "l4", "l5", "l6", "l7"}


def test_layer_two_names_the_gateway_mac():
    osi = schema.build_osi(full_trace())
    assert osi["l2"]["observed"] is True
    joined = " ".join(osi["l2"]["facts"])
    assert "11:22:33:44:55:66" in joined
    assert "aa:bb:cc:dd:ee:ff" in joined


def test_layer_three_reports_nat_and_the_as_path():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l3"]["facts"])
    assert "NAT" in joined
    assert "AS8708" in joined and "AS13335" in joined


def test_layer_four_reports_ports_rtt_and_mss():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l4"]["facts"])
    assert ":54213" in joined and ":443" in joined
    assert "12.4" in joined
    assert "1460" in joined


def test_layer_six_reports_tls_and_compression():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l6"]["facts"])
    assert "TLSv1.3" in joined
    assert "gzip" in joined


def test_layer_seven_reports_the_request_and_dns():
    osi = schema.build_osi(full_trace())
    joined = " ".join(osi["l7"]["facts"])
    assert "200" in joined
    assert "93.184.216.34" in joined


def test_test_commands_are_filled_with_this_hosts_values():
    osi = schema.build_osi(full_trace())
    assert osi["l3"]["test_command"] == "ping 93.184.216.34"
    assert osi["l4"]["test_command"] == "nc -vz example.com 443"
    assert "openssl s_client" in osi["l6"]["test_command"]
    assert "curl -sSI https://example.com/dashboard" == osi["l7"]["test_command"]


def test_unobserved_sections_propagate_their_reason():
    trace = full_trace()
    trace["local"] = {"observed": False, "why_not": "neither route nor ip is on PATH"}
    osi = schema.build_osi(trace)
    assert osi["l1"]["observed"] is False
    assert osi["l1"]["why_not"] == "neither route nor ip is on PATH"
    assert osi["l1"]["facts"] == []


def test_empty_trace_yields_seven_unobserved_layers():
    trace = schema.new_trace(
        target={"input": "x", "host": "x", "scheme": "https", "port": 443, "path": "/"},
        tool_version="2.1.0", generated_at="t", capabilities={}, redacted=False)
    osi = schema.build_osi(trace)
    assert all(layer["observed"] is False for layer in osi.values())


def test_layer_seven_flags_a_truncated_redirect_chain():
    trace = full_trace()
    trace["http"]["hops"] = [{"status": 301}, {"status": 302}]
    trace["http"]["redirect_limit_reached"] = True
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l7"]["facts"])
    assert "2 redirect(s) followed" in joined
    assert "truncated" in joined


def test_layer_seven_names_failed_dns_record_types():
    trace = full_trace()
    trace["dns"]["records_failed"] = ["CAA", "MX"]
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l7"]["facts"])
    assert "query failed for: CAA, MX" in joined


def test_layer_seven_dns_fact_never_prints_none_when_tcp_never_resolved_a_target():
    # DNS and TCP are collected independently: DNS can succeed while every TCP
    # candidate fails to connect, leaving no chosen target IP on the trace.
    trace = full_trace()
    trace["tcp"] = {"observed": False, "why_not": "no candidate accepted a connection"}
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l7"]["facts"])
    assert "None" not in joined
    assert "DNS: example.com resolved" in joined


def test_layer_seven_status_line_never_prints_none_when_protocol_and_status_are_absent():
    # A malformed HTTP status line yields protocol=None, status=None from
    # parse_response even though the section is otherwise observed.
    trace = full_trace()
    trace["http"]["final"]["protocol"] = None
    trace["http"]["final"]["status"] = None
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l7"]["facts"])
    assert "None" not in joined


def test_nat_true_with_absent_ips_never_fabricates_a_none_fact():
    # Currently unreachable in practice (wj/collect/local.py only sets nat=True
    # when both IPs are truthy), but build_osi must not fabricate a fact from
    # absent values if nat and the IPs ever disagree.
    trace = full_trace()
    trace["local"].update(nat=True, local_ip=None, public_ip=None)
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l3"]["facts"])
    assert "None" not in joined
    assert "NAT" not in joined


def test_gateway_mac_with_absent_gateway_ip_never_fabricates_a_none_fact():
    # Same family as the NAT fact above: currently unreachable in practice
    # (wj/collect/local.py only sets gateway_mac when gateway_ip is truthy),
    # but build_osi must not fabricate a fact from an absent gateway_ip.
    trace = full_trace()
    trace["local"].update(gateway_mac="11:22:33:44:55:66", gateway_ip=None)
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l2"]["facts"])
    assert "None" not in joined
    assert "gateway MAC" not in joined


def test_layer_five_does_not_claim_redirects_shared_one_connection():
    # C6: every redirect hop opens a fresh connection (wj/collect/http.py sets
    # sock = None before the next hop's fetch, and every request sends
    # Connection: close) -- the old wording, "N+1 request(s) over this
    # connection", asserted the opposite of what the collector actually does.
    trace = full_trace()
    trace["http"]["hops"] = [{"status": 301}, {"status": 302}]
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l5"]["facts"])
    assert "over this connection" in joined
    assert "3 request" not in joined
    assert "1 request over this connection" in joined
    assert "2 redirect(s), each on a new connection" in joined


def test_layer_five_with_no_redirects_does_not_mention_redirects():
    trace = full_trace()
    trace["http"]["hops"] = []
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l5"]["facts"])
    assert "1 request over this connection" in joined
    assert "redirect" not in joined


def test_layer_six_guards_a_partial_compression_combo_ratio_missing():
    # I1: the general standing guard below sets encoding=None AND ratio=None
    # together, which never opens the `if final.get("encoding")` branch --
    # the partial combination (encoding present, ratio absent, e.g. a failed
    # inflate) is the shape that actually reaches the buggy code.
    trace = full_trace()
    trace["http"]["final"].update(encoding="gzip", ratio=None,
                                   wire_bytes=14000, decoded_bytes=None)
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l6"]["facts"])
    assert "None" not in joined
    assert "gzip" in joined


def test_layer_six_guards_a_partial_compression_combo_decoded_bytes_missing():
    trace = full_trace()
    trace["http"]["final"].update(encoding="gzip", ratio=4.36,
                                   wire_bytes=14000, decoded_bytes=None)
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l6"]["facts"])
    assert "None" not in joined
    assert "14000" in joined


def test_all_optional_sub_fields_none_never_prints_the_literal_none():
    trace = full_trace()
    trace["local"].update(link=None, mtu=None, local_ip=None, local_mac=None,
                           gateway_mac=None, public_ip=None, nat=None)
    trace["dns"].update(dnssec=None, delegation=None, alpn_advertised=None,
                         ech=None, timing_ms=None)
    trace["tcp"].update(winner_family=None, local=None,
                         kernel={"rtt_ms": None, "mss": None,
                                 "retransmits": None, "source": None})
    trace["tls"].update(version=None, cipher=None, alpn=None,
                         handshake_ms=None, chain=[], trust_root=None,
                         resumption=None)
    trace["http"]["final"].update(protocol=None, status=None, reason=None,
                                   encoding=None, ratio=None, content_type=None)
    trace["path"].update(hops=[], asn_path=None, path_mtu=None)

    osi = schema.build_osi(trace)
    for layer, val in osi.items():
        for fact in val["facts"]:
            assert "None" not in fact, f"{layer}: leaked None in fact: {fact!r}"


def test_l5_reports_real_reuse_under_h2():
    trace = full_trace()
    trace["negotiation"] = {"observed": True, "advertised": ["h2"],
                            "offered": ["h2", "http/1.1"], "unavailable": [],
                            "chosen": "h2", "attempted": []}
    trace["http"]["hops"] = [{"url": "https://example.com/", "status": 301,
                              "location": "https://www.example.com/",
                              "protocol": "HTTP/2", "ttfb_ms": 1.0,
                              "connection_reused": True, "stream_id": 3}]
    osi = schema.build_osi(trace)
    joined = " ".join(osi["l5"]["facts"])
    assert "reused" in joined
    assert "each on a new connection" not in joined


def test_l5_still_says_new_connection_per_hop_under_http1():
    trace = full_trace()
    trace["negotiation"] = {"observed": True, "advertised": [], "offered": ["http/1.1"],
                            "unavailable": [], "chosen": "http/1.1", "attempted": []}
    trace["http"]["hops"] = [{"url": "http://example.com/", "status": 301,
                              "location": "https://example.com/",
                              "protocol": "HTTP/1.1", "ttfb_ms": 1.0,
                              "connection_reused": False, "stream_id": None}]
    osi = schema.build_osi(trace)
    assert "each on a new connection" in " ".join(osi["l5"]["facts"])


def test_l7_names_the_negotiated_protocol():
    trace = full_trace()
    trace["negotiation"] = {"observed": True, "advertised": ["h2"],
                            "offered": ["h2", "http/1.1"], "unavailable": [],
                            "chosen": "h2", "attempted": []}
    osi = schema.build_osi(trace)
    assert "h2" in " ".join(osi["l7"]["facts"])
