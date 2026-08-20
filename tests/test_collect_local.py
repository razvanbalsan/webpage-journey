from pathlib import Path

from wj import capabilities
from wj.collect import local as local_collect
from wj.context import Context

FIXTURES = Path(__file__).parent / "fixtures"


def read(name):
    return (FIXTURES / name).read_text()


def test_parse_route_get_darwin():
    assert local_collect.parse_route_get_darwin(read("route_get_darwin.txt")) == {
        "interface": "en0", "gateway": "192.168.1.1"}


def test_parse_ip_route_get():
    assert local_collect.parse_ip_route_get(read("ip_route_get.txt")) == {
        "interface": "wlan0", "gateway": "192.168.1.1", "src": "192.168.1.23"}


def test_parse_ifconfig_reads_mac_ip_mtu_and_status():
    out = local_collect.parse_ifconfig(read("ifconfig_en0.txt"))
    assert out == {"mac": "aa:bb:cc:dd:ee:ff", "ipv4": "192.168.1.23",
                   "mtu": 1500, "status": "active"}


def test_parse_ip_addr_reads_mac_ip_and_mtu():
    out = local_collect.parse_ip_addr(read("ip_addr_show.txt"))
    assert out["mac"] == "aa:bb:cc:dd:ee:ff"
    assert out["ipv4"] == "192.168.1.23"
    assert out["mtu"] == 1500


def test_parse_arp_extracts_the_gateway_mac():
    assert local_collect.parse_arp(read("arp_gateway.txt")) == "11:22:33:44:55:66"


def test_parse_arp_returns_none_when_incomplete():
    assert local_collect.parse_arp("? (192.168.1.1) at (incomplete) on en0") is None


def test_parse_ip_neigh_extracts_the_gateway_mac():
    assert local_collect.parse_ip_neigh(read("ip_neigh.txt")) == "11:22:33:44:55:66"


def test_parse_ipconfig_getpacket_reads_lease_and_dns():
    out = local_collect.parse_ipconfig_getpacket(read("ipconfig_getpacket.txt"))
    assert out["server"] == "192.168.1.1"
    assert out["lease_seconds"] == 86400
    assert out["dns"] == ["192.168.1.1", "1.1.1.1"]


def test_is_private_covers_rfc1918_and_loopback():
    assert local_collect.is_private("192.168.1.23") is True
    assert local_collect.is_private("10.0.2.14") is True
    assert local_collect.is_private("172.16.4.1") is True
    assert local_collect.is_private("127.0.0.1") is True
    assert local_collect.is_private("93.184.216.34") is False


def test_collect_assembles_a_section_from_injected_commands():
    caps = capabilities.Capabilities(
        libs={}, tools={"route": "/sbin/route", "ifconfig": "/sbin/ifconfig",
                        "arp": "/usr/sbin/arp", "ipconfig": "/usr/sbin/ipconfig"},
        privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    ctx.results["tcp"] = {"observed": True, "chosen": {"ip": "93.184.216.34"}}

    outputs = {
        "route": read("route_get_darwin.txt"),
        "ifconfig": read("ifconfig_en0.txt"),
        "arp": read("arp_gateway.txt"),
        "ipconfig": read("ipconfig_getpacket.txt"),
    }

    section = local_collect.collect(
        ctx, run=lambda cmd, timeout: outputs[cmd[0]],
        public_ip=lambda: "81.180.20.7")

    assert section["observed"] is True
    assert section["interface"] == "en0"
    assert section["local_mac"] == "aa:bb:cc:dd:ee:ff"
    assert section["gateway_mac"] == "11:22:33:44:55:66"
    assert section["mtu"] == 1500
    assert section["nat"] is True
    assert section["public_ip"] == "81.180.20.7"
    assert section["dhcp"]["lease_seconds"] == 86400


def test_collect_without_any_tooling_is_unobserved():
    caps = capabilities.Capabilities(libs={}, tools={}, privileged=False, can_sudo=False)
    ctx = Context(host="example.com", scheme="https", port=443, path="/",
                  timeout=5.0, deadline=1e9, caps=caps, results={})
    section = local_collect.collect(ctx, run=lambda cmd, timeout: "",
                                    public_ip=lambda: None)
    assert section["observed"] is False
    assert "route" in section["why_not"]
