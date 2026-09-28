"""Unit tests for the network layer rendering. No root required."""
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src", "intern_ai_guard"))

import network  # noqa: E402
import policy   # noqa: E402


def base_cfg(**net):
    n = dict(policy.DEFAULTS["network"])
    n.update(net)
    return {"network": n}


def test_hosts_block_has_markers_and_ipv6():
    block = network.render_hosts_block(["chatgpt.com"])
    assert network.HOSTS_BEGIN in block and network.HOSTS_END in block
    assert "0.0.0.0 chatgpt.com" in block
    assert ":: chatgpt.com" in block  # IPv6 null-routed too


def test_hosts_block_adds_www_for_two_label():
    block = network.render_hosts_block(["chatgpt.com"])
    assert "0.0.0.0 www.chatgpt.com" in block
    # subdomain host should NOT get a www prefix
    block2 = network.render_hosts_block(["api.openai.com"])
    assert "www.api.openai.com" not in block2


def test_hosts_apply_and_strip_roundtrip(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    assert network.hosts_apply(["chatgpt.com"], str(hosts)) is True
    assert "chatgpt.com" in hosts.read_text()
    assert network.hosts_apply(["chatgpt.com"], str(hosts)) is False  # idempotent
    assert network.hosts_remove(str(hosts)) is True
    text = hosts.read_text()
    assert "chatgpt.com" not in text and "127.0.0.1 localhost" in text


def test_hosts_check_detects_drift(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    network.hosts_apply(["chatgpt.com"], str(hosts))
    assert network.hosts_check(["chatgpt.com"], str(hosts))[0] == "OK"
    hosts.write_text("127.0.0.1 localhost\n")  # user wiped it
    assert network.hosts_check(["chatgpt.com"], str(hosts))[0] == "DRIFT"


def test_nft_render_contains_expected_rules():
    cfg = base_cfg()
    rs = network.render_nft(cfg, upstreams=["192.168.1.1"])
    assert "table inet intern_ai_guard" in rs
    assert "delete table inet intern_ai_guard" in rs  # atomic replace
    assert "iag:public_dns" in rs
    assert "iag:dot" in rs
    assert "iag:doh" in rs
    assert "192.168.1.1" in rs  # upstream whitelisted


def test_nft_render_whitelists_private_ranges():
    rs = network.render_nft(base_cfg(), upstreams=[])
    assert "192.168.0.0/16" in rs and "10.0.0.0/8" in rs


def test_nft_render_quic_toggle():
    assert "iag:quic" not in network.render_nft(base_cfg(block_quic=False))
    assert "iag:quic" in network.render_nft(base_cfg(block_quic=True))


def test_nft_render_ipv6_toggle():
    with_v6 = network.render_nft(base_cfg(ipv6=True), upstreams=["2001:4860:4860::8888"])
    assert "ip6" in with_v6
    no_v6 = network.render_nft(base_cfg(ipv6=False))
    assert "doh_v6" not in no_v6


def test_nft_render_denied_ip_set_when_enabled():
    cfg = base_cfg(resolve_and_block_ips=True)
    rs = network.render_nft(cfg, upstreams=[], denied_ips=(["203.0.113.5"], []))
    assert "ai_v4" in rs and "203.0.113.5" in rs and "iag:denied_ip" in rs


def test_discover_dns_upstreams_returns_list():
    # smoke: must not raise, returns a list of strings
    ups = network.discover_dns_upstreams()
    assert isinstance(ups, list)
    assert all(isinstance(x, str) for x in ups)
