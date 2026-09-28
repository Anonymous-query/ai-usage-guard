"""Compliance orchestrator tests with mocked enforcement layers. No root required."""
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src", "intern_ai_guard"))

import compliance  # noqa: E402
import guardlog    # noqa: E402
import policy      # noqa: E402


def make_cfg(tmp_path):
    (tmp_path / "policy.yaml").write_text("version: 1\n")
    files = {
        "denied-domains.txt": "chatgpt.com\n",
        "allowed-domains.txt": "",
        "denied-applications.txt": "ollama\n",
        "denied-processes.txt": "ollama\n",
        "denied-vscode-extensions.txt": "github.copilot\n",
        "denied-browser-extensions.txt": "ofpnmcalabcbjgholdjcjblkibolbppb\n",
    }
    for n, c in files.items():
        (tmp_path / n).write_text(c)
    return policy.load(str(tmp_path))


def test_apply_writes_state_and_runs_layers(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    lg = guardlog.get_logger()
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n")

    monkeypatch.setattr(compliance.network, "hosts_apply",
                        lambda domains, path="/etc/hosts": True)
    monkeypatch.setattr(compliance.network, "nft_available", lambda: False)
    monkeypatch.setattr(compliance.network, "nft_counters", lambda: {})
    monkeypatch.setattr(compliance.browsers, "apply", lambda *a, **k: True)
    monkeypatch.setattr(compliance.applications, "scan_filesystem", lambda p: [])
    monkeypatch.setattr(compliance.applications, "scan_packages", lambda p: [])
    monkeypatch.setattr(compliance.applications, "scan_runtime_markers", lambda: [])
    monkeypatch.setattr(compliance.applications, "scan_processes", lambda p: [])
    monkeypatch.setattr(compliance.vscode, "scan", lambda ids: [])
    monkeypatch.setattr(compliance, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(compliance, "STATE_FILE", str(tmp_path / "state" / "state.json"))

    state = compliance.apply(cfg, lg)
    assert state["layers"]["hosts"] == "OK"
    assert state["layers"]["nftables"] == "UNSUPPORTED"
    assert state["layers"]["browsers"] == "OK"
    assert state["policy_version"] == 1
    assert os.path.exists(compliance.STATE_FILE)


def test_terminate_only_when_configured(tmp_path, monkeypatch):
    (tmp_path / "policy.yaml").write_text("version: 1\napplications:\n  enforce: terminate\n")
    for n, c in {"denied-domains.txt": "chatgpt.com\n", "allowed-domains.txt": "",
                 "denied-applications.txt": "ollama\n", "denied-processes.txt": "ollama\n",
                 "denied-vscode-extensions.txt": "github.copilot\n",
                 "denied-browser-extensions.txt": "ofpnmcalabcbjgholdjcjblkibolbppb\n"}.items():
        (tmp_path / n).write_text(c)
    cfg = policy.load(str(tmp_path))
    lg = guardlog.get_logger()
    killed = []
    monkeypatch.setattr(compliance.network, "hosts_apply", lambda *a, **k: False)
    monkeypatch.setattr(compliance.network, "nft_available", lambda: False)
    monkeypatch.setattr(compliance.network, "nft_counters", lambda: {})
    monkeypatch.setattr(compliance.browsers, "apply", lambda *a, **k: False)
    monkeypatch.setattr(compliance.applications, "scan_filesystem", lambda p: [])
    monkeypatch.setattr(compliance.applications, "scan_packages", lambda p: [])
    monkeypatch.setattr(compliance.applications, "scan_runtime_markers", lambda: [])
    monkeypatch.setattr(compliance.applications, "scan_processes",
                        lambda p: [{"name": "ollama", "pid": 999999, "kind": "process"}])
    monkeypatch.setattr(compliance.applications, "terminate",
                        lambda hits: killed.extend(hits) or hits)
    monkeypatch.setattr(compliance.vscode, "scan", lambda ids: [])
    monkeypatch.setattr(compliance, "STATE_DIR", str(tmp_path / "s"))
    monkeypatch.setattr(compliance, "STATE_FILE", str(tmp_path / "s" / "state.json"))
    compliance.apply(cfg, lg)
    assert killed and killed[0]["name"] == "ollama"


def test_check_detects_drift(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    lg = guardlog.get_logger()
    monkeypatch.setattr(compliance.network, "hosts_check",
                        lambda domains, path="/etc/hosts": ("DRIFT", "wiped"))
    monkeypatch.setattr(compliance.network, "nft_available", lambda: False)
    monkeypatch.setattr(compliance.browsers, "check", lambda d: ("OK", ""))
    layers = compliance.check(cfg, lg)
    assert layers["hosts"][0] == "DRIFT"
