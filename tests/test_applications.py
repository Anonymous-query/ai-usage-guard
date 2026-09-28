"""Unit tests for detection matchers and browser/vscode logic. No root required."""
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src", "intern_ai_guard"))

import applications  # noqa: E402
import browsers      # noqa: E402
import vscode        # noqa: E402


def test_match_glob_case_insensitive():
    assert applications._match("Ollama", ["ollama"])
    assert applications._match("cursor-0.42.AppImage", ["cursor*.appimage"])
    assert not applications._match("git", ["ollama", "aider"])


def test_scan_filesystem_finds_binary(tmp_path, monkeypatch):
    fake = tmp_path / "Downloads"
    fake.mkdir()
    (fake / "cursor-1.2.AppImage").write_text("x")
    (fake / "totally-normal-tool").write_text("x")

    class U:
        pw_dir = str(tmp_path)
        pw_name = "intern"
    monkeypatch.setattr(applications, "human_users", lambda: [U])
    monkeypatch.setattr(applications, "SYSTEM_BIN_DIRS", [])
    hits = applications.scan_filesystem(["cursor*.appimage"])
    names = [h["name"] for h in hits]
    assert "cursor-1.2.AppImage" in names
    assert "totally-normal-tool" not in names


def test_scan_processes_skips_self():
    # self must never appear (would create a kill-self hazard)
    hits = applications.scan_processes(["python*", "pytest*"])
    assert all(h["pid"] != os.getpid() for h in hits)


def test_chromium_policy_is_blocklist_only():
    pol = browsers.chromium_policy(["chatgpt.com"], ["abc"])
    assert pol["URLBlocklist"] == ["chatgpt.com"]
    assert pol["DnsOverHttpsMode"] == "off"
    assert "URLAllowlist" not in pol  # never allowlist -> never blocks normal sites


def test_firefox_policy_does_not_block_all_extensions():
    pol = browsers.firefox_policy(["chatgpt.com"], ["ext@ai"])
    ext = pol["policies"]["ExtensionSettings"]
    assert ext["*"]["installation_mode"] == "allowed"   # normal extensions still work
    assert ext["ext@ai"]["installation_mode"] == "blocked"
    assert "*://*.chatgpt.com/*" in pol["policies"]["WebsiteFilter"]["Block"]


def test_browser_apply_and_check(tmp_path, monkeypatch):
    cdir = tmp_path / "chrome"
    fdir = tmp_path / "firefox"
    monkeypatch.setattr(browsers, "CHROMIUM_POLICY_DIRS", [str(cdir)])
    monkeypatch.setattr(browsers, "FIREFOX_POLICY_DIR", str(fdir))
    assert browsers.apply(["chatgpt.com"], ["abc"], ["ext@ai"]) is True
    assert browsers.apply(["chatgpt.com"], ["abc"], ["ext@ai"]) is False  # idempotent
    assert browsers.check(["chatgpt.com"])[0] == "OK"
    written = json.load(open(cdir / browsers.POLICY_FILENAME))
    assert written["URLBlocklist"] == ["chatgpt.com"]


def test_vscode_scan_matches_versioned_dir(tmp_path, monkeypatch):
    extdir = tmp_path / ".vscode" / "extensions"
    extdir.mkdir(parents=True)
    (extdir / "github.copilot-1.150.0").mkdir()
    (extdir / "ms-python.python-2024.1").mkdir()

    class U:
        pw_dir = str(tmp_path)
        pw_name = "intern"
    monkeypatch.setattr(applications, "human_users", lambda: [U])
    hits = vscode.scan(["github.copilot"])
    assert len(hits) == 1 and hits[0]["id"] == "github.copilot"
    # unrelated extension untouched
    assert all("ms-python" not in h["path"] for h in hits)
