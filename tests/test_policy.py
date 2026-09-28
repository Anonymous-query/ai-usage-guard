"""Unit tests for the policy engine and list parsing. No root required."""
import os
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src", "intern_ai_guard"))

import policy  # noqa: E402


def write_etc(tmp_path, policy_yaml, lists=None):
    (tmp_path / "policy.yaml").write_text(policy_yaml)
    defaults = {
        "denied-domains.txt": "# [AI chat]\nchatgpt.com\nclaude.ai\n",
        "allowed-domains.txt": "# exceptions\n",
        "denied-applications.txt": "ollama\naider\n",
        "denied-processes.txt": "ollama\n",
        "denied-vscode-extensions.txt": "github.copilot\n",
        "denied-browser-extensions.txt": "ofpnmcalabcbjgholdjcjblkibolbppb  # Monica\n",
    }
    if lists:
        defaults.update(lists)
    for name, content in defaults.items():
        (tmp_path / name).write_text(content)
    return str(tmp_path)


def test_load_minimal(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n")
    cfg = policy.load(etc)
    assert cfg["version"] == 1
    assert "chatgpt.com" in policy.effective_domains(cfg)
    assert cfg["network"]["block_public_dns"] is True  # default merged


def test_parse_list_categories(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n",
                    {"denied-domains.txt": "# [AI chat]\nchatgpt.com\n# [AI APIs]\napi.openai.com\n"})
    cfg = policy.load(etc)
    cats = {e["value"]: e["category"] for e in cfg["_lists"]["domains_deny"]}
    assert cats["chatgpt.com"] == "AI chat"
    assert cats["api.openai.com"] == "AI APIs"


def test_inline_comment_stripped(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n",
                    {"denied-domains.txt": "chatgpt.com   # the chat one\n"})
    cfg = policy.load(etc)
    assert "chatgpt.com" in policy.effective_domains(cfg)


def test_allow_carves_out_deny(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n",
                    {"denied-domains.txt": "chatgpt.com\nhuggingface.co\n",
                     "allowed-domains.txt": "huggingface.co\n"})
    cfg = policy.load(etc)
    eff = policy.effective_domains(cfg)
    assert "chatgpt.com" in eff and "huggingface.co" not in eff


def test_bad_version_rejected(tmp_path):
    etc = write_etc(tmp_path, "version: zero\n")
    with pytest.raises(policy.PolicyError):
        policy.load(etc)


def test_bad_enum_rejected(tmp_path):
    etc = write_etc(tmp_path, "version: 1\napplications:\n  enforce: nuke\n")
    with pytest.raises(policy.PolicyError):
        policy.load(etc)


def test_invalid_domain_rejected(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n",
                    {"denied-domains.txt": "not a domain!!\n"})
    with pytest.raises(policy.PolicyError):
        policy.load(etc)


def test_invalid_chrome_ext_rejected(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n",
                    {"denied-browser-extensions.txt": "SHORTID\n"})
    with pytest.raises(policy.PolicyError):
        policy.load(etc)


def test_missing_list_file_rejected(tmp_path):
    (tmp_path / "policy.yaml").write_text("version: 1\n")
    with pytest.raises(policy.PolicyError):
        policy.load(str(tmp_path))


def test_hash_changes_with_content(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n")
    h1 = policy.load(etc)["_hash"]
    (tmp_path / "denied-domains.txt").write_text("chatgpt.com\nnewsite.ai\n")
    h2 = policy.load(etc)["_hash"]
    assert h1 != h2


def test_malformed_yaml_rejected(tmp_path):
    etc = write_etc(tmp_path, "version: 1\n  bad: : :\n")
    with pytest.raises(policy.PolicyError):
        policy.load(etc)
